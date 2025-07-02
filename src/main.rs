use actix_web::{dev::{ServiceRequest, ServiceResponse, Transform, Service}, get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder, Error, body::BoxBody};
use serde::{Deserialize, Serialize};
use futures::future::{ok, Ready, LocalBoxFuture};
use std::task::{Context, Poll};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{info, error};

mod status;
mod utils;

use status::get_status;
use utils::{fetch_port, init_tracing, load_config, get_local_ip};


// --- local network protect ---


pub struct LocalNetworkOnly;


impl<S> Transform<S, ServiceRequest> for LocalNetworkOnly
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = LocalNetworkOnlyMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(LocalNetworkOnlyMiddleware {
            service: Rc::new(service),
        })
    }
}


pub struct LocalNetworkOnlyMiddleware<S> {
    service: Rc<S>,
}


impl<S> Service<ServiceRequest> for LocalNetworkOnlyMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = Rc::clone(&self.service);

        let ip_opt = req.connection_info().realip_remote_addr()
            .and_then(|addr| addr.split(':').next())
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok());

        let allowed = match ip_opt {
            Some(ip) => is_local_ip(&ip),
            None => false,
        };

        if allowed {
            Box::pin(async move { svc.call(req).await })
        } else {
            Box::pin(async move {
                Err(actix_web::error::PayloadError::Io(
                    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "not local ip")
                ).into())
            })
        }
    }
}


fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}


// --- local network protect ---



#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}



#[get("/status")]
async fn status_handler(start: web::Data<Instant>, req: HttpRequest) -> impl Responder {
    let client_addr = req
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let status_json = get_status(*start.get_ref());
    let status = serde_json::json!({ "success": true, "data": status_json });

    info!(target: "status_handler", "Client {} requested status: {}", client_addr, status);

    HttpResponse::Ok().json(status)
}


#[get("/stop")]
async fn stop_handler() -> impl Responder {
    info!(target: "control", "Received /stop request. Exiting...");

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::process::exit(0);
    });

    HttpResponse::Ok().json(serde_json::json!({ "success": true, "data": null }))
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let start = Instant::now();
    let start_data = web::Data::new(start);
    let config = load_config();

    init_tracing(&config.logs_dir, &config.name_for_port_manager);

    let Some(port) = fetch_port(&config).await else {
        error!(target: "main", "Failed to retrieve port. {} will not start.", &config.name_for_port_manager);
        std::process::exit(1);
    };

    let ip = get_local_ip().map(|addr| addr.to_string()).unwrap_or("error".to_string());

    info!(target: "main", "Starting {} on {}:{}", &config.name_for_port_manager, ip, port);

    HttpServer::new(move || {
        App::new()
            .app_data(start_data.clone())
            .service(status_handler)
            .service(stop_handler)
    })
    .workers(config.workers_count)
    .bind((ip.as_str(), port))?
    .run()
    .await
}
