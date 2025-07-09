// Use's

mod status;
mod utils;

use std::{
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use actix_web::{
    body::BoxBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    get,
    web::{Data},
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use tokio;
use tracing::{error, info};

// Local use's

use status::get_status;
use utils::{fetch_port, get_local_ip, init_tracing, load_config, check_hmac_auth, check_lan_only, check_require_https};



// Const's

const HMAC_TIMEOUT_SECS: u64 = 300;



// Struct's

pub struct HmacAuthStruct {
    secret: String,
}

pub struct HmacAuthMiddlewareStruct<S> {
    service: Rc<S>,
    secret: String,
}

pub struct LANOnlyStruct;

pub struct LANOnlyMiddlewareStruct<S> {
    service: Rc<S>,
}

pub struct RequireHttpsStruct {
    enforce_https: bool,
}

pub struct RequireHttpsMiddlewareStruct<S> {
    service: Rc<S>,
    enforce_https: bool,
}



// Impl's

impl HmacAuthStruct {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

impl RequireHttpsStruct {
    pub fn new(enforce_https: bool) -> Self {
        Self { enforce_https }
    }
}



// Middleware's

// Check HMAC auth
impl<S> Transform<S, ServiceRequest> for HmacAuthStruct
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = HmacAuthMiddlewareStruct<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(HmacAuthMiddlewareStruct {
            service: Rc::new(service),
            secret: self.secret.clone(),
        })
    }
}

impl<S> Service<ServiceRequest> for HmacAuthMiddlewareStruct<S>
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
        let secret = self.secret.clone();
        let svc = Rc::clone(&self.service);
        let method = req.method().to_string();
        let path = req.path().to_string();

        Box::pin(async move {
            check_hmac_auth(&req, &secret, &method, &path, HMAC_TIMEOUT_SECS)?;
            svc.call(req).await
        })
    }
}

// Check where are request from (LAN or not LAN)
impl<S> Transform<S, ServiceRequest> for LANOnlyStruct
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = LANOnlyMiddlewareStruct<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(LANOnlyMiddlewareStruct {
            service: Rc::new(service),
        })
    }
}

impl<S> Service<ServiceRequest> for LANOnlyMiddlewareStruct<S>
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

        Box::pin(async move {
            check_lan_only(&req)?;
            svc.call(req).await
        })
    }
}

// Check is request use HTTPS (if it turned on in config)
impl<S> Transform<S, ServiceRequest> for RequireHttpsStruct
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireHttpsMiddlewareStruct<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequireHttpsMiddlewareStruct {
            service: Rc::new(service),
            enforce_https: self.enforce_https,
        })
    }
}

impl<S> Service<ServiceRequest> for RequireHttpsMiddlewareStruct<S>
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
        let enforce_https = self.enforce_https;

        Box::pin(async move {
            check_require_https(&req, enforce_https)?;
            svc.call(req).await
        })
    }
}



// --- Handlers ---

#[get("/status")]
async fn status_handler(start: Data<Instant>, req: HttpRequest) -> impl Responder {
    let client_ip = req
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let status_json = get_status(*start.get_ref());
    let response = serde_json::json!({ "success": true, "data": status_json });

    info!(
        target: "handler::status",
        "Client {} requested /status -> {:?}",
        client_ip, response
    );

    HttpResponse::Ok().json(response)
}

#[get("/stop")]
async fn stop_handler(req: HttpRequest) -> impl Responder {
    let client_ip = req
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    info!(
        target: "handler::control",
        "Client {} requested /stop. Shutting down...",
        client_ip
    );

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::process::exit(0);
    });

    HttpResponse::Ok().json(serde_json::json!({ "success": true, "data": null }))
}



// --- Main ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let start = Instant::now();
    let start_data = Data::new(start);
    let config = load_config();

    init_tracing(&config.logs_dir, &config.name_for_port_manager);

    let port = match fetch_port(&config).await {
        Some(port) => port,
        None => {
            error!(
                target: "main",
                "Failed to retrieve port. {} will not start.",
                &config.name_for_port_manager
            );
            std::process::exit(1);
        }
    };

    let ip = get_local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "error".to_string());

    info!(
        target: "main",
        "Starting {} on {}:{} with {} workers",
        &config.name_for_port_manager,
        ip,
        port,
        config.workers_count
    );

    HttpServer::new(move || {
        App::new()
            .app_data(start_data.clone())
            .wrap(LANOnlyStruct)
            .wrap(HmacAuthStruct::new(config.hmac_secret.clone()))
            .wrap(RequireHttpsStruct::new(config.require_https))
            .service(status_handler)
            .service(stop_handler)
    })
    .workers(config.workers_count)
    .bind((ip.as_str(), port))?
    .run()
    .await
}