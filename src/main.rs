use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{error, info};

mod status;
mod utils;

use status::get_status;
use utils::{fetch_port, init_tracing, load_config};



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

    //let port = 1045;

    let ip = config.ip.clone();

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
//
