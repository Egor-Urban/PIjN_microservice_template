/*
Base microservice template
Developer: Urban Egor
*/



use actix_web::{get, web, App, HttpServer, Responder, HttpResponse, HttpRequest};
use chrono::Local;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use tracing::{info, warn, error};
use tracing_subscriber;
use std::time::Instant;
use tokio::time::{sleep, Duration};

mod status;



#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}


#[derive(Deserialize)]
struct Config {
    ip: String,
    port_manager_ip: String,
    port_manager_port: String,
    port_manager_endpoint: String,
    name_for_port_manager: String,
    logs_dir: String,
}




fn load_config() -> Config {
    let config_path = "config.json";
    let config_data = std::fs::read_to_string(config_path)
        .expect("Can't read config.json");

    serde_json::from_str(&config_data)
        .expect("Can't parsing config.json")
}



async fn fetch_port(config: &Config) -> Option<u16> {
    let url = format!(
        "http://{}:{}/{}/{}",
        config.port_manager_ip,
        config.port_manager_port,
        config.port_manager_endpoint,
        config.name_for_port_manager
    );

    for attempt in 1..=3 {
        info!(target: "port_resolver", "Attempt {}: Requesting port from {}", attempt, url);

        match reqwest::get(&url).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<ApiResponse<serde_json::Value>>().await {
                        Ok(json) => {
                            if json.success {
                                if let Some(port_val) = json.data.as_u64() {
                                    let port = port_val as u16;
                                    info!(target: "port_resolver", "Got port: {}", port);
                                    return Some(port);
                                } else {
                                    error!(target: "port_resolver", "No port in response data");
                                }
                            } else {
                                warn!(target: "port_resolver", "Error from server: {:?}", json.data);
                            }
                        }
                        Err(e) => error!(target: "port_resolver", "JSON parse error: {}", e),
                    }
                } else {
                    warn!(target: "port_resolver", "Response status: {}", resp.status());
                }
            }
            Err(e) => {
                warn!(target: "port_resolver", "Attempt {} failed: {}", attempt, e);
                if attempt == 3 {
                    error!(target: "port_resolver", "All attempts failed to fetch port");
                    return None;
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    None
}



fn init_tracing(logs_dir: &str, log_name: &str) {
    let date = Local::now().format("%d_%m_%Y").to_string();
    let log_dir = if logs_dir.trim().is_empty() {
        "./logs"
    } else {
        logs_dir
    };

    std::fs::create_dir_all(log_dir).expect("Can't create logs directory");

    let log_path = format!("{}/{}_{}.log", log_dir, log_name, date);

    tracing_subscriber::fmt()
        .with_target(true)
        .with_writer(std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("Can't open log file"))
        .with_thread_names(true)
        .with_ansi(false)
        .init();
}




#[get("/status")]
async fn get_status(start: web::Data<Instant>, req: HttpRequest) -> impl Responder {
    let client_addr = req.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let status_json = status::get_status(*start.get_ref());
    let status = serde_json::json!({ "success": true, "data": status_json });


    info!(target: "status_handler", "Client {} requested status: {}", client_addr, status);



    HttpResponse::Ok().json(status)
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let start = Instant::now();
    let start_data = web::Data::new(start);
    let config = load_config();

    init_tracing(&config.logs_dir, &config.name_for_port_manager);

    let Some(port) = fetch_port(&config).await else {
        error!(target: "main", "Can't get port. {} won't start.", &config.name_for_port_manager);
        std::process::exit(1);
    };

    let ip = config.ip.clone();

    info!(target: "main", "Starting {} on {}:{}", &config.name_for_port_manager, ip, port);

    HttpServer::new(move || {
        App::new()
            .app_data(start_data.clone()) 
            .service(get_status)
    })

    .workers(4)
    .bind((ip.as_str(), port))?
    .run()
    .await
}



