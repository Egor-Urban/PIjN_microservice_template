// Use's

use chrono::Local;
use serde::Deserialize;
use std::fs;
use tracing::{error, info, warn};
use tracing_subscriber;
use reqwest;
use tokio::time::{sleep, Duration};
use serde_json::json;
use std::net::{UdpSocket, IpAddr};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use actix_web::{
    dev::{ServiceRequest}, Error
};



// Struct's

#[derive(Deserialize, Clone)]
pub struct Config {
    pub port_manager_ip: String,
    pub port_manager_port: String,
    pub port_manager_endpoint: String,
    pub name_for_port_manager: String,
    pub logs_dir: String,
    pub workers_count: usize,
    pub hmac_secret: String,
    pub require_https: bool
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}



// Util's

pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}


pub fn check_hmac_auth(req: &ServiceRequest, secret: &str, method: &str, path: &str, hmac_timeout_secs: u64) -> Result<(), Error> {
    let headers = req.headers();
    let signature = headers
        .get("X-HMAC-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let timestamp = headers
        .get("X-HMAC-Timestamp")
        .and_then(|h| h.to_str().ok())
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if timestamp == 0 || (current_time > timestamp && current_time - timestamp > hmac_timeout_secs) {
        error!(
            target: "middleware::hmac",
            "Rejected request to {} {} - invalid or expired timestamp ({} vs current {})",
            method, path, timestamp, current_time
        );
        return Err(actix_web::error::ErrorUnauthorized("Invalid or expired timestamp"));
    }

    let message = format!("{}:{}:{}", method, path, timestamp);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if signature != expected_signature {
        error!(
            target: "middleware::hmac",
            "Rejected request to {} {} - invalid HMAC (provided: {}, expected: {})",
            method, path, signature, expected_signature
        );
        return Err(actix_web::error::ErrorUnauthorized("Invalid HMAC signature"));
    }

    info!(
        target: "middleware::hmac",
        "Accepted HMAC authenticated request to {} {}",
        method, path
    );

    Ok(())
}


pub fn check_lan_only(req: &ServiceRequest) -> Result<(), Error> {
    let ip_opt = req
        .connection_info()
        .realip_remote_addr()
        .and_then(|addr| addr.split(':').next())
        .and_then(|ip| ip.parse::<IpAddr>().ok());

    if ip_opt.map_or(false, is_local_ip) {
        info!(
            target: "middleware::local_only",
            "Accepted request from local IP {:?} to {} {}",
            ip_opt,
            req.method(),
            req.path()
        );
        Ok(())
    } else {
        error!(
            target: "middleware::local_only",
            "Rejected request from non-local IP {:?} to {} {}",
            ip_opt,
            req.method(),
            req.path()
        );
        Err(actix_web::error::PayloadError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "not local ip"),
        )
        .into())
    }
}


pub fn check_require_https(req: &ServiceRequest, enforce_https: bool) -> Result<(), Error> {
    let scheme = req.connection_info().scheme().to_string();
    let method = req.method().to_string();
    let path = req.path().to_string();

    if enforce_https && scheme != "https" {
        error!(
            target: "middleware::require_https",
            "Rejected request to {} {} - HTTPS required, but {} used",
            method, path, scheme
        );
        return Err(actix_web::error::ErrorForbidden("HTTPS required"));
    }

    info!(
        target: "middleware::require_https",
        "Accepted request to {} {} with scheme {}",
        method, path, scheme
    );

    Ok(())
}


pub fn get_local_ip() -> Option<IpAddr> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            error!(target: "utils", "Failed to bind UDP socket for local IP detection: {}", e);
            return None;
        }
    };
    if let Err(e) = socket.connect("8.8.8.8:80") {
        error!(target: "utils", "Failed to connect UDP socket for local IP detection: {}", e);
        return None;
    }
    match socket.local_addr() {
        Ok(addr) => Some(addr.ip()),
        Err(e) => {
            error!(target: "utils", "Failed to get local address from UDP socket: {}", e);
            None
        }
    }
}


pub fn load_config() -> Config {
    let config_path = "config.json";
    match fs::read_to_string(config_path) {
        Ok(config_data) => {
            match serde_json::from_str(&config_data) {
                Ok(config) => config,
                Err(e) => {
                    error!(target: "config", "Failed to parse config.json: {}", e);
                    panic!("Failed to parse config.json");
                }
            }
        }
        Err(e) => {
            error!(target: "config", "Failed to read config.json: {}", e);
            panic!("Failed to read config.json");
        }
    }
}


pub fn init_tracing(logs_dir: &str, log_name: &str) {
    let date = Local::now().format("%d_%m_%Y").to_string();
    let log_dir = if logs_dir.trim().is_empty() {
        "./logs"
    } else {
        logs_dir
    };

    if let Err(e) = fs::create_dir_all(log_dir) {
        error!(target: "tracing", "Can't create logs directory '{}': {}", log_dir, e);
        panic!("Can't create logs directory");
    }

    let log_path = format!("{}/{}_{}.log", log_dir, log_name, date);

    tracing_subscriber::fmt()
        .with_target(true)
        .with_writer(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap_or_else(|e| {
                    error!(target: "tracing", "Can't open log file '{}': {}", log_path, e);
                    panic!("Can't open log file");
                }),
        )
        .with_thread_names(true)
        .with_ansi(false)
        .init();

    info!(target: "tracing", "Logging initialized, output file: {}", log_path);
}


pub async fn fetch_port(config: &Config) -> Option<u16> {
    let url = format!(
        "http://{}:{}/{}",
        config.port_manager_ip,
        config.port_manager_port,
        config.port_manager_endpoint
    );

    let local_ip = get_local_ip().unwrap_or_else(|| {
        error!(target: "port_resolver", "Failed to determine local IP, using 127.0.0.1 as fallback");
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
    });

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let message = format!("POST:{}:{}", config.port_manager_endpoint, timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(config.hmac_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let body = json!({
        "ip": local_ip.to_string(),
        "service_name": config.name_for_port_manager
    });

    for attempt in 1..=3 {
        info!(target: "port_resolver", "Attempt {}: Requesting port from {} with body {:?}", attempt, url, body);

        match reqwest::Client::new()
            .post(&url)
            .header("X-HMAC-Signature", signature.clone())
            .header("X-HMAC-Timestamp", timestamp.to_string())
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<ApiResponse<serde_json::Value>>().await {
                        Ok(json) => {
                            if json.success {
                                if let Some(port_val) = json.data.as_u64() {
                                    let port = port_val as u16;
                                    info!(target: "port_resolver", "Received port: {}", port);
                                    return Some(port);
                                } else {
                                    error!(target: "port_resolver", "No port found in response data");
                                }
                            } else {
                                warn!(target: "port_resolver", "Server returned error: {:?}", json.data);
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
                    error!(target: "port_resolver", "All attempts to fetch port failed");
                    return None;
                }
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    None
}
