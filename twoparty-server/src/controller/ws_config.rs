use axum::Json;
use serde::Serialize;
use crate::config::AppConfig;

#[derive(Serialize)]
pub struct WsConfig {
    pub ws_server_idle: u8,
    pub ws_client_interval: u8,
}

pub async fn ws_config() -> Json<WsConfig> {
    let app_config = AppConfig::get_app_config();
    let ws_config = WsConfig { ws_server_idle: app_config.ws_server_idle, ws_client_interval: app_config.ws_client_interval };
    Json(ws_config)
}