mod ws_config;

use std::net::{SocketAddr};
use axum::{Router};
use axum::routing::{get};
use tracing::info;
use crate::config::AppConfig;
use crate::websocket::ws_handler;

pub async fn launch_axum() {
    let app_config = AppConfig::get_app_config();

    let router = build_router();
    let addr = format!("0.0.0.0:{}", app_config.server_port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("{}", health().await);
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.expect("Failed to run axum server");
}

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .route("/ws-config", get(ws_config::ws_config))
}

async fn health() -> String {
    let app_config = AppConfig::get_app_config();
    let crate_name = env!("CARGO_PKG_NAME");
    format!("{crate_name} runs at port: {}", app_config.server_port)
}