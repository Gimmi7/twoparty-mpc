#![feature(once_cell_try)]

use clap::Parser;

use crate::config::{AppConfig, CliArgs, log_config};
use crate::controller::launch_axum;


pub mod config;
pub mod websocket;
pub mod controller;

#[tokio::main]
async fn main() {
    let cli_args = CliArgs::parse();
    std::env::set_var("ENV", cli_args.env);

    let _app_config = AppConfig::get_app_config();
    let _guard = log_config();


    // launch_server().await;
    launch_axum().await;
}


