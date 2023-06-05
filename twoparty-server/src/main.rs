#![feature(once_cell_try)]
#![feature(lazy_cell)]

use clap::Parser;

use crate::config::{AppConfig, CliArgs, log_config};
use crate::controller::launch_axum;


pub mod config;
pub mod websocket;
pub mod controller;
pub mod storage;

// https://github.com/tokio-rs/tokio/discussions/3858
// tokio: worker-threads= cpu_num,  blocking-threads: create-on-demand with upper limit=500
#[tokio::main]
async fn main() {
    let cli_args = CliArgs::parse();
    std::env::set_var("ENV", cli_args.env);

    let _app_config = AppConfig::get_app_config();
    let _guard = log_config();

    // launch http & websocket server
    launch_axum().await;
}


