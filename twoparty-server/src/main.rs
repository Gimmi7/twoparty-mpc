#![feature(once_cell_try)]

use clap::Parser;
use tracing::{debug, error, info, warn};
use crate::config::{AppConfig, CliArgs, log_config};

pub mod config;

#[tokio::main]
async fn main() {
    let cli_args = CliArgs::parse();
    std::env::set_var("ENV", cli_args.env);

    let app_config = AppConfig::get_app_config();
    let _guard = log_config();

    debug!("debug debug");
    info!("hello {:?}", app_config);
    warn!("warn warn");
    error!("error error");
}
