use std::sync::OnceLock;
use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};
use tracing::{Level};

use tracing_appender::non_blocking::{WorkerGuard};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, Registry};
use tracing_subscriber::fmt::TestWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;


pub const RESOURCES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/resources");

#[derive(clap::Parser, Debug)]
#[command(author, version, about)]
pub struct CliArgs {
    #[clap(long, default_value = "test")]
    pub env: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AppConfig {
    pub server_port: u16,
    pub env: String,
    pub ws_server_idle: u8,
    pub ws_client_interval: u8,
}

// rust static vs const
// static can hold both mutable and immutable value,the value of static variable can be changed at runtime.
// const can only hold immutable values, and can not be changed at runtime, const values are evaluated at compile-time,and directly embedded into the compiled binary.
static CONFIG_LOCK: OnceLock<AppConfig> = OnceLock::new();

impl AppConfig {
    pub fn get_app_config() -> &'static Self {
        let app_config = CONFIG_LOCK.get_or_try_init(|| -> Result<AppConfig, _>{
            let env = std::env::var("ENV").unwrap_or("test".to_string());
            let config_file_path = format!("config-{env}.yml");
            if let Some(env_file) = RESOURCES_DIR.get_file(config_file_path) {
                if let Some(env_yaml) = env_file.contents_utf8() {
                    serde_yaml::from_str::<AppConfig>(env_yaml)
                } else {
                    panic!("env {env} config file is empty")
                }
            } else {
                panic!("env {env} not supported")
            }
        }).expect("fail to parse yml config");

        app_config
    }
}

pub fn log_config() -> Vec<WorkerGuard> {
    let env = std::env::var("ENV").unwrap_or("test".to_string());
    let crate_name = env!("CARGO_PKG_NAME");

    let info_file_appender = tracing_appender::rolling::hourly("/data/logs", format!("{crate_name}_{env}.log"));
    let (info_writer, info_guard) = tracing_appender::non_blocking(info_file_appender);

    let err_file_appender = tracing_appender::rolling::hourly("/data/logs", format!("{crate_name}_{env}_err.log"));
    let (err_writer, err_guard) = tracing_appender::non_blocking(err_file_appender);


    if env == "prod" {
        let registry = Registry::default()
            .with(fmt::Layer::default().with_writer(info_writer.with_max_level(Level::INFO)))
            .with(fmt::Layer::default().with_writer(err_writer.with_max_level(Level::WARN)));
        tracing::subscriber::set_global_default(registry).expect("fail to set tracing subscriber");
    } else {
        let registry = Registry::default()
            .with(fmt::Layer::default().with_writer(info_writer.with_max_level(Level::INFO)))
            .with(fmt::Layer::default().with_writer(err_writer.with_max_level(Level::WARN)))
            .with(fmt::Layer::default().with_writer(TestWriter::default().with_max_level(Level::INFO)));
        tracing::subscriber::set_global_default(registry).expect("fail to set tracing subscriber");
    }

    vec![info_guard, err_guard]
}