mod handler;
mod inbound_dispatcher;
mod connection_holder;

use std::net::SocketAddr;

use std::time::Duration;

use axum::extract::{ConnectInfo, WebSocketUpgrade};
use axum::extract::ws::{Message, WebSocket};
use axum::response::IntoResponse;
use futures_util::{StreamExt};

use tokio::time;


use tracing::{error, info};
use common::socketmsg::MsgWrapper;
use common;
use crate::config::AppConfig;
use crate::websocket::connection_holder::{drop_producer, share_ws_sender_with_channel};

use crate::websocket::inbound_dispatcher::dispatch_inbound;


// https://github.com/tokio-rs/axum/blob/main/examples/websockets/src/main.rs
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // upgrade stream protocol to websocket, register the socket handler
    ws.on_upgrade(move |socket| handle_socket(socket, addr))
}

async fn handle_socket(socket: WebSocket, peer: SocketAddr) {
    info!("New WebSocket connection, peer address:{}", peer);
    let app_config = AppConfig::get_app_config();
    let socket_id = common::get_uuid();

    let (sender, mut receiver) = socket.split();
    let tx = share_ws_sender_with_channel(sender, socket_id.clone()).await;
    loop {
        // tungstenite-rs implements auto pong, no need to process ping,
        // but ping msg will also be bubbling to here.
        // we can utilize ping bubbling to implements heartbeat
        match time::timeout(Duration::from_secs(app_config.ws_server_idle as u64), receiver.next()).await {
            Err(_elapsed) => {
                // oops, client no heartbeat, close stream
                info!("client no heartbeat, close stream");
                drop_producer(&socket_id).await;
                return;
            }
            Ok(msg_option) => {
                if msg_option.is_none() {
                    info!("msg_option none, connection alreadyClosed");
                    drop_producer(&socket_id).await;
                    return;
                }

                let msg_result = msg_option.unwrap();
                if msg_result.is_err() {
                    // Connection reset without closing handshake
                    let e = msg_result.err().unwrap();
                    info!("Protocol error: {}", e);
                    drop_producer(&socket_id).await;
                    return;
                }

                let msg = msg_result.unwrap();
                match msg {
                    Message::Binary(bytes) => {
                        match serde_json::from_slice::<MsgWrapper>(&bytes) {
                            Ok(msg_wrapper) => {
                                dispatch_inbound(msg_wrapper, tx.clone(), socket_id.clone()).await;
                            }
                            Err(e) => {
                                error!("fail to parse bytes to MsgWrapper: err={}", e);
                            }
                        }
                    }
                    Message::Text(txt) => {
                        info!("server get test msg={}", txt);
                    }
                    Message::Close(option) => {
                        info!("client proactive close the connection:{:?}", option);
                        drop_producer(&socket_id).await;
                        return;
                    }
                    Message::Ping(_) => {
                        info!("server get ping");
                    }
                    _other => {}
                }
            }
        }
    }
}
