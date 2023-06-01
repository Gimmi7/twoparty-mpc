use std::net::SocketAddr;
use std::time::Duration;
use axum::extract::{ConnectInfo, WebSocketUpgrade};
use axum::extract::ws::{Message, WebSocket};
use axum::response::IntoResponse;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, WebSocketStream, tungstenite};
use tracing::{error, info};
use crate::config::AppConfig;
use futures_util::{SinkExt, StreamExt};
use tokio::time;
use tokio_tungstenite::tungstenite::{Error};

// https://github.com/tokio-rs/axum/blob/main/examples/websockets/src/main.rs
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // upgrade stream protocol to websocket, register the socket handler
    ws.on_upgrade(move |socket| handle_socket(socket, addr))
}

async fn handle_socket( socket: WebSocket, peer: SocketAddr) {
    info!("New WebSocket connection, peer address:{}", peer);
    let (mut sender, mut receiver) = socket.split();
    loop {
        // tungstenite-rs implements auto pong, no need to process ping,
        // but ping msg will also be bubbling to here.
        // we can utilize ping bubbling to implements heartbeat
        match time::timeout(Duration::from_secs(10), receiver.next()).await {
            Err(_elapsed) => {
                // oops, client no heartbeat, close stream, todo
                info!("client no heartbeat, close stream");
                let _ = sender.close().await;
                return;
            }
            Ok(msg_option) => {
                if msg_option.is_none() {
                    // Error::AlreadyClosed todo
                    info!("msg_option none, connection alreadyClosed");
                    return;
                }

                let msg_result = msg_option.unwrap();
                if msg_result.is_err() {
                    let e = msg_result.err().unwrap();
                    error!("Error processing inbound message: {}", e);
                    return;
                }

                let msg = msg_result.unwrap();
                match msg {
                    Message::Binary(bytes) => {
                        info!("server get binary msg={:?}", bytes);
                    }
                    Message::Text(txt) => {
                        info!("server get test msg={}", txt);
                    }
                    Message::Close(option) => {
                        // todo
                        info!("client proactive close the connection:{:?}", option);
                        return;
                    }
                    _other => {}
                }
            }
        }
    }
}


pub async fn launch_server() {
    let app_config = AppConfig::get_app_config();
    let addr = format!("127.0.0.1:{}", app_config.server_port);
    let listener = TcpListener::bind(&addr).await.expect(format!("Can not bind {addr}").as_str());
    info!("websocket server listening on:{}",addr);

    while let Ok((stream, _)) = listener.accept().await {
        let peer = stream.peer_addr().expect("connected streams should hava a peer address");

        // https://github.com/tokio-rs/tokio/discussions/3858
        // tokio: worker-threads= cpu_num,  blocking-threads: create-on-demand with upper limit=500
        tokio::spawn(accept_connection(peer, stream));
    }
}

async fn accept_connection(peer: SocketAddr, stream: TcpStream) {
    let ws_accept_result = accept_async(stream).await;
    if ws_accept_result.is_err() {
        error!("accept a tcp stream as ws_stream fail:{}", ws_accept_result.err().unwrap());
        return;
    }

    let ws_stream = ws_accept_result.unwrap();
    info!("New WebSocket connection, peer address:{}", peer);

    if let Err(e) = handle_connection(peer, ws_stream).await {
        match e {
            tungstenite::Error::ConnectionClosed | tungstenite::Error::Protocol(_) | tungstenite::Error::Utf8 => {
                //todo
                info!("connection closed !!!");
            }
            err => error!("Error processing connection: {}", err)
        }
    }
}

async fn handle_connection(_peer: SocketAddr, ws_stream: WebSocketStream<TcpStream>) -> tungstenite::Result<()> {
    let (mut sink, mut read) = ws_stream.split();


    loop {
        // tungstenite-rs implements auto pong, no need to process ping,
        // but ping msg will also be bubbling to here.
        // we can utilize ping bubbling to implements heartbeat
        match time::timeout(Duration::from_secs(10), read.next()).await {
            Err(_elapsed) => {
                // oops, client no heartbeat, close stream, todo
                info!("client no heartbeat, close stream");
                let _ = sink.close().await;
                return Err(Error::ConnectionClosed);
            }
            Ok(msg_result) => {
                if msg_result.is_none() {
                    return Err(Error::AlreadyClosed);
                }
                let msg = msg_result.unwrap()?;

                if msg.is_text() || msg.is_binary() {
                    info!("server get msg={}", msg.to_string());
                }
            }
        }
    }
}