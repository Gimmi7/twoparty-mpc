use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, WebSocketStream, tungstenite};
use tracing::{error, info};
use crate::config::AppConfig;
use futures_util::StreamExt;

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
            }
            err => error!("Error processing connection: {}", err)
        }
    }
}

async fn handle_connection(_peer: SocketAddr, mut ws_stream: WebSocketStream<TcpStream>) -> tungstenite::Result<()> {
    while let Some(msg) = ws_stream.next().await {
        let msg = msg?;
        info!("socket-msg:{}", msg.to_string());
        // if msg.is_text() || msg.is_binary() {
        //     let (sink, read) = ws_stream.split();
        //     ws_stream.close()
        // }
    }

    Ok(())
}