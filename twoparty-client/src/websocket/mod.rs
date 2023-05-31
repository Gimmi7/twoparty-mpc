use std::thread::sleep;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

async fn connect_server() -> tungstenite::Result<()> {
    let (ws_stream, _) = connect_async(
        Url::parse("ws://localhost:8822/mpc").expect("Can't connect to server")
    ).await?;

    let (mut sink, mut read) = ws_stream.split();

    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            let msg = msg.unwrap();
            println!("client get msg: {}", msg);
        }
    });

    for i in 1..=100 {
        sink.send(Message::Ping(vec![1])).await.expect("fail to send msg");
        println!("send msg {i}");
        sleep(Duration::from_secs(3));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::websocket::connect_server;

    #[tokio::test]
    async fn test_websocket_ping() {
        let _r = connect_server().await;
    }
}