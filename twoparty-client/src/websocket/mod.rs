use std::thread::sleep;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite};
use tokio_tungstenite::tungstenite::{Error, Message};
use url::Url;

pub async fn connect_server() -> tungstenite::Result<()> {
    let (ws_stream, _) = connect_async(
        Url::parse("ws://localhost:8822/ws").expect("Can't connect to server")
    ).await?;

    let (mut sink, mut read) = ws_stream.split();

    tokio::spawn(async move {
        for i in 1..=3 {
            let outbound_msg = Message::Ping(vec![11]);
            // let outbound_msg=Message::text(format!("hello-{i}");
            sink.send(outbound_msg).await.expect("fail to send msg");
            println!("send msg {i}");
            sleep(Duration::from_secs(3));
        }
    });

    loop {
        match read.next().await {
            Some(msg_result) => {
                let msg = msg_result?;
                if msg.is_pong() {
                    println!("client get pong: {}", msg.to_text().unwrap())
                } else {
                    println!("client get msg: {}", msg.to_string());
                }
            }
            None => {
                println!("connection already closed");
                return Err(Error::AlreadyClosed);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::websocket::connect_server;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_websocket() {
        let result = connect_server().await;
        if result.is_err() {
            println!("{}", result.err().unwrap());
            panic!("")
        }
    }
}