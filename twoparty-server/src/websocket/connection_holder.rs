use std::collections::HashMap;

use std::sync::{Arc, LazyLock};
use axum::extract::ws::{Message, WebSocket};
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use tokio::sync::{mpsc, RwLock};
use tokio::sync::mpsc::{UnboundedSender};
use tracing::info;

#[allow(clippy::type_complexity)]
pub static PRODUCER_GROUP: LazyLock<Arc<RwLock<HashMap<String, UnboundedSender<Message>>>>> = LazyLock::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});


pub async fn drop_producer(connection_id: &str) {
    // drop the producer will close the channel, then trigger consumer task return
    PRODUCER_GROUP.write().await.remove(connection_id);
    info!("removed producer:connection_id={}", connection_id);
}

pub async fn share_ws_sender_with_channel(mut ws_sender: SplitSink<WebSocket, Message>, connection_id: String) -> UnboundedSender<Message> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // cache the tx
    PRODUCER_GROUP.write().await.insert(connection_id, tx.clone());
    // spawn a task to manage the ws_sender
    tokio::spawn(async move {
        loop {
            let option_msg = rx.recv().await;
            if option_msg.is_none() {
                info!("channel closed, stop the consumer task, close the ws_sender");
                ws_sender.close().await.unwrap_or(());
                return;
            }
            let msg = option_msg.unwrap();
            ws_sender.send(msg).await.unwrap_or(());
        }
    });
    tx
}



