use std::collections::HashMap;

use std::sync::{Arc, LazyLock};
use axum::extract::ws::{Message, WebSocket};
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use tokio::sync::{mpsc, RwLock};
use tokio::sync::mpsc::{UnboundedSender};
use tracing::info;
use twoparty_secp256k1::generic::share::Party2Share as Secp256k1Share;
use twoparty_ed25519::generic::share::Ed25519Share;

#[allow(clippy::type_complexity)]
static PRODUCER_GROUP: LazyLock<Arc<RwLock<HashMap<String, UnboundedSender<Message>>>>> = LazyLock::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});

#[derive(Clone)]
pub struct SocketLocal {
    pub socket_id: String,
    pub identity_id: String,
    pub share_id: String,
    pub mpc_eph: HashMap<String, Vec<u8>>,
    pub secp256k1_share: Option<Secp256k1Share>,
    pub ed25519_share: Option<Ed25519Share>,
}

#[allow(clippy::type_complexity)]
static SOCKET_LOCALS: LazyLock<Arc<RwLock<HashMap<String, SocketLocal>>>> = LazyLock::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});


// cannot borrow data in dereference of `tokio::sync::RwLockReadGuard<'_, HashMap<std::string::String, SocketLocal>>` as mutable
pub async fn get_socket_local(socket_id: &str) -> Option<SocketLocal> {
    let hashmap = SOCKET_LOCALS.read().await;
    let option_ref = hashmap.get(socket_id);
    if option_ref.is_none() {
        None
    } else {
        Some(option_ref.unwrap().clone())
    }
}


pub async fn upsert_socket_local(socket_local: SocketLocal) {
    let socket_id = socket_local.socket_id.clone();
    SOCKET_LOCALS.write().await.insert(socket_id, socket_local);
}

pub async fn drop_producer(socket_id: &str) {
    // drop the producer will close the channel, then trigger consumer task return
    PRODUCER_GROUP.write().await.remove(socket_id);
    info!("drop producer:socket_id={}", socket_id);
    // drop socket_locals
    SOCKET_LOCALS.write().await.remove(socket_id);
}

pub async fn share_ws_sender_with_channel(mut ws_sender: SplitSink<WebSocket, Message>, socket_id: String) -> UnboundedSender<Message> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // cache the tx
    PRODUCER_GROUP.write().await.insert(socket_id, tx.clone());
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



