use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use tokio::sync::{oneshot, Mutex};

use common::socketmsg::MsgWrapper;


#[allow(clippy::type_complexity)]
static REQUEST_TXS: LazyLock<Arc<Mutex<HashMap<u32, oneshot::Sender<MsgWrapper>>>>> = LazyLock::new(|| {
    Arc::new(Mutex::new(HashMap::new()))
});

pub async fn register_request(seq: u32) -> oneshot::Receiver<MsgWrapper>{
    let (req_tx, req_rx) = oneshot::channel::<MsgWrapper>();

    // cache the req_tx
    REQUEST_TXS.lock().await.insert(seq, req_tx);
    req_rx
}


pub async fn resolve_request(rsp_msg: MsgWrapper) {
    let seq = rsp_msg.seq;
    let option_req_tx = REQUEST_TXS.lock().await.remove(&seq);
    if let Some(req_tx) = option_req_tx {
        req_tx.send(rsp_msg).unwrap_or(());
    } else {
        println!("******** cna not find req_tx with rsp_msg={:?}", rsp_msg);
    }
}

pub async fn drop_req_tx(seq: u32) {
    REQUEST_TXS.lock().await.remove(&seq);
    println!("remove req_tx: seq={}", seq);
}