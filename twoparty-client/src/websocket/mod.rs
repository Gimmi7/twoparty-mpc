mod request_holder;
#[cfg(test)]
mod test;


use std::error;
use std::sync::Arc;

use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async};
use tokio_tungstenite::tungstenite::{Message};
use url::Url;
use common::get_tsp;
use common::socketmsg::{MSG_ACTION_REQ, MSG_ACTION_RSP, MSG_ACTION_NOTICE, MsgWrapper};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::{mpsc, mpsc::UnboundedSender};


use tokio::task::{AbortHandle};


use tokio::time;

use common::errors::GenericError;
use crate::websocket::request_holder::{drop_req_tx, register_request, resolve_request};

pub struct SyncClient {
    seq: Arc<AtomicU32>,
    pub identity_id: String,
    // send ws_message by tx
    tx: UnboundedSender<Message>,
    // when send req_msg, send "1" by heartbeat_tx to calc heartbeat timeout
    heartbeat_tx: UnboundedSender<u8>,
    abort_handles: Vec<AbortHandle>,
}

impl SyncClient {
    pub async fn connect_server(identity_id: String, url: String, heartbeat_sec: u8) -> Result<Self, Box<dyn error::Error>> {
        let parsed_url = Url::parse(&url)?;
        let (ws_stream, _) = connect_async(
            parsed_url
        ).await?;

        let (mut sender, mut receiver) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let (heartbeat_tx, mut heartbeat_rx) = mpsc::unbounded_channel::<u8>();

        // spawn a task to send heartbeat ping
        let c_tx = tx.clone();
        let heartbeat_task = tokio::spawn(async move {
            // both ping_msg & req_msg will be used to judge if a connection is idle at server,
            // so send "1" to heartbeat_rx when send a req_msg;
            // if heartbeat_rx get "2", the heartbeat task should stop
            loop {
                match time::timeout(Duration::from_secs(heartbeat_sec as u64), heartbeat_rx.recv()).await {
                    Err(_elapsed) => {
                        // send ping
                        println!("client send ping");
                        c_tx.send(Message::Ping(vec![1])).unwrap_or(());
                    }
                    Ok(msg_option) => {
                        if msg_option.is_none() {
                            // channel already closed
                            println!("heartbeat channel is closed");
                            return;
                        }
                        let msg = msg_option.unwrap();
                        if msg == 2 {
                            // stop the heartbeat
                            return;
                        }
                    }
                }
            }
        });

        // spawn a task to manage ws_sender
        let c_heartbeat_tx = heartbeat_tx.clone();
        let ws_sender_task = tokio::spawn(async move {
            loop {
                let option_msg = rx.recv().await;
                if option_msg.is_none() {
                    // channel closed, stop the consumer task, stop heartbeat
                    c_heartbeat_tx.send(2).unwrap_or(());
                    return;
                }
                let msg = option_msg.unwrap();
                sender.send(msg).await.unwrap_or(());
            }
        });

        // spawn a task to receive msg
        let ws_receiver_task = tokio::spawn(async move {
            loop {
                match receiver.next().await {
                    Some(msg_result) => {
                        if msg_result.is_err() {
                            println!("receive msg from server error:{}", msg_result.err().unwrap());
                            continue;
                        }
                        let msg = msg_result.unwrap();
                        if msg.is_binary() {
                            // resolve request promise or dispatch notice
                            let parse_result = serde_json::from_slice::<MsgWrapper>(&msg.into_data());
                            if let Ok(msg_wrapper) = parse_result {
                                let action = msg_wrapper.action;
                                match action {
                                    MSG_ACTION_RSP => {
                                        resolve_request(msg_wrapper).await;
                                    }
                                    MSG_ACTION_NOTICE => {}
                                    _ => {}
                                }
                            } else {
                                println!("parse server binary to MsgWrapper fail, err={}", parse_result.err().unwrap());
                            }
                        } else if msg.is_close() {
                            println!("client get close");
                        }
                    }
                    None => {
                        println!("connection already closed");
                        return;
                    }
                }
            }
        });

        let sync_client = SyncClient {
            seq: Arc::new(Default::default()),
            identity_id,
            tx,
            heartbeat_tx,
            abort_handles: vec![heartbeat_task.abort_handle(), ws_sender_task.abort_handle(), ws_receiver_task.abort_handle()],
            // abort_handles: vec![heartbeat_task, ws_sender_task, ws_receiver_task],
        };
        Ok(sync_client)
    }

    pub async fn send_req(&self, req_code: u32, req_body: Vec<u8>, option_timeout: Option<u64>) -> Result<MsgWrapper, Box<dyn error::Error>> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let req = MsgWrapper {
            seq,
            timestamp: get_tsp(),
            action: MSG_ACTION_REQ,
            action_code: req_code,
            body: req_body,
            error_msg: "".to_string(),
            notice_id: "".to_string(),
        };

        // serialize req_msg
        let req_bytes = serde_json::to_vec(&req);
        if req_bytes.is_err() {
            let err = GenericError(format!("serialize req_msg error:{}", req_bytes.err().unwrap()));
            return Err(Box::new(err));
        }

        // register request
        let req_rx = register_request(seq).await;
        // send msg to server
        self.tx.send(Message::from(req_bytes.unwrap()))?;

        // poll rsp_msg
        let mut timeout_ms = 20_000;
        if let Some(_timeout) = option_timeout {
            timeout_ms = option_timeout.unwrap();
        }
        match time::timeout(Duration::from_millis(timeout_ms), req_rx).await {
            Err(_elapsed) => {
                drop_req_tx(seq).await;
                Err(Box::new(GenericError("timeout".to_string())))
            }
            Ok(msg_result) => {
                if let Ok(msg) = msg_result {
                    // resolve_request will drop the req_tx
                    return Ok(msg);
                }
                drop_req_tx(seq).await;
                let err = GenericError(format!("req_rx recv error={}", msg_result.err().unwrap()));
                Err(Box::new(err))
            }
        }
    }
}

// https://doc.rust-lang.org/reference/destructors.html
impl Drop for SyncClient {
    fn drop(&mut self) {
        self.abort_handles.iter().for_each(|h| h.abort());
    }
}


