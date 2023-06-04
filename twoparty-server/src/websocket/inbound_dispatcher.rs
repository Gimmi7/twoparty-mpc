use axum::extract::ws::{Message};

use tokio::sync::mpsc::UnboundedSender;
use tracing::{error};

use common::{get_tsp, socketmsg};
use common::socketmsg::{MsgWrapper, MSG_ACTION_RSP, RSP_CODE_SUCCESS, MSG_ACTION_REQ};

use crate::websocket::handler::mpc22_handler::mpc22_handler;


pub async fn dispatch_inbound(msg_wrapper: MsgWrapper, tx: UnboundedSender<Message>, socket_id: String) {
    let inbound_with_sender = InboundWithTx {
        msg_wrapper: msg_wrapper.clone(),
        tx,
        socket_id,
    };

    if msg_wrapper.action == MSG_ACTION_REQ {
        match msg_wrapper.action_code {
            socketmsg::REQ_CODE_MPC22 => {
                mpc22_handler(inbound_with_sender).await;
            }
            RSP_CODE_SUCCESS => {
                println!("nothing")
            }
            _ => {}
        }
    }
}

pub struct InboundWithTx {
    pub msg_wrapper: MsgWrapper,
    tx: UnboundedSender<Message>,
    pub socket_id: String,
}

impl InboundWithTx {
    pub async fn send_async(&self, msg: MsgWrapper) {
        let msg_bytes_r = serde_json::to_vec(&msg);
        if let Err(_e) = msg_bytes_r {
            error!("InboundWithTx: failed to serialize outbound msg={:?}", msg);
            return;
        }
        let axum_message = Message::from(msg_bytes_r.unwrap());
        self.tx.send(axum_message).unwrap_or(());
    }

    fn base_rsp(&self) -> MsgWrapper {
        let req_msg = &self.msg_wrapper;
        MsgWrapper {
            seq: req_msg.seq,
            timestamp: get_tsp(),
            action: MSG_ACTION_RSP,
            action_code: RSP_CODE_SUCCESS,
            body: vec![],
            error_msg: "".to_string(),
            notice_id: "".to_string(),
        }
    }

    pub async fn success_rsp(&self, option_body: Option<Vec<u8>>) {
        let mut rsp = self.base_rsp();
        if let Some(body) = option_body {
            rsp.body = body;
        }
        self.send_async(rsp).await;
    }

    pub async fn fail_rsp(&self, rsp_code: u32, error_msg: String) {
        let mut rsp = self.base_rsp();
        rsp.action_code = rsp_code;
        rsp.error_msg = error_msg;
        self.send_async(rsp).await;
    }
}

