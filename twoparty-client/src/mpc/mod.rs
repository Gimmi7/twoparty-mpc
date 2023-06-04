use serde::Serialize;
use common::socketmsg::{MsgWrapper, REQ_CODE_MPC22, RSP_CODE_SUCCESS};
use common::socketmsg::types::Mpc22Msg;
use crate::websocket::SyncClient;

pub mod ecdsa;
#[cfg(test)]
mod test;

impl SyncClient {
    pub async fn send_mpc22_msg<T>(&self, msg_detail: &T, mut mpc22_msg: Mpc22Msg) -> Result<MsgWrapper, String>
        where T: ?Sized + Serialize
    {
        // serialize msg_detail
        let detail_bytes = serde_json::to_vec(msg_detail);
        if detail_bytes.is_err() {
            return Err(detail_bytes.err().unwrap().to_string());
        }
        mpc22_msg.msg_detail = detail_bytes.unwrap();

        // serialize mpc22_msg
        let mpc22_bytes = serde_json::to_vec(&mpc22_msg);
        if mpc22_bytes.is_err() {
            return Err(mpc22_bytes.err().unwrap().to_string());
        }

        // send_req
        let rsp = self.send_req(REQ_CODE_MPC22, mpc22_bytes.unwrap(), None).await;
        if rsp.is_err() {
            return Err(rsp.err().unwrap().to_string());
        }

        Ok(rsp.unwrap())
    }
}

fn parse_rsp<'a,T: serde::Deserialize<'a>>(msg_wrapper: &'a MsgWrapper) -> Result<T, String> {
    if RSP_CODE_SUCCESS != msg_wrapper.action_code {
        return Err(msg_wrapper.error_msg.clone());
    }

    let t = serde_json::from_slice::<T>(&msg_wrapper.body);
    if t.is_err() {
        return Err(format!("parse msg_detail fail, err={}", t.err().unwrap()));
    }

    Ok(t.unwrap())
}