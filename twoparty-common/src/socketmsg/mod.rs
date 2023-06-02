pub mod types;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MsgWrapper {
    pub seq: u32,
    pub timestamp: u128,
    pub action: u8,
    // req_code | rsp_code
    pub action_code: u32,
    pub body: Vec<u8>,

    // only for rsp
    pub error_msg: String,
    // only for notice
    pub notice_id: String,
}

pub const MSG_ACTION_REQ: u8 = 1;
pub const MSG_ACTION_RSP: u8 = 2;
pub const MSG_ACTION_NOTICE: u8 = 3;
pub const MSG_ACTION_ACK: u8 = 4;


pub const REQ_CODE_MPC22: u32 = 1;


pub const RSP_CODE_SUCCESS: u32 = 200;
pub const RSP_CODE_BAD_REQUEST: u32 = 400;
pub const RSP_CODE_UNAUTHORIZED: u32 = 401;
pub const RSP_CODE_PAYMENT_REQUIRED: u32 = 402;
pub const RSP_CODE_FORBIDDEN: u32 = 403;
pub const RSP_CODE_NOT_FOUND: u32 = 404;
pub const RSP_CODE_TOO_MANY_REQUESTS: u32 = 429;
pub const RSP_CODE_INTERNAL_SERVER_ERROR: u32 = 500;
pub const RSP_CODE_NOT_IMPLEMENTED: u32 = 501;
pub const RSP_CODE_SERVICE_UNAVAILABLE: u32 = 503;


impl MsgWrapper {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> MsgWrapper {
        serde_json::from_slice::<MsgWrapper>(bytes).unwrap()
    }
}