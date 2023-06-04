use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mpc22Msg {
    pub command: u8,
    pub scope: u8,
    pub party: u8,
    pub step: u8,
    pub msg_detail: Vec<u8>,
    // needed only when keygen
    pub identity_id: String,
    // needed except keygen
    pub share_id: String,
}


pub const MPC_KEYGEN: u8 = 1;
pub const MPC_SIGN: u8 = 2;
pub const MPC_ROTATE: u8 = 3;
pub const MPC_EXPORT: u8 = 4;


pub const MPC_SCOPE_SECP256K1ECDSA: u8 = 1;
pub const MPC_SCOPE_ED25519EDDSA: u8 = 2;

#[derive(Serialize, Deserialize)]
pub struct SavedShare {
    pub identity_id: String,
    pub share_id: String,
    pub scope: u8,
    pub party: u8,
    pub uncompressed_pub: Vec<u8>,
    pub share_detail: Vec<u8>,
}