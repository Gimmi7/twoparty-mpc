use std::collections::HashMap;

use tracing::{error};
use crate::websocket::inbound_dispatcher::InboundWithTx;

use common::socketmsg::{RSP_CODE_BAD_REQUEST, RSP_CODE_NOT_FOUND};
use common::socketmsg::types::{Mpc22Msg, MPC_KEYGEN, MPC_SIGN, MPC_ROTATE, MPC_EXPORT, MPC_SCOPE_SECP256K1ECDSA, MPC_SCOPE_ED25519EDDSA};
use twoparty_ed25519::generic::share::Ed25519Share;
use twoparty_secp256k1::generic::share::Party2Share;
use crate::storage::share_storage::FileShareStorage;
use crate::websocket::connection_holder::{SocketLocal, get_socket_local, upsert_socket_local};
use crate::websocket::handler::mpc22_ed25519::{ed25519_keygen, ed25519_rotate, ed25519_sign};
use crate::websocket::handler::mpc22_secp256k1::{secp256k1_export, secp256k1_keygen, secp256k1_rotate, secp256k1_sign};

pub async fn mpc22_handler(inbound: InboundWithTx) {
    let req = &inbound.msg_wrapper;

    let parse_result = serde_json::from_slice::<Mpc22Msg>(&req.body);
    if parse_result.is_err() {
        error!("fail to parse mpc22 msg");
        inbound.fail_rsp(RSP_CODE_BAD_REQUEST, parse_result.err().unwrap().to_string()).await;
        return;
    }
    let mpc22_msg = parse_result.unwrap();
    let socket_id = inbound.socket_id.clone();

    // init connection_local
    let step = mpc22_msg.step;
    if step == 1 {
        let mut socket_local = SocketLocal {
            socket_id: socket_id.clone(),
            identity_id: "".to_string(),
            share_id: "".to_string(),
            mpc_eph: HashMap::new(),
            secp256k1_share: None,
            ed25519_share: None,
        };

        if &mpc22_msg.command == &MPC_KEYGEN {
            let identity_id = &mpc22_msg.identity_id;
            if identity_id.is_empty() {
                error!("identity_id is empty");
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "identity_id is empty".to_string()).await;
                return;
            }
            socket_local.identity_id = identity_id.clone();
        } else {
            let share_id = &mpc22_msg.share_id;
            socket_local.share_id = share_id.clone();
            if share_id.is_empty() {
                error!("share_id is empty for {}", &mpc22_msg.command);
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "share_id is empty".to_string()).await;
                return;
            }
            // load share
            let saved_share_result = FileShareStorage::load_share(share_id.clone()).await;
            if saved_share_result.is_err() {
                let err = format!("fail to load share:{}", saved_share_result.err().unwrap());
                error!("{}", &err);
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, err).await;
                return;
            }
            let saved_share = saved_share_result.unwrap();
            // set socket_local.identity_id
            let identity_id = &saved_share.identity_id;
            socket_local.identity_id = identity_id.clone();
            // set socket_local share TODO: cache share
            match saved_share.scope {
                MPC_SCOPE_SECP256K1ECDSA => {
                    let inner_share = serde_json::from_slice::<Party2Share>(&saved_share.share_detail).unwrap();
                    socket_local.secp256k1_share = Some(inner_share);
                }
                MPC_SCOPE_ED25519EDDSA => {
                    let inner_share = serde_json::from_slice::<Ed25519Share>(&saved_share.share_detail).unwrap();
                    socket_local.ed25519_share = Some(inner_share);
                }
                _ => {}
            }
        }
        // insert connection_local
        upsert_socket_local(socket_local).await;
    }

    // get socket_local
    let option_socket_local = get_socket_local(&socket_id).await;
    if option_socket_local.is_none() {
        error!("can not find socket_local");
        inbound.fail_rsp(RSP_CODE_NOT_FOUND, "can not find socket_local".to_string()).await;
        return;
    }
    let socket_local = option_socket_local.unwrap();


    let command = &mpc22_msg.command;
    let scope = &mpc22_msg.scope;
    let msg_detail = &mpc22_msg.msg_detail;
    match *command {
        MPC_KEYGEN => {
            match *scope {
                MPC_SCOPE_SECP256K1ECDSA => {
                    secp256k1_keygen(inbound, socket_local.clone(), step, msg_detail).await;
                }
                MPC_SCOPE_ED25519EDDSA => {
                    ed25519_keygen(inbound, socket_local.clone(), step, msg_detail).await;
                }
                _ => {
                    inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "unsupported scope".to_string()).await;
                }
            }
        }
        MPC_SIGN => {
            match *scope {
                MPC_SCOPE_SECP256K1ECDSA => {
                    secp256k1_sign(inbound, socket_local.clone(), step, msg_detail).await;
                }
                MPC_SCOPE_ED25519EDDSA => {
                    ed25519_sign(inbound, socket_local.clone(), step, msg_detail).await;
                }
                _ => {
                    inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "unsupported scope".to_string()).await;
                }
            }
        }
        MPC_ROTATE => {
            match *scope {
                MPC_SCOPE_SECP256K1ECDSA => {
                    secp256k1_rotate(inbound, socket_local.clone(), step, msg_detail).await;
                }
                MPC_SCOPE_ED25519EDDSA => {
                    ed25519_rotate(inbound, socket_local.clone(), step, msg_detail).await;
                }
                _ => {
                    inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "unsupported scope".to_string()).await;
                }
            }
        }
        MPC_EXPORT => {
            match *scope {
                MPC_SCOPE_SECP256K1ECDSA => {
                    secp256k1_export(inbound, socket_local.clone(), step, msg_detail).await;
                }
                _ => {
                    inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "only SECP256K1ECDSA support export".to_string()).await;
                }
            }
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "unsupported command".to_string()).await;
        }
    }
}

