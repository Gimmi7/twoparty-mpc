use curv::elliptic::curves::Ed25519;
use tracing::error;
use tracing::log::info;
use common::dlog::CurveKeyPair;
use common::socketmsg::{RSP_CODE_BAD_REQUEST, RSP_CODE_FORBIDDEN, RSP_CODE_INTERNAL_SERVER_ERROR};
use common::socketmsg::types::{MPC_SCOPE_ED25519EDDSA, SavedShare};
use twoparty_ed25519::{keygen, rotate, sign};
use twoparty_ed25519::keygen::party1::{Party1KeygenMsg1, Party1KeygenMsg2};
use twoparty_ed25519::keygen::party2::Party2InitAssets;
use twoparty_ed25519::rotate::party1::{Party1RotateMsg1, Party1RotateMsg2};
use twoparty_ed25519::sign::party1::{Party1SignMsg1, Party1SignMsg2};
use crate::storage::share_storage::FileShareStorage;
use crate::websocket::connection_holder::{SocketLocal, upsert_socket_local};
use crate::websocket::inbound_dispatcher::InboundWithTx;

pub async fn ed25519_keygen(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("ed25519_keygen step1 start");
            let party1_msg1_result = serde_json::from_slice::<Party1KeygenMsg1>(msg_detail);
            if party1_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_msg1".to_string()).await;
                return;
            }

            let (party2_msg1, assets2) = keygen::party2::party2_step1();
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("assets2".to_string(), serde_json::to_vec(&assets2).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_msg1_bytes = serde_json::to_vec(&party2_msg1).unwrap();
            inbound.success_rsp(Some(party2_msg1_bytes)).await;
            info!("ed25519_keygen step1 success");
        }
        2 => {
            info!("ed25519_keygen step2 start");
            let party1_msg2_result = serde_json::from_slice::<Party1KeygenMsg2>(msg_detail);
            if party1_msg2_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_msg2".to_string()).await;
                return;
            }
            let party1_msg2 = party1_msg2_result.unwrap();

            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_msg1 = serde_json::from_slice::<Party1KeygenMsg1>(mpc_eph.get("party1_msg1").unwrap()).unwrap();
            let assets2 = serde_json::from_slice::<Party2InitAssets>(mpc_eph.get("assets2").unwrap()).unwrap();

            let party2_result2 = keygen::party2::party2_step2(
                party1_msg2,
                party1_msg1,
                assets2,
            );
            if party2_result2.is_err() {
                let err = party2_result2.err().unwrap().to_string();
                error!("{}" , err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let (party2_msg2, share2) = party2_result2.unwrap();

            let share_id = &party2_msg2.share_id;
            let saved_share = SavedShare {
                identity_id: socket_local.identity_id,
                share_id: share_id.clone(),
                scope: MPC_SCOPE_ED25519EDDSA,
                party: 2,
                uncompressed_pub: share2.agg_Q.to_bytes(false).to_vec(),
                share_detail: serde_json::to_vec(&share2).unwrap(),
            };
            // save share2
            let save_result = FileShareStorage::save_share(saved_share).await;
            if save_result.is_err() {
                let err = format!("save share fail: {}", save_result.unwrap_err());
                error!("{}",&err);
                inbound.fail_rsp(RSP_CODE_INTERNAL_SERVER_ERROR, err).await;
                return;
            }

            let party2_msg2_bytes = serde_json::to_vec(&party2_msg2).unwrap();
            inbound.success_rsp(Some(party2_msg2_bytes)).await;
            info!("ed25519_keygen step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "ed25519_keygen max step=2".to_string()).await;
        }
    }
}

pub async fn ed25519_sign(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("ed25519_sign step1 start");
            let inner_share = socket_local.ed25519_share.as_ref().unwrap().clone();
            let party1_sign_msg1_result = serde_json::from_slice::<Party1SignMsg1>(msg_detail);
            if party1_sign_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_sign_msg1".to_string()).await;
                return;
            }
            let party1_sign_msg1 = party1_sign_msg1_result.unwrap();

            let (party2_sign_msg1,
                eph_keypair2) = sign::party2::party2_step1(party1_sign_msg1.clone(), &inner_share);
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_sign_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("eph_keypair2".to_string(), serde_json::to_vec(&eph_keypair2).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_sign_msg1_bytes = serde_json::to_vec(&party2_sign_msg1).unwrap();
            inbound.success_rsp(Some(party2_sign_msg1_bytes)).await;
            info!("ed25519_sign step1 success");
        }
        2 => {
            info!("ed25519_sign step2 start");
            let inner_share = socket_local.ed25519_share.unwrap();

            let party1_sign_msg2_result = serde_json::from_slice::<Party1SignMsg2>(msg_detail);
            if party1_sign_msg2_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_sign_msg2".to_string()).await;
                return;
            }
            let party1_sign_msg2 = party1_sign_msg2_result.unwrap();

            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_sign_msg1 = serde_json::from_slice::<Party1SignMsg1>(mpc_eph.get("party1_sign_msg1").unwrap()).unwrap();
            let eph_keypair2 = serde_json::from_slice::<CurveKeyPair<Ed25519>>(mpc_eph.get("eph_keypair2").unwrap()).unwrap();

            let party2_result2 = sign::party2::party2_step2(
                party1_sign_msg2,
                party1_sign_msg1,
                eph_keypair2,
                &inner_share);
            if party2_result2.is_err() {
                let err = party2_result2.err().unwrap().to_string();
                error!("{}", err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let party2_sign_msg2 = party2_result2.unwrap();

            let party2_sign_msg2_bytes = serde_json::to_vec(&party2_sign_msg2).unwrap();
            inbound.success_rsp(Some(party2_sign_msg2_bytes)).await;
            info!("ed25519_sign step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "ed25519_sign max step=2".to_string()).await;
        }
    }
}


pub async fn ed25519_rotate(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("ed25519_rotate step1 start");
            let party1_rotate_msg1_result = serde_json::from_slice::<Party1RotateMsg1>(msg_detail);
            if party1_rotate_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_rotate_msg1".to_string()).await;
                return;
            }

            let (party2_rotate_msg1,
                delta_keypair2) = rotate::party2::party2_step1();

            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_rotate_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("delta_keypair2".to_string(), serde_json::to_vec(&delta_keypair2).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_rotate_msg1_bytes = serde_json::to_vec(&party2_rotate_msg1).unwrap();
            inbound.success_rsp(Some(party2_rotate_msg1_bytes)).await;
            info!("ed25519_rotate step1 success");
        }
        2 => {
            info!("ed25519_rotate step2 start");
            let inner_share = socket_local.ed25519_share.unwrap();

            let party1_rotate_msg2_result = serde_json::from_slice::<Party1RotateMsg2>(msg_detail);
            if party1_rotate_msg2_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_rotate_msg2".to_string()).await;
                return;
            }
            let party1_rotate_msg2 = party1_rotate_msg2_result.unwrap();

            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_rotate_msg1 = serde_json::from_slice::<Party1RotateMsg1>(mpc_eph.get("party1_rotate_msg1").unwrap()).unwrap();
            let delta_keypair2 = serde_json::from_slice::<CurveKeyPair<Ed25519>>(mpc_eph.get("delta_keypair2").unwrap()).unwrap();


            let party2_result2 = rotate::party2::party2_step2(
                party1_rotate_msg2,
                party1_rotate_msg1,
                delta_keypair2,
                &inner_share,
            );
            if party2_result2.is_err() {
                let err = party2_result2.err().unwrap().to_string();
                error!("{}", err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let (party2_rotate_msg2, new_share2) = party2_result2.unwrap();

            let new_share_id = &party2_rotate_msg2.share_id;
            let new_saved_share = SavedShare {
                identity_id: socket_local.socket_id,
                share_id: new_share_id.to_string(),
                scope: MPC_SCOPE_ED25519EDDSA,
                party: 2,
                uncompressed_pub: new_share2.agg_Q.to_bytes(false).to_vec(),
                share_detail: serde_json::to_vec(&new_share2).unwrap(),
            };
            // save new_share2
            let save_result = FileShareStorage::save_share(new_saved_share).await;
            if save_result.is_err() {
                let err = format!("save share fail: {}", save_result.unwrap_err());
                error!("{}",&err);
                inbound.fail_rsp(RSP_CODE_INTERNAL_SERVER_ERROR, err).await;
                return;
            }

            let party2_rotate_msg2_bytes = serde_json::to_vec(&party2_rotate_msg2).unwrap();
            inbound.success_rsp(Some(party2_rotate_msg2_bytes)).await;
            info!("ed25519_rotate step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "ed25519_rotate max step=2".to_string()).await;
        }
    }
}
