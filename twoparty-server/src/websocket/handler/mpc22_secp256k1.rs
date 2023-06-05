use curv::elliptic::curves::Secp256k1;
use tracing::{error, info};
use common::dlog::CurveKeyPair;
use common::get_uuid;
use common::socketmsg::{RSP_CODE_BAD_REQUEST, RSP_CODE_FORBIDDEN, RSP_CODE_INTERNAL_SERVER_ERROR};
use common::socketmsg::types::{MPC_SCOPE_SECP256K1ECDSA, SavedShare};
use crate::websocket::connection_holder::{SocketLocal, upsert_socket_local};
use crate::websocket::inbound_dispatcher::InboundWithTx;
use twoparty_secp256k1::{keygen, rotate, sign};
use twoparty_secp256k1::rotate::party1::{Party1RotateMsg1, Party1RotateMsg2};
use twoparty_secp256k1::sign::party1::{Party1SignMsg1, Party1SignMsg2};
use crate::storage::share_storage::{FileShareStorage};

pub async fn secp256k1_keygen(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("secp256k1_keygen step1 start");
            let party1_keygen_msg1_result = serde_json::from_slice::<keygen::party1::Party1KeyGenMsg1>(msg_detail);
            if party1_keygen_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_keygen_msg1".to_string()).await;
                return;
            }

            let (party2_keygen_msg1, party2_keypair) = keygen::party2::party2_step1();
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_keygen_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("party2_keypair".to_string(), serde_json::to_vec(&party2_keypair).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_keygen_msg1_bytes = serde_json::to_vec(&party2_keygen_msg1).unwrap();
            inbound.success_rsp(Some(party2_keygen_msg1_bytes)).await;
            info!("secp256k1_keygen step1 success");
        }
        2 => {
            info!("secp256k1_keygen step2 start");
            let party1_keygen_msg2 = serde_json::from_slice::<keygen::party1::Party1KeygenMsg2>(msg_detail);
            if party1_keygen_msg2.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_keygen_msg2".to_string()).await;
                return;
            }
            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_keygen_msg1 = serde_json::from_slice::<keygen::party1::Party1KeyGenMsg1>(mpc_eph.get("party1_keygen_msg1").unwrap()).unwrap();
            let party2_keypair = serde_json::from_slice::<CurveKeyPair<Secp256k1>>(mpc_eph.get("party2_keypair").unwrap()).unwrap();
            let result2 = keygen::party2::party2_step2(
                party1_keygen_msg2.unwrap(),
                party1_keygen_msg1,
                party2_keypair,
            );
            if result2.is_err() {
                let err = result2.err().unwrap().to_string();
                error!("{}", err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let share_id = get_uuid();
            let share2 = result2.unwrap();

            let saved_share = SavedShare {
                identity_id: socket_local.identity_id,
                share_id: share_id.clone(),
                scope: MPC_SCOPE_SECP256K1ECDSA,
                party: 2,
                uncompressed_pub: share2.public.pub_key.to_bytes(false).to_vec(),
                share_detail: serde_json::to_vec(&share2).unwrap(),
            };
            //  save share2
            let save_result = FileShareStorage::save_share(saved_share).await;
            if save_result.is_err() {
                let err = format!("save share fail: {}", save_result.unwrap_err());
                error!("{}",&err);
                inbound.fail_rsp(RSP_CODE_INTERNAL_SERVER_ERROR, err).await;
                return;
            }

            let share_id_bytes = serde_json::to_vec(&share_id).unwrap();
            inbound.success_rsp(Some(share_id_bytes)).await;
            info!("secp256k1_keygen step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "secp256k1_keygen max step=2".to_string()).await;
        }
    }
}

pub async fn secp256k1_sign(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("secp256k1_sign step1 start");
            let party1_sign_msg1_result = serde_json::from_slice::<Party1SignMsg1>(msg_detail);
            if party1_sign_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_sign_msg1".to_string()).await;
                return;
            }

            let (party2_sign_msg1, party2_eph_keypair) = sign::party2::party2_step1();
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_sign_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("party2_eph_keypair".to_string(), serde_json::to_vec(&party2_eph_keypair).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_sign_msg1_bytes = serde_json::to_vec(&party2_sign_msg1).unwrap();
            inbound.success_rsp(Some(party2_sign_msg1_bytes)).await;
            info!("secp256k1_sign step1 success");
        }
        2 => {
            info!("secp256k1_sign step2 start");
            let inner_share = socket_local.secp256k1_share.unwrap();

            let party1_sign_msg2_result = serde_json::from_slice::<Party1SignMsg2>(msg_detail);
            if party1_sign_msg2_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_sign_msg2".to_string()).await;
                return;
            }
            let party1_sign_msg2 = party1_sign_msg2_result.unwrap();

            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_sign_msg1 = serde_json::from_slice::<Party1SignMsg1>(mpc_eph.get("party1_sign_msg1").unwrap()).unwrap();
            let party2_eph_keypair = serde_json::from_slice::<CurveKeyPair<Secp256k1>>(mpc_eph.get("party2_eph_keypair").unwrap()).unwrap();

            let party2_result2 = sign::party2::party2_step2(
                party1_sign_msg2,
                party1_sign_msg1,
                &inner_share,
                party2_eph_keypair);
            if party2_result2.is_err() {
                let err = party2_result2.err().unwrap().to_string();
                error!("{}", err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let party2_sign_msg2 = party2_result2.unwrap();

            let party2_sign_msg2_bytes = serde_json::to_vec(&party2_sign_msg2).unwrap();
            inbound.success_rsp(Some(party2_sign_msg2_bytes)).await;
            info!("secp256k1_sign step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "secp256k1_sign max step=2".to_string()).await;
        }
    }
}


pub async fn secp256k1_rotate(inbound: InboundWithTx, mut socket_local: SocketLocal, step: u8, msg_detail: &[u8]) {
    match step {
        1 => {
            info!("secp256k1_rotate step1 start");
            let party1_rotate_msg1_result = serde_json::from_slice::<Party1RotateMsg1>(msg_detail);
            if party1_rotate_msg1_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_rotate_msg1".to_string()).await;
                return;
            }

            let (party2_rotate_msg1, party2_seed_keypair) = rotate::party2::party2_step1();
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_rotate_msg1".to_string(), msg_detail.to_vec());
            mpc_eph.insert("party2_seed_keypair".to_string(), serde_json::to_vec(&party2_seed_keypair).unwrap());

            // update socket_local
            upsert_socket_local(socket_local).await;

            let party2_rotate_msg1_bytes = serde_json::to_vec(&party2_rotate_msg1).unwrap();
            inbound.success_rsp(Some(party2_rotate_msg1_bytes)).await;
            info!("secp256k1_rotate step1 success");
        }
        2 => {
            info!("secp256k1_rotate step2 start");
            let inner_share = socket_local.secp256k1_share.unwrap();

            let party1_rotate_msg2_result = serde_json::from_slice::<Party1RotateMsg2>(msg_detail);
            if party1_rotate_msg2_result.is_err() {
                inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "fail to parse party1_rotate_msg2".to_string()).await;
                return;
            }
            let party1_rotate_msg2 = party1_rotate_msg2_result.unwrap();

            let mpc_eph = &mut socket_local.mpc_eph;
            let party1_rotate_msg1 = serde_json::from_slice::<Party1RotateMsg1>(mpc_eph.get("party1_rotate_msg1").unwrap()).unwrap();
            let party2_seed_keypair = serde_json::from_slice::<CurveKeyPair<Secp256k1>>(mpc_eph.get("party2_seed_keypair").unwrap()).unwrap();

            let party2_result2 = rotate::party2::party2_step2(
                party1_rotate_msg2,
                party1_rotate_msg1,
                party2_seed_keypair,
                &inner_share,
            );
            if party2_result2.is_err() {
                let err = party2_result2.err().unwrap().to_string();
                error!("{}", err);
                inbound.fail_rsp(RSP_CODE_FORBIDDEN, err).await;
                return;
            }
            let (party2_rotate_msg2, share22) = party2_result2.unwrap();
            let new_share_id = &party2_rotate_msg2.share_id;
            let new_saved_share = SavedShare {
                identity_id: socket_local.identity_id,
                share_id: new_share_id.to_string(),
                scope: MPC_SCOPE_SECP256K1ECDSA,
                party: 2,
                uncompressed_pub: share22.public.pub_key.to_bytes(false).to_vec(),
                share_detail: serde_json::to_vec(&share22).unwrap(),
            };
            // save share22
            let save_result=FileShareStorage::save_share(new_saved_share).await;
            if save_result.is_err() {
                let err = format!("save share fail: {}", save_result.unwrap_err());
                error!("{}",&err);
                inbound.fail_rsp(RSP_CODE_INTERNAL_SERVER_ERROR, err).await;
                return;
            }

            let party2_rotate_msg2_bytes = serde_json::to_vec(&party2_rotate_msg2).unwrap();
            inbound.success_rsp(Some(party2_rotate_msg2_bytes)).await;
            info!("secp256k1_rotate step2 success");
        }
        _ => {
            inbound.fail_rsp(RSP_CODE_BAD_REQUEST, "secp256k1_rotate max step=2".to_string()).await;
        }
    }
}
