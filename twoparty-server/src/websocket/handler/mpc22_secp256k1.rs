use curv::elliptic::curves::Secp256k1;
use tracing::{error, info};
use common::dlog::CurveKeyPair;
use common::get_uuid;
use common::socketmsg::{RSP_CODE_BAD_REQUEST, RSP_CODE_FORBIDDEN, RSP_CODE_INTERNAL_SERVER_ERROR};
use common::socketmsg::types::{MPC_SCOPE_SECP256K1ECDSA, SavedShare};
use crate::websocket::connection_holder::{SocketLocal, upsert_socket_local};
use crate::websocket::inbound_dispatcher::InboundWithTx;
use twoparty_secp256k1::{keygen};
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
            let party1_keygen_msg1 = party1_keygen_msg1_result.unwrap();
            let (party2_keygen_msg1, party2_keypair) = keygen::party2::party2_step1();
            let mpc_eph = &mut socket_local.mpc_eph;
            mpc_eph.insert("party1_keygen_msg1".to_string(), serde_json::to_vec(&party1_keygen_msg1).unwrap());
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