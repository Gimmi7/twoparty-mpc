use tracing::error;
use tracing::log::info;
use common::socketmsg::{RSP_CODE_BAD_REQUEST, RSP_CODE_FORBIDDEN, RSP_CODE_INTERNAL_SERVER_ERROR};
use common::socketmsg::types::{MPC_SCOPE_ED25519EDDSA, SavedShare};
use twoparty_ed25519::keygen;
use twoparty_ed25519::keygen::party1::{Party1KeygenMsg1, Party1KeygenMsg2};
use twoparty_ed25519::keygen::party2::Party2InitAssets;
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