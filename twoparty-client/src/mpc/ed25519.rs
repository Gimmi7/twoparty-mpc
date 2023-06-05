use common::socketmsg::types::{Mpc22Msg, MPC_KEYGEN, MPC_SCOPE_ED25519EDDSA, SavedShare};
use twoparty_ed25519::keygen;
use twoparty_ed25519::keygen::party2::{Party2KeygenMsg1, Party2KeygenMsg2};
use crate::mpc::parse_rsp;
use crate::websocket::SyncClient;

pub async fn ed25519_keygen(identity_id: String, url: String) -> Result<SavedShare, String> {
    let sync_client = SyncClient::connect_server(identity_id.clone(), url, 10).await?;
    let (party1_msg1, asset1) = keygen::party1::party1_step1();
    let mpc22_msg = Mpc22Msg {
        command: MPC_KEYGEN,
        scope: MPC_SCOPE_ED25519EDDSA,
        party: 1,
        step: 1,
        msg_detail: vec![],
        identity_id: identity_id.clone(),
        share_id: "".to_string(),
    };
    let rsp1 = sync_client.send_mpc22_msg(&party1_msg1, mpc22_msg.clone()).await?;
    let party2_msg1 = parse_rsp::<Party2KeygenMsg1>(&rsp1)?;

    let party1_result2 = keygen::party1::party1_step2(
        party2_msg1,
        asset1,
    );
    if party1_result2.is_err() {
        return Err(party1_result2.err().unwrap().to_string());
    }
    let (party1_msg2, pending_share1) = party1_result2.unwrap();

    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_msg2, mpc22_step2).await?;
    let party2_msg2 = parse_rsp::<Party2KeygenMsg2>(&rsp2)?;

    let party1_result3 = keygen::party1::party1_step3(
        party2_msg2.clone(),
        pending_share1,
    );
    if party1_result3.is_err() {
        return Err(party1_result3.err().unwrap().to_string());
    }
    let share1 = party1_result3.unwrap();

    let share_id = &party2_msg2.share_id;
    let inner_share_bytes = serde_json::to_vec(&share1).unwrap();
    let saved_share = SavedShare {
        identity_id,
        share_id: share_id.clone(),
        scope: MPC_SCOPE_ED25519EDDSA,
        party: 1,
        uncompressed_pub: share1.agg_Q.to_bytes(false).to_vec(),
        share_detail: inner_share_bytes,
    };

    Ok(saved_share)
}