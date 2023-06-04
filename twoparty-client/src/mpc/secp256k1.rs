
use common::socketmsg::types::{Mpc22Msg, MPC_KEYGEN, MPC_SCOPE_SECP256K1ECDSA, SavedShare};
use crate::websocket::SyncClient;
use twoparty_secp256k1::keygen;
use crate::mpc::parse_rsp;

pub async fn keygen(identity_id: String, url: String) -> Result<SavedShare, String> {
    let sync_client = SyncClient::connect_server(identity_id.clone(), url, 10).await?;
    let (party1_keygen_msg1, witness, party1_keypair) = keygen::party1::party1_step1();
    let mpc22_msg = Mpc22Msg {
        command: MPC_KEYGEN,
        scope: MPC_SCOPE_SECP256K1ECDSA,
        party: 1,
        step: 1,
        msg_detail: vec![],
        identity_id: identity_id.clone(),
        share_id: "".to_string(),
    };

    let rsp1 = sync_client.send_mpc22_msg(&party1_keygen_msg1, mpc22_msg.clone()).await?;
    let party2_keygen_msg1 = parse_rsp::<keygen::party2::Party2KeyGenMsg1>(&rsp1)?;

    let party1_result2 = keygen::party1::party1_step2(
        party2_keygen_msg1,
        witness,
        party1_keypair,
    );
    if party1_result2.is_err() {
        return Err(party1_result2.err().unwrap().to_string());
    }
    let (party1_keygen_msg2, party1_share) = party1_result2.unwrap();

    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_keygen_msg2, mpc22_step2).await?;
    let share_id = parse_rsp::<String>(&rsp2)?;

    let inner_share_bytes = serde_json::to_vec(&party1_share).unwrap();
    let saved_share = SavedShare {
        identity_id,
        share_id,
        scope: MPC_SCOPE_SECP256K1ECDSA,
        party: 1,
        uncompressed_pub: party1_share.public.pub_key.to_bytes(false).to_vec(),
        share_detail: inner_share_bytes,
    };
    Ok(saved_share)
}