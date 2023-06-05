use common::socketmsg::types::{Mpc22Msg, MPC_KEYGEN, MPC_SCOPE_ED25519EDDSA, MPC_SIGN, SavedShare};
use twoparty_ed25519::generic::share::Ed25519Share;
use twoparty_ed25519::{keygen, sign};
use twoparty_ed25519::keygen::party2::{Party2KeygenMsg1, Party2KeygenMsg2};
use twoparty_ed25519::sign::party2::{Party2SignMsg1, Party2SignMsg2};
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

fn parse_share(share_detail: &[u8]) -> Result<Ed25519Share, String> {
    let share_detail_result = serde_json::from_slice::<Ed25519Share>(share_detail);
    if share_detail_result.is_err() {
        return Err(share_detail_result.err().unwrap().to_string());
    }

    Ok(share_detail_result.unwrap())
}

pub async fn ed25519_sign(url: String, saved_share: &SavedShare, message_digest: Vec<u8>) -> Result<Vec<u8>, String> {
    let inner_share = parse_share(&saved_share.share_detail)?;
    let identity_id = &saved_share.identity_id;
    let sync_client = SyncClient::connect_server(identity_id.to_string(), url, 10).await?;
    let (party1_sign_msg1,
        eph_keypair1,
        eph_witness) = sign::party1::party1_step1(&inner_share, &message_digest);
    let mpc22_msg = Mpc22Msg {
        command: MPC_SIGN,
        scope: MPC_SCOPE_ED25519EDDSA,
        party: 1,
        step: 1,
        msg_detail: vec![],
        identity_id: identity_id.clone(),
        share_id: saved_share.share_id.to_string(),
    };
    let rsp1 = sync_client.send_mpc22_msg(&party1_sign_msg1, mpc22_msg.clone()).await?;
    let party2_sign_msg1 = parse_rsp::<Party2SignMsg1>(&rsp1)?;

    let party1_result2 = sign::party1::party1_step2(
        party2_sign_msg1,
        eph_witness,
        &message_digest,
        eph_keypair1,
        &inner_share);
    if party1_result2.is_err() {
        return Err(party1_result2.err().unwrap().to_string());
    }
    let party1_sign_msg2 = party1_result2.unwrap();

    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_sign_msg2, mpc22_step2).await?;
    let party2_sign_msg2 = parse_rsp::<Party2SignMsg2>(&rsp2)?;

    let party1_partial_sig = &party1_sign_msg2.partial_sig;
    let party1_result3 = sign::party1::party1_step3(
        party2_sign_msg2, party1_partial_sig, &inner_share, &message_digest);
    if party1_result3.is_err() {
        return Err(party1_result3.err().unwrap().to_string());
    }

    let sig = party1_result3.unwrap();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(sig.R.to_bytes(true).as_ref());
    sig_bytes[32..].copy_from_slice(sig.s.to_bytes().as_ref());
    Ok(Vec::from(sig_bytes))
}
