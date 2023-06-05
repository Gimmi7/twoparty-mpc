use serde::{Deserialize, Serialize};
use common::socketmsg::types::{EmptyMsg, Mpc22Msg, MPC_EXPORT, MPC_KEYGEN, MPC_ROTATE, MPC_SCOPE_SECP256K1ECDSA, MPC_SIGN, SavedShare};
use crate::websocket::SyncClient;
use twoparty_secp256k1::{keygen, sign, generic::share::Party1Share, rotate, export};
use twoparty_secp256k1::sign::party2::{Party2SignMsg1, Party2SignMsg2};
use crate::mpc::parse_rsp;
use curv::arithmetic::traits::Converter;
use twoparty_secp256k1::export::party2::Party2ExportMsg1;
use twoparty_secp256k1::rotate::party2::{Party2RotateMsg1, Party2RotateMsg2};


pub async fn secp256k1_keygen(identity_id: String, url: String) -> Result<SavedShare, String> {
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

fn parse_party1_share(share_detail: &[u8]) -> Result<Party1Share, String> {
    let share_detail_result = serde_json::from_slice::<Party1Share>(share_detail);
    if share_detail_result.is_err() {
        return Err(share_detail_result.err().unwrap().to_string());
    }
    Ok(share_detail_result.unwrap())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Secp256k1Sig {
    // hex encoded
    pub r: String,
    // hex encoded
    pub s: String,
    pub v: u8,
}

pub async fn secp256k1_sign(url: String, saved_share: &SavedShare, message_digest: Vec<u8>) -> Result<Vec<u8>, String> {
    let inner_share = parse_party1_share(&saved_share.share_detail)?;
    let identity_id = &saved_share.identity_id;
    let sync_client = SyncClient::connect_server(identity_id.to_string(), url, 10).await?;
    let (
        party1_sign_msg1,
        d_log_witness,
        party1_eph_keypair
    ) = sign::party1::party1_step1();
    let mpc22_msg = Mpc22Msg {
        command: MPC_SIGN,
        scope: MPC_SCOPE_SECP256K1ECDSA,
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
        d_log_witness,
        &message_digest,
        &party1_eph_keypair,
        &inner_share,
    );
    if party1_result2.is_err() {
        return Err(party1_result2.err().unwrap().to_string());
    }
    let (party1_sign_msg2, k2_G) = party1_result2.unwrap();
    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_sign_msg2, mpc22_step2).await?;
    let party2_sign_msg2 = parse_rsp::<Party2SignMsg2>(&rsp2)?;

    let party1_result3 = sign::party1::party1_step3(
        party2_sign_msg2,
        &inner_share,
        party1_eph_keypair,
        &message_digest,
        k2_G,
    );
    if party1_result3.is_err() {
        return Err(party1_result3.err().unwrap().to_string());
    }
    let sig = party1_result3.unwrap();

    let secp256k1_sig = Secp256k1Sig {
        r: sig.r.to_hex(),
        s: sig.s.to_hex(),
        v: sig.v,
    };
    Ok(serde_json::to_vec(&secp256k1_sig).unwrap())
}

pub async fn secp256k1_rotate(url: String, old_share: &SavedShare) -> Result<SavedShare, String> {
    let old_inner_share = parse_party1_share(&old_share.share_detail)?;
    let identity_id = &old_share.identity_id;
    let sync_client = SyncClient::connect_server(identity_id.clone(), url, 10).await?;
    let (party1_rotate_msg1,
        seed_witness,
        party1_seed_keypair) = rotate::party1::party1_step1();
    let mpc22_msg = Mpc22Msg {
        command: MPC_ROTATE,
        scope: MPC_SCOPE_SECP256K1ECDSA,
        party: 1,
        step: 1,
        msg_detail: vec![],
        identity_id: identity_id.clone(),
        share_id: old_share.share_id.to_string(),
    };
    let rsp1 = sync_client.send_mpc22_msg(&party1_rotate_msg1, mpc22_msg.clone()).await?;
    let party2_rotate_msg1 = parse_rsp::<Party2RotateMsg1>(&rsp1)?;

    let party1_result2 = rotate::party1::party1_step2(
        party2_rotate_msg1,
        seed_witness,
        party1_seed_keypair,
        &old_inner_share,
    );
    if party1_result2.is_err() {
        return Err(party1_result2.err().unwrap().to_string());
    }
    let (party1_rotate_msg2, pending_share) = party1_result2.unwrap();

    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_rotate_msg2, mpc22_step2).await?;
    let party2_rotate_msg2 = parse_rsp::<Party2RotateMsg2>(&rsp2)?;

    let party1_result3 = rotate::party1::party1_step3(
        party2_rotate_msg2.clone(),
        pending_share);
    if party1_result3.is_err() {
        return Err(party1_result3.err().unwrap().to_string());
    }
    let share11 = party1_result3.unwrap();
    let new_share_id = &party2_rotate_msg2.share_id;
    let new_inner_bytes = serde_json::to_vec(&share11).unwrap();
    let new_saved_share = SavedShare {
        identity_id: identity_id.to_string(),
        share_id: new_share_id.to_string(),
        scope: MPC_SCOPE_SECP256K1ECDSA,
        party: 1,
        uncompressed_pub: share11.public.pub_key.to_bytes(false).to_vec(),
        share_detail: new_inner_bytes,
    };

    Ok(new_saved_share)
}


pub async fn secp256k1_export(url: String, saved_share: &SavedShare) -> Result<String, String> {
    let inner_share = parse_party1_share(&saved_share.share_detail)?;
    let identity_id = &saved_share.identity_id;
    let sync_client = SyncClient::connect_server(identity_id.to_string(), url, 10).await?;
    let mpc22_msg = Mpc22Msg {
        command: MPC_EXPORT,
        scope: MPC_SCOPE_SECP256K1ECDSA,
        party: 1,
        step: 1,
        msg_detail: vec![],
        identity_id: identity_id.clone(),
        share_id: saved_share.share_id.to_string(),
    };
    let empty_msg = EmptyMsg {};
    let rsp1 = sync_client.send_mpc22_msg(&empty_msg, mpc22_msg.clone()).await?;
    let party2_export_msg1 = parse_rsp::<Party2ExportMsg1>(&rsp1)?;

    let party1_export_msg2 = export::party1::party1_step2(party2_export_msg1, &inner_share);
    let mut mpc22_step2 = mpc22_msg.clone();
    mpc22_step2.step = 2;
    let rsp2 = sync_client.send_mpc22_msg(&party1_export_msg2, mpc22_step2).await?;
    let party2_export_msg2 = parse_rsp(&rsp2)?;

    let party1_result3 = export::party1::party1_step3(
        party2_export_msg2, &inner_share);
    if party1_result3.is_err() {
        return Err(party1_result3.err().unwrap().to_string());
    }
    let export_x = party1_result3.unwrap();

    Ok(export_x.to_hex())
}
