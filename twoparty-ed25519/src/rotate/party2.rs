use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use common::get_uuid;
use crate::generic::share::Ed25519Share;
use crate::rotate::party1::{Party1RotateMsg1, Party1RotateMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2RotateMsg1 {
    pub delta_proof: DLogProof<Ed25519>,
}

pub fn party2_step1() -> (Party2RotateMsg1, CurveKeyPair<Ed25519>) {
    let (delta_keypair, delta_proof) = CurveKeyPair::generate_keypair_and_d_log_proof();
    let party2_rotate_msg1 = Party2RotateMsg1 {
        delta_proof
    };
    (
        party2_rotate_msg1,
        delta_keypair
    )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Party2RotateMsg2 {
    pub new_x2_proof: DLogProof<Ed25519>,
    pub share_id: String,
}

pub fn party2_step2(msg2: Party1RotateMsg2, msg1: Party1RotateMsg1, delta_keypair: CurveKeyPair<Ed25519>, share: &Ed25519Share) -> Result<(Party2RotateMsg2, Ed25519Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 2,
        action: "rotate".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let peer_delta_witness = msg2.delta_witness;
    let flag = peer_delta_witness.verify(msg1.delta_commitment, None);
    if !flag {
        error.reason = "fail to verify peer delta d_log_proof_blind".to_string();
        return Err(error);
    }

    let new_x1_proof = msg2.new_x1_proof;
    let flag = new_x1_proof.verify(None);
    if !flag {
        error.reason = "fail to verify new_x1 d_log_proof".to_string();
        return Err(error);
    }

    // calc delta, check new_agg_Q == old_agg_Q
    let delta = (delta_keypair.secret * peer_delta_witness.d_log_proof.Q).x_coord().unwrap();
    let new_x2 = &share.x - Scalar::<Ed25519>::from_bigint(&delta);
    let x1_G = new_x1_proof.Q;
    let G = Point::<Ed25519>::generator();
    let new_agg_Q = &share.agg_hash_Q * (&new_x2 * G + x1_G);
    if new_agg_Q.x_coord().unwrap() != share.agg_Q.x_coord().unwrap() {
        error.reason = "new_agg_Q not consistent with old".to_string();
        return Err(error);
    }

    // new_x2 proof
    let (_, new_x2_proof) = CurveKeyPair::generate_keypair_and_d_log_proof_with_x(&new_x2);

    let mut new_share = share.clone();
    new_share.x = new_x2;

    Ok((
        Party2RotateMsg2 {
            new_x2_proof,
            share_id: get_uuid(),
        },
        new_share
    ))
}

