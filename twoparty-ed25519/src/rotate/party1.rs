use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogCommitment, DLogProof, DLogWitness};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use crate::generic::share::Ed25519Share;
use crate::rotate::party2::{Party2RotateMsg1, Party2RotateMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1RotateMsg1 {
    pub delta_commitment: DLogCommitment,
}

pub fn party1_step1() -> (Party1RotateMsg1, CurveKeyPair<Ed25519>, DLogWitness<Ed25519>) {
    let (delta_keypair, delta_commitment, delta_witness) = CurveKeyPair::generate_keypair_and_blind_d_log_proof();
    let party1_rotate_msg1 = Party1RotateMsg1 {
        delta_commitment
    };
    (
        party1_rotate_msg1,
        delta_keypair,
        delta_witness
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1RotateMsg2 {
    pub delta_witness: DLogWitness<Ed25519>,
    pub new_x1_proof: DLogProof<Ed25519>,
}

pub fn party1_step2(msg1: Party2RotateMsg1, delta_witness: DLogWitness<Ed25519>, delta_keypair: CurveKeyPair<Ed25519>, share: &Ed25519Share) -> Result<(Party1RotateMsg2, Scalar<Ed25519>), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "rotate".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let peer_delta_proof = msg1.delta_proof;
    let flag = peer_delta_proof.verify(None);
    if !flag {
        error.reason = "fail to verify peer delta d_log_proof".to_string();
        return Err(error);
    }

    // calc delta
    let delta = (delta_keypair.secret * peer_delta_proof.Q).x_coord().unwrap();
    let new_x1 = &share.x + Scalar::<Ed25519>::from_bigint(&delta);

    // proof new_x1
    let (_keypair, new_x1_proof) = CurveKeyPair::generate_keypair_and_d_log_proof_with_x(&new_x1);

    let party1_rotate_msg2 = Party1RotateMsg2 {
        delta_witness,
        new_x1_proof,
    };

    Ok((
        party1_rotate_msg2, new_x1
    ))
}


pub fn party1_step3(msg2: Party2RotateMsg2, new_x1: Scalar<Ed25519>, share: &Ed25519Share) -> Result<Ed25519Share, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "rotate".to_string(),
        step: 3,
        reason: "".to_string(),
    };

    let new_x2_proof = msg2.new_x2_proof;
    let flag = new_x2_proof.verify(None);
    if !flag {
        error.reason = "fail to verify new_x2 d_log_proof".to_string();
        return Err(error);
    }

    // check new_agg_Q == old_agg_Q
    let G = Point::<Ed25519>::generator();
    let x1_G = &new_x1 * G;
    let x2_G = new_x2_proof.Q;
    let new_agg_Q = &share.agg_hash_Q * (x1_G + x2_G);
    if new_agg_Q.x_coord().unwrap() != share.agg_Q.x_coord().unwrap() {
        error.reason = "new_agg_Q not consistent with old".to_string();
        return Err(error);
    }

    let mut new_share = share.clone();
    new_share.x = new_x1;

    Ok(new_share)
}