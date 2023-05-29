use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use crate::ChosenHash;
use crate::generic::clamping_seed;
use crate::generic::share::Ed25519Share;
use crate::keygen::party1::{Party1KeygenMsg1, Party1KeygenMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2KeygenMsg1 {
    pub d_log_proof: DLogProof<Ed25519>,
}

pub struct Party2InitAssets {
    pub x2: Scalar<Ed25519>,
    pub prefix: [u8; 32],
    pub Q2: Point<Ed25519>,
}

pub fn party2_step1() -> (Party2KeygenMsg1, Party2InitAssets) {
    let (x2, prefix, _seed) = clamping_seed();
    let (keypair, x2_d_log_proof) = CurveKeyPair::generate_keypair_and_d_log_proof_with_x(&x2);

    let party2_keygen_msg1 = Party2KeygenMsg1 {
        d_log_proof: x2_d_log_proof
    };
    (
        party2_keygen_msg1,
        Party2InitAssets {
            x2,
            prefix,
            Q2: keypair.public,
        }
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2KeygenMsg2 {
    pub agg_Q: Point<Ed25519>,
}

pub fn party2_step2(msg2: Party1KeygenMsg2, msg1: Party1KeygenMsg1, assets: Party2InitAssets) -> Result<(Party2KeygenMsg2, Ed25519Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 2,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    // verify x1's d_log_proof_blind
    let d_log_witness = msg2.x1_d_log_witness;
    let flag = d_log_witness.verify(msg1, None);
    if !flag {
        error.reason = "fail to verify x1's d_log_proof_blind".to_string();
        return Err(error);
    }

    // calc share
    let Q1 = d_log_witness.d_log_proof.Q;
    let Q2 = assets.Q2;
    let agg_hash_Q: Scalar<Ed25519> = ChosenHash::new()
        .chain_point(&Q1)
        .chain_point(&Q2)
        .result_scalar();
    let agg_Q = (&agg_hash_Q * Q1) + (&agg_hash_Q * Q2);
    let agg_Q_minus = -&agg_Q;

    let share = Ed25519Share {
        prefix: assets.prefix,
        x: assets.x2,
        agg_hash_Q,
        agg_Q: agg_Q.clone(),
        agg_Q_minus,
    };

    // check agg_Q consistent
    if agg_Q != msg2.agg_Q {
        error.reason = "agg_Q not consistent".to_string();
        return Err(error);
    }

    let party2_keygen_msg2 = Party2KeygenMsg2 {
        agg_Q
    };

    Ok((
        party2_keygen_msg2,
        share
    ))
}

