use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogCommitment, DLogWitness};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use crate::ChosenHash;
use crate::generic::clamping_seed;
use crate::generic::share::Ed25519Share;
use crate::keygen::party2::{Party2KeygenMsg1, Party2KeygenMsg2};

pub type Party1KeygenMsg1 = DLogCommitment;

pub struct Party1InitAssets {
    pub x1: Scalar<Ed25519>,
    pub prefix: [u8; 32],
    pub Q1: Point<Ed25519>,
    pub x1_d_log_witness: DLogWitness<Ed25519>,
}

pub fn party1_step1() -> (Party1KeygenMsg1, Party1InitAssets) {
    let (x1, prefix, _seed) = clamping_seed();
    let (keypair, x1_d_log_commitment, x1_d_log_witness) = CurveKeyPair::generate_keypair_and_blind_d_log_proof_with_x(&x1);

    let party1_keygen_msg1 = x1_d_log_commitment;
    (
        party1_keygen_msg1,
        Party1InitAssets {
            x1,
            prefix,
            Q1: keypair.public,
            x1_d_log_witness,
        }
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1KeygenMsg2 {
    pub x1_d_log_witness: DLogWitness<Ed25519>,
    pub agg_Q: Point<Ed25519>,
}

pub fn party1_step2(msg1: Party2KeygenMsg1, assets: Party1InitAssets) -> Result<(Party1KeygenMsg2, Ed25519Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let peer_d_log_proof = msg1.d_log_proof;
    let flag = peer_d_log_proof.verify(None);
    if !flag {
        error.reason = "fail to verify peer d_log_proof".to_string();
        return Err(error);
    }

    // calc share
    let Q1 = &assets.Q1;
    let Q2 = peer_d_log_proof.Q;
    let agg_hash = ChosenHash::new()
        .chain_point(Q1)
        .chain_point(&Q2)
        .finalize();
    // ensure that x= agg_hash_Q(x1+x2) is a multiple of cofactor
    let agg_hash_Q = Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&agg_hash)) * Scalar::<Ed25519>::from(8);

    let agg_Q = (&agg_hash_Q * Q1) + (&agg_hash_Q * Q2);

    let pending_share = Ed25519Share {
        prefix: assets.prefix,
        x: assets.x1,
        agg_hash_Q,
        agg_Q: agg_Q.clone(),
        agg_Q_minus: (-&agg_Q),
    };

    let party1_keygen_msg2 = Party1KeygenMsg2 {
        x1_d_log_witness: assets.x1_d_log_witness,
        agg_Q,
    };

    Ok((
        party1_keygen_msg2,
        pending_share
    ))
}

pub fn party1_step3(msg2: Party2KeygenMsg2, pending_share: Ed25519Share) -> Result<Ed25519Share, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "keygen".to_string(),
        step: 3,
        reason: "".to_string(),
    };

    let agg_Q = &pending_share.agg_Q;
    if agg_Q != &msg2.agg_Q {
        error.reason = "agg_Q not consistent".to_string();
        return Err(error);
    }
    Ok(pending_share)
}