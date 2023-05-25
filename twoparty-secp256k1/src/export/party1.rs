use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use kzen_paillier::{Decrypt, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};

use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};

use crate::export::party2::{Party2ExportMsg1, Party2ExportMsg2};
use crate::generic::challenge_dlog::ChallengeDLogProof;

use crate::generic::share::Party1Share;


pub fn party1_step1() {
    // quest party2 for challenge
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1ExportMsg2 {
    pub x1_d_log_proof: ChallengeDLogProof,
}

pub fn party1_step2(party2_export_msg1: Party2ExportMsg1, share: &Party1Share) -> Party1ExportMsg2 {
    let challenge = party2_export_msg1.challenge;
    let x1 = &share.private.x1;
    let x1_d_log_proof = ChallengeDLogProof::prove(x1, &challenge);
    Party1ExportMsg2 {
        x1_d_log_proof
    }
}

pub fn party1_step3(party2_export_msg2: Party2ExportMsg2, share: &Party1Share) -> Result<BigInt, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 1,
        action: "export".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let encrypted_x2 = party2_export_msg2.encrypted_x2;
    let x2 = Paillier::decrypt(
        &share.private.paillier_dk,
        RawCiphertext::from(encrypted_x2),
    ).0.into_owned();
    let G = Point::<Secp256k1>::generator();
    let x = &share.private.x1 * Scalar::<Secp256k1>::from(x2);

    let new_pub = &x * G;
    if new_pub != share.public.pub_key {
        error.reason = "x2 is not the pairing of x1".to_string();
        return Err(error);
    }

    Ok(x.to_bigint())
}