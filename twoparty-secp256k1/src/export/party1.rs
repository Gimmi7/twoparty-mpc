use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{Decrypt, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};

use common::errors::TwoPartyError;
use crate::ChosenHash;
use crate::export::party2::Party2ExportMsg1;

use crate::generic::share::Party1Share;

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1ExportMsg1 {
    pub x1_d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}

pub fn party1_step1(share: &Party1Share) -> Party1ExportMsg1 {
    let x1 = &share.private.x1;
    let d_log_proof = DLogProof::prove(x1);

    Party1ExportMsg1 {
        x1_d_log_proof: d_log_proof
    }
}

pub fn party1_step2(party2_export_msg1: Party2ExportMsg1, share: &Party1Share) -> Result<BigInt, TwoPartyError> {
    let mut error = TwoPartyError {
        party: 1,
        action: "export".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let encrypted_x2 = party2_export_msg1.encrypted_x2;
    let x2 = Paillier::decrypt(
        &share.private.paillier_dk,
        RawCiphertext::from(encrypted_x2),
    ).0.into_owned();
    if (Scalar::<Secp256k1>::from(&x2) * &share.public.public_share).x_coord().unwrap()
        != share.public.pub_key.x_coord().unwrap() {
        error.reason = "x2 is not the pairing of x1".to_string();
        return Err(error);
    }

    let x = &share.private.x1 * Scalar::<Secp256k1>::from(x2);
    Ok(x.to_bigint())
}