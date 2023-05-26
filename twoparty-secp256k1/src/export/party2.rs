use curv::arithmetic::Samplable;
use curv::BigInt;

use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{Encrypt, Paillier, RawPlaintext};
use serde::{Deserialize, Serialize};
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};
use crate::export::party1::{Party1ExportMsg2};
use crate::generic::share::Party2Share;

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2ExportMsg1 {
    pub challenge: BigInt,
}

pub fn party2_step1() -> Party2ExportMsg1 {
    let challenge = BigInt::sample(2048);
    Party2ExportMsg1 {
        challenge
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2ExportMsg2 {
    pub encrypted_x2: BigInt,
}

pub fn party2_step2(party1_export_msg2: Party1ExportMsg2, challenge: &BigInt, share: &Party2Share) -> Result<Party2ExportMsg2, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 2,
        action: "export".to_string(),
        step: 1,
        reason: "".to_string(),
    };

    let x1_d_log_proof = party1_export_msg2.x1_d_log_proof;
    let flag = x1_d_log_proof.verify(Some(challenge));
    if !flag {
        error.reason = "fail to verify x1_d_log_proof".to_string();
        return Err(error);
    }

    let x1_G = x1_d_log_proof.Q;
    let x2 = &share.private.x2.to_bigint();
    let pub_key = &share.public.pub_key;
    if (Scalar::<Secp256k1>::from(x2) * x1_G).x_coord().unwrap() !=
        pub_key.x_coord().unwrap() {
        error.reason = "x1 is not the pairing of x2".to_string();
        return Err(error);
    }

    let encrypted_x2 = Paillier::encrypt(
        &share.public.paillier_ek,
        RawPlaintext::from(x2),
    ).0.into_owned();

    Ok(
        Party2ExportMsg2 {
            encrypted_x2
        }
    )
}