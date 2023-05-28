use std::ops::Mul;

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};
use crate::ChosenHash;
use crate::generic::share::Ed25519Share;

pub mod party2;
pub mod party1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EdDSASignature {
    pub R: Point<Ed25519>,
    pub s: Scalar<Ed25519>,
}

pub struct PartialSigningParams {
    pub agg_R: Point<Ed25519>,
    pub message_digest: Vec<u8>,
    pub ri: Scalar<Ed25519>,
}

impl PartialSigningParams {
    pub fn partial_sign(self, share: &Ed25519Share) -> EdDSASignature {
        // calc k= sha512(agg_R,agg_Q,message_digest)
        let k:Scalar<Ed25519> = ChosenHash::new()
            .chain(self.agg_R.to_bytes(true))
            .chain(share.agg_Q.to_bytes(true))
            .chain(self.message_digest)
            .result_scalar();

        let s = self.ri + k * &share.x * &share.agg_hash_Q;
        EdDSASignature {
            R: self.agg_R,
            s,
        }
    }
}


pub fn add_signature_parts(sigs: &[EdDSASignature]) -> Result<EdDSASignature, ()> {
    //test equality of group elements:
    let all_R_eq = sigs[1..].iter().all(|sig| sig.R == sigs[0].R);
    if !all_R_eq {
        return Err(());
    }

    //sum s part of the signature:
    let s1 = sigs[0].s.clone();
    let sum = sigs[1..].iter().fold(s1, |acc, si| acc + &si.s);
    Ok(
        EdDSASignature {
            R: sigs[0].R.clone(),
            s: sum,
        }
    )
}

impl EdDSASignature {
    // the verification equation `[8][s]B = [8]R + [8][k]A` MUST be satisfied;
    // [8]s*G= [8]R + [8]kQ
    pub fn verify(&self, message_digest: &Vec<u8>, share: &Ed25519Share) -> bool {
        let  k = ChosenHash::new()
            .chain(self.R.to_bytes(true))
            .chain(share.agg_Q.to_bytes(true))
            .chain(message_digest)
            .result_scalar();
        let G = Point::<Ed25519>::generator();
        let R_test = (k * &share.agg_Q_minus) + &self.s * G;
        (&self.R - R_test).mul(Scalar::from(8)).is_zero()
    }
}
