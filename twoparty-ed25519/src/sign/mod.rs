use std::ops::Mul;
use curv::arithmetic::Converter;
use curv::BigInt;

use curv::cryptographic_primitives::hashing::{Digest};
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
        let mut k_hash = ChosenHash::new()
            .chain(self.agg_R.to_bytes(true))
            .chain(share.agg_Q.to_bytes(true))
            .chain(self.message_digest)
            .finalize();
        // reverse because BigInt uses big-endian
        k_hash.reverse();
        let k=Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&k_hash));

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
        let mut k_hash = ChosenHash::new()
            .chain(self.R.to_bytes(true))
            .chain(share.agg_Q.to_bytes(true))
            .chain(message_digest)
            .finalize();
        // reverse because BigInt uses big-endian
        k_hash.reverse();

        let k=Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&k_hash));

        let G = Point::<Ed25519>::generator();
        let R_test = (k * &share.agg_Q_minus) + &self.s * G;
        (&self.R - R_test).mul(Scalar::from(8)).is_zero()
    }
}

pub fn normal_sign(x: &Scalar<Ed25519>, prefix: &[u8; 32], digest: &[u8]) -> [u8; 64] {
    let mut r_hash = ChosenHash::new()
        .chain(prefix)
        .chain(digest)
        .finalize();
    // reverse because BigInt uses big-endian
    r_hash.reverse();
    let r = Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&r_hash));


    let G = Point::<Ed25519>::generator();
    let R = &r * G;
    let Q = x * G;

    let mut k_hash = ChosenHash::new()
        .chain(R.to_bytes(true))
        .chain(Q.to_bytes(true))
        .chain(digest)
        .finalize();
    // reverse because BigInt uses big-endian
    k_hash.reverse();
    let k = Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&k_hash));

    let s = r + k * x;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(R.to_bytes(true).as_ref());
    sig_bytes[32..].copy_from_slice(s.to_bytes().as_ref());
    sig_bytes
}