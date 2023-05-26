//! This is a Schnorr signature,[https://gimmi7.github.io/stromata/cryptography/schnorr.html],
//! proof of knowledge for knowing discrete logarithm of Q which is x
//!
//! prover:
//! R= r*G, Q= x*G
//! e= hash(R + G + Q + [challenge])
//! s= r - e·x
//! (s,R,Q)
//!
//! verifier:
//! s * G + e * Q == R  && R != 0
#![allow(non_snake_case)]

use std::marker::PhantomData;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

pub mod errors;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DLogProof<C: Curve, H: Digest + Clone> {
    pub Q: Point<C>,
    pub R: Point<C>,
    pub s: Scalar<C>,
    #[serde(skip)]
    phantom: PhantomData<H>,
}

impl<C: Curve, H: Digest + Clone> DLogProof<C, H> {
    pub fn prove(x: &Scalar<C>, challenge: Option<&BigInt>) -> Self {
        let G = Point::<C>::generator();

        let r = Scalar::<C>::random();
        let R = &r * G;

        let Q = x * G;

        let mut hash = H::new()
            .chain_point(&R)
            .chain_point(&G.to_point())
            .chain_point(&Q);
        if challenge.is_some() {
            hash = hash.chain_bigint(challenge.unwrap());
        }
        let e: Scalar<C> = hash.result_scalar();

        let e_x = e * x;
        let s = r - e_x;
        DLogProof {
            Q,
            R,
            s,
            phantom: PhantomData::default(),
        }
    }

    // s * G + e * Q == R  && R != 0
    pub fn verify(&self, challenge: Option<&BigInt>) -> bool {
        let G = Point::<C>::generator();

        let mut hash = H::new()
            .chain_point(&self.R)
            .chain_point(&G.to_point())
            .chain_point(&self.Q);
        if challenge.is_some() {
            hash = hash.chain_bigint(challenge.unwrap());
        }
        let e: Scalar<C> = hash.result_scalar();

        let e_Q = e * &self.Q;
        let R_v = &self.s * G + e_Q;
        R_v == self.R && !R_v.is_zero()
    }
}

#[cfg(test)]
mod test {
    use curv::arithmetic::Samplable;
    use curv::BigInt;
    use curv::elliptic::curves::{Scalar, Secp256k1};
    use crate::DLogProof;

    #[test]
    fn test_d_log_proof() {
        let x = Scalar::<Secp256k1>::random();
        let challenge = BigInt::sample(2048);

        let proof = DLogProof::<Secp256k1, sha3::Keccak256>::prove(&x, Some(&challenge));
        assert!(proof.verify(Some(&challenge)));

        let proof = DLogProof::<Secp256k1, sha3::Keccak256>::prove(&x, None);
        assert!(proof.verify(None));
    }
}