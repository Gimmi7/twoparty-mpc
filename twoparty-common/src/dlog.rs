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


use curv::arithmetic::{Converter, Samplable};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};


const SECURITY_BITS: usize = 256;
type ChosenHash = sha3::Keccak256;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DLogProof<C: Curve> {
    pub Q: Point<C>,
    pub R: Point<C>,
    pub s: Scalar<C>,
}


impl<C: Curve> DLogProof<C> {
    pub fn prove(x: &Scalar<C>, challenge: Option<&BigInt>) -> Self {
        let G = Point::<C>::generator();

        let r = Scalar::<C>::random();
        let R = &r * G;

        let Q = x * G;

        let mut hash = ChosenHash::new()
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
        }
    }

    // s * G + e * Q == R  && R != 0
    pub fn verify(&self, challenge: Option<&BigInt>) -> bool {
        let G = Point::<C>::generator();

        let mut hash = ChosenHash::new()
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

pub struct CurveKeyPair<C: Curve> {
    pub public: Point<C>,
    pub secret: Scalar<C>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogWitness<C: Curve> {
    pub Q_blind_factor: BigInt,
    pub R_blind_factor: BigInt,
    pub d_log_proof: DLogProof<C>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogCommitment {
    // hash(Q, Q_blind_factor)
    pub Q_hash_commitment: BigInt,
    // hash( R, R_blind_factor)
    pub R_hash_commitment: BigInt,
}

impl<C: Curve> CurveKeyPair<C> {
    pub fn generate_keypair_and_d_log_proof() -> (CurveKeyPair<C>, DLogProof<C>) {
        let x = Scalar::<C>::random();

        let d_log_proof = DLogProof::prove(&x, None);

        let keypair = CurveKeyPair {
            public: d_log_proof.Q.clone(),
            secret: x,
        };

        (keypair, d_log_proof)
    }

    pub fn generate_keypair_and_blind_d_log_proof() -> (CurveKeyPair<C>, DLogCommitment, DLogWitness<C>) {
        let (keypair, d_log_proof) = CurveKeyPair::generate_keypair_and_d_log_proof();

        let Q_blind_factor = BigInt::sample(SECURITY_BITS);
        let Q_hash_commitment = HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.Q.to_bytes(false).as_ref()),
            &Q_blind_factor,
        );

        let R_blind_factor = BigInt::sample(SECURITY_BITS);
        let R_hash_commitment =
            HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(d_log_proof.R.to_bytes(false).as_ref()),
                &R_blind_factor,
            );

        let d_log_commitment = DLogCommitment {
            Q_hash_commitment,
            R_hash_commitment,
        };

        let d_log_witness = DLogWitness {
            Q_blind_factor,
            R_blind_factor,
            d_log_proof,
        };

        (keypair, d_log_commitment, d_log_witness)
    }
}

impl<C: Curve> DLogWitness<C> {
    pub fn verify(&self, Q_hash_commitment: &BigInt, R_hash_commitment: &BigInt, challenge: Option<&BigInt>) -> bool {
        let Q = &self.d_log_proof.Q;
        let R = &self.d_log_proof.R;
        // verify Q_hash_commitment
        let Q_test = HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(Q.to_bytes(false).as_ref()),
            &self.Q_blind_factor,
        );
        if Q_test != Q_hash_commitment.clone() {
            return false;
        }
        // verify R_hash_commitment
        let R_test = HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(R.to_bytes(false).as_ref()),
            &self.R_blind_factor,
        );
        if R_test != R_hash_commitment.clone() {
            return false;
        }
        // verify d_log_proof
        self.d_log_proof.verify(challenge)
    }
}

