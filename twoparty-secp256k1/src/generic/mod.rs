pub mod share;

use curv::arithmetic::{Converter, Samplable};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use common::DLogProof;
use crate::ChosenHash;


const SECURITY_BITS: usize = 256;


pub struct Secp256k1KeyPair {
    pub public: Point<Secp256k1>,
    pub secret: Scalar<Secp256k1>,
}

pub fn generate_keypair_with_dlog_proof() -> (DLogProof<Secp256k1, ChosenHash>, Secp256k1KeyPair) {
    let x = Scalar::<Secp256k1>::random();
    let G = Point::<Secp256k1>::generator();
    let Q = G * &x;
    let d_log_proof = DLogProof::prove(&x, None);
    let keypair = Secp256k1KeyPair {
        public: Q,
        secret: x,
    };
    (
        d_log_proof,
        keypair,
    )
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogWitness {
    pub Q_blind_factor: BigInt,
    pub R_blind_factor: BigInt,
    pub d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogCommitment {
    // hash(Q, Q_blind_factor)
    pub Q_hash_commitment: BigInt,
    // hash( R, R_blind_factor)
    pub R_hash_commitment: BigInt,
}

pub fn generate_keypair_with_blind_dlog_proof() -> (DLogWitness, DLogCommitment, Secp256k1KeyPair) {
    let (d_log_proof, keypair) = generate_keypair_with_dlog_proof();

    let Q_blind_factor = BigInt::sample(SECURITY_BITS);
    let Q_hash_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.Q.to_bytes(false).as_ref()),
            &Q_blind_factor,
        );

    let R_blind_factor = BigInt::sample(SECURITY_BITS);
    let R_hash_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.R.to_bytes(false).as_ref()),
            &R_blind_factor,
        );
    (
        DLogWitness {
            Q_blind_factor,
            R_blind_factor,
            d_log_proof,
        },
        DLogCommitment {
            Q_hash_commitment,
            R_hash_commitment,
        },
        keypair
    )
}

pub fn calc_point_hash_commitment(point: &Point<Secp256k1>, blind: &BigInt) -> BigInt {
    let hash_commitment = HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(point.to_bytes(false).as_ref()),
        blind,
    );
    hash_commitment
}