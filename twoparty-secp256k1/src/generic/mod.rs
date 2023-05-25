pub mod share;
pub mod challenge_dlog;

use curv::arithmetic::{Converter, Samplable};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use crate::ChosenHash;


const SECURITY_BITS: usize = 256;


pub struct Secp256k1KeyPair {
    pub public: Point<Secp256k1>,
    pub secret: Scalar<Secp256k1>,
}

pub fn generate_keypair_with_dlog_proof() -> (DLogProof<Secp256k1, ChosenHash>, Secp256k1KeyPair) {
    let secret_share = Scalar::<Secp256k1>::random();
    let base = Point::<Secp256k1>::generator();
    let public_share = base * &secret_share;
    let d_log_proof = DLogProof::prove(&secret_share);
    let keypair = Secp256k1KeyPair {
        public: public_share,
        secret: secret_share,
    };
    (
        d_log_proof,
        keypair,
    )
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DLogCommitment {
    // hash(public_share, pk_commitment_blind_factor)
    pub pk_commitment: BigInt,
    // hash( R, zk_pok_blind_factor)
    pub zk_pok_commitment: BigInt,
}

pub fn generate_keypair_with_blind_dlog_proof() -> (DLogWitness, DLogCommitment, Secp256k1KeyPair) {
    let (d_log_proof, keypair) = generate_keypair_with_dlog_proof();

    let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
    let pk_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.pk.to_bytes(true).as_ref()),
            &pk_commitment_blind_factor,
        );

    let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
    let zk_pok_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
            &zk_pok_blind_factor,
        );
    (
        DLogWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            d_log_proof,
        },
        DLogCommitment {
            pk_commitment,
            zk_pok_commitment,
        },
        keypair
    )
}