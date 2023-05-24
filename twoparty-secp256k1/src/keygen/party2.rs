use curv::arithmetic::{BitManipulation, Converter};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::Secp256k1;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{SALT_STRING};
use common::errors::TwoPartyError;
use crate::ChosenHash;
use crate::generic::{self, Secp256k1KeyPair};
use crate::generic::share::{Party2Private, Party2Public, Party2Share};
use crate::keygen::correct_encrypt_secret::CorrectEncryptSecretStatement;
use crate::keygen::party1::{Party1KeyGenMsg1, Party1KeygenMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2KeyGenMsg1 {
    pub d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}

// party2_step1: generate public_share
pub fn party2_step1() -> (Party2KeyGenMsg1, Secp256k1KeyPair) {
    let (d_log_proof, keypair) = generic::generate_keypair_with_dlog_proof();
    (
        Party2KeyGenMsg1 {
            d_log_proof,
        },
        keypair,
    )
}

// get paillier ek, get encrypted x1, verify prillier keypair generate correctly
// party1_keygen_msg1 was stored by party2 before party2_step1
pub fn party2_step2(party1_keygen_msg2: Party1KeygenMsg2, party1_keygen_msg1: Party1KeyGenMsg1, secp256k1_keypair: Secp256k1KeyPair) -> Result<Party2Share, TwoPartyError> {
    let mut error = TwoPartyError {
        party: 2,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let d_log_witness = party1_keygen_msg2.d_log_witness;
    // verify peer's public_share is not zero
    let peer_public_share = &d_log_witness.d_log_proof.pk;
    if peer_public_share.is_zero() {
        error.reason = "peer's public_share is zero".to_string();
        return Err(error);
    }
    // verify party1's pk_commitment= hash(public_share, blind)
    let pk_commitment = &party1_keygen_msg1.pk_commitment;
    let pk_commitment_blind_factor = &d_log_witness.pk_commitment_blind_factor;
    if pk_commitment != &HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(peer_public_share.to_bytes(true).as_ref()),
        pk_commitment_blind_factor,
    ) {
        error.reason = "fail to verify pk_commitment".to_string();
        return Err(error);
    }
    // verify party1's zk_pok_commitment = ( R, zk_pok_blind_factor)
    let zk_pok_commitment = &party1_keygen_msg1.zk_pok_commitment;
    let point_r = &d_log_witness.d_log_proof.pk_t_rand_commitment;
    let zk_pok_commitment_blind_factor = &d_log_witness.zk_pok_blind_factor;
    if zk_pok_commitment != &HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(point_r.to_bytes(true).as_ref()),
        zk_pok_commitment_blind_factor,
    ) {
        error.reason = "fail to verify zk_pok_commitment".to_string();
        return Err(error);
    }
    // verify peer's d_log_proof
    let result = DLogProof::verify(&d_log_witness.d_log_proof);
    if result.is_err() {
        error.reason = "fail to verify d_log_proof".to_string();
        return Err(error);
    }

    // verify paillier keypair generate correctly
    let paillier_ek = party1_keygen_msg2.paillier_ek;
    if paillier_ek.n.bit_length() < 2048 - 1 {
        // if bit_length < 2047, p,q is not big prime
        error.reason = "the bit length of paillier n less than 2047".to_string();
        return Err(error);
    }
    let result = party1_keygen_msg2.correct_paillier_key_proof.verify(&paillier_ek, SALT_STRING);
    if result.is_err() {
        error.reason = "fail to verify paillier correct key proof".to_string();
        return Err(error);
    }

    // verify correctly encrypted x1
    let encrypted_x1 = party1_keygen_msg2.encrypted_x1;
    let statement = CorrectEncryptSecretStatement {
        paillier_ek: paillier_ek.clone(),
        c: encrypted_x1.clone(),
        Q: peer_public_share.clone(),
    };
    let result = party1_keygen_msg2.correct_encrypt_secret_proof.verify(&statement);
    if result.is_err() {
        error.reason = "fail to verify correct_encrypt_x1 proof".to_string();
        return Err(error);
    }

    // construct party2 share
    let party2_private = Party2Private {
        x2: secp256k1_keypair.secret,
    };
    let pub_key = &party2_private.x2 * peer_public_share;
    let party2_public = Party2Public {
        public_share: secp256k1_keypair.public,
        encrypted_x1,
        paillier_ek,
        pub_key,
    };
    let party2_share = Party2Share {
        public: party2_public,
        private: party2_private,
    };

    Ok(party2_share)
}