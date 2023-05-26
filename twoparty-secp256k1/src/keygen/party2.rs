use curv::arithmetic::{BitManipulation};



use curv::elliptic::curves::Secp256k1;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{SALT_STRING};
use common::DLogProof;
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};
use crate::ChosenHash;
use crate::generic::{self, calc_point_hash_commitment, Secp256k1KeyPair};
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
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 2,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let d_log_witness = party1_keygen_msg2.d_log_witness;
    let peer_public_share = &d_log_witness.d_log_proof.Q;
    // verify party1's Q_hash_commitment= hash(public_share, blind)
    let Q_hash_commitment = &party1_keygen_msg1.Q_hash_commitment;
    let Q_blind_factor = &d_log_witness.Q_blind_factor;
    if Q_hash_commitment != &calc_point_hash_commitment(peer_public_share, Q_blind_factor) {
        error.reason = "fail to verify pk_commitment".to_string();
        return Err(error);
    }
    // verify party1's R_hash_commitment = ( R, blind)
    let R_hash_commitment = &party1_keygen_msg1.R_hash_commitment;
    let point_r = &d_log_witness.d_log_proof.R;
    let R_blind_factor = &d_log_witness.R_blind_factor;
    if R_hash_commitment != &calc_point_hash_commitment(point_r, R_blind_factor) {
        error.reason = "fail to verify zk_pok_commitment".to_string();
        return Err(error);
    }
    // verify peer's d_log_proof
    let flag = &d_log_witness.d_log_proof.verify(None);
    if !flag {
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
        error.reason = result.err().unwrap();
        return Err(error);
    }

    // construct party2 share
    let party2_private = Party2Private {
        x2: secp256k1_keypair.secret,
    };
    let pub_key = &party2_private.x2 * peer_public_share;
    let party2_public = Party2Public {
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