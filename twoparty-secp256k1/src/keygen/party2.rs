use curv::arithmetic::{BitManipulation};


use curv::elliptic::curves::Secp256k1;
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{SALT_STRING};
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};

use crate::generic::share::{Party2Private, Party2Public, Party2Share};
use crate::keygen::correct_encrypt_secret::CorrectEncryptSecretStatement;
use crate::keygen::party1::{Party1KeyGenMsg1, Party1KeygenMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2KeyGenMsg1 {
    pub d_log_proof: DLogProof<Secp256k1>,
}

// party2_step1: generate public_share
pub fn party2_step1() -> (Party2KeyGenMsg1, CurveKeyPair<Secp256k1>) {
    let (keypair, d_log_proof) = CurveKeyPair::generate_keypair_and_d_log_proof();
    (
        Party2KeyGenMsg1 {
            d_log_proof,
        },
        keypair,
    )
}

// get paillier ek, get encrypted x1, verify prillier keypair generate correctly
// party1_keygen_msg1 was stored by party2 before party2_step1
pub fn party2_step2(party1_keygen_msg2: Party1KeygenMsg2, party1_keygen_msg1: Party1KeyGenMsg1, secp256k1_keypair: CurveKeyPair<Secp256k1>) -> Result<Party2Share, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 2,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let d_log_witness = party1_keygen_msg2.d_log_witness;
    // verify x1 d_log_proof_blind
    let flag = d_log_witness.verify(party1_keygen_msg1, None);
    if !flag {
        error.reason = "fail to verify x1 blind d_log_proof".to_string();
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
    let peer_public_share = &d_log_witness.d_log_proof.Q;
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