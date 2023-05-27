use curv::arithmetic::{BitManipulation, Integer};


use curv::elliptic::curves::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::SALT_STRING;
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};

use crate::generic::share::{Party2Private, Party2Public, Party2Share};
use crate::keygen::correct_encrypt_secret::CorrectEncryptSecretStatement;
use crate::rotate::party1::{Party1RotateMsg1, Party1RotateMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2RotateMsg1 {
    pub d_log_proof: DLogProof<Secp256k1>,
}

pub fn party2_step1() -> (Party2RotateMsg1, CurveKeyPair<Secp256k1>) {
    let (seed_keypair, d_log_proof) = CurveKeyPair::generate_keypair_and_d_log_proof();
    (
        Party2RotateMsg1 {
            d_log_proof,
        },
        seed_keypair
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2RotateMsg2 {
    pub new_x2_proof: DLogProof<Secp256k1>,
}

pub fn party2_step2(
    party1_rotate_msg2: Party1RotateMsg2,
    party1_rotate_msg1: Party1RotateMsg1,
    seed_keypair: CurveKeyPair<Secp256k1>,
    old_share: &Party2Share) -> Result<(Party2RotateMsg2, Party2Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 2,
        action: "rotate".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    // verify party1's seed d_log_proof_blind
    let seed_d_log_witness = party1_rotate_msg2.seed_d_log_witness;
    let Q_hash_commitment = &party1_rotate_msg1.Q_hash_commitment;
    let R_hash_commitment = &party1_rotate_msg1.R_hash_commitment;
    let flag = seed_d_log_witness.verify(Q_hash_commitment, R_hash_commitment, None);
    if !flag {
        error.reason = "fail to verify party1's seed d_log_proof_blind".to_string();
        return Err(error);
    }


    // verify paillier keypair generate correctly
    let paillier_ek = &party1_rotate_msg2.paillier_ek;
    if paillier_ek.n.bit_length() < 2048 - 1 {
        // if bit_length < 2047, p,q is not big prime
        error.reason = "the bit length of paillier n less than 2047".to_string();
        return Err(error);
    }
    let result = party1_rotate_msg2.correct_paillier_key_proof.verify(paillier_ek, SALT_STRING);
    if result.is_err() {
        error.reason = "fail to verify paillier correct key proof".to_string();
        return Err(error);
    }

    // verify d_log_proof of new x1
    let new_x1_proof = &party1_rotate_msg2.new_x1_proof;
    let flag = new_x1_proof.verify(None);
    if !flag {
        error.reason = "fail to verify d_log_proof for new x1".to_string();
        return Err(error);
    }

    // verify correctly encrypted x1
    let encrypted_x1 = party1_rotate_msg2.encrypted_x1;
    let statement = CorrectEncryptSecretStatement {
        paillier_ek: paillier_ek.clone(),
        c: encrypted_x1.clone(),
        Q: new_x1_proof.Q.clone(),
    };
    let result = party1_rotate_msg2.correct_encrypt_secret_proof.verify(&statement);
    if result.is_err() {
        error.reason = result.err().unwrap();
        return Err(error);
    }

    // calc x2_new
    let seed_d_log_proof = &seed_d_log_witness.d_log_proof;
    let peer_seed = &seed_d_log_proof.Q;
    let q = Scalar::<Secp256k1>::group_order();
    let factor = (seed_keypair.secret * peer_seed).x_coord().unwrap().mod_floor(q);
    let factor_fe = Scalar::<Secp256k1>::from(factor);
    let factor_inv = factor_fe.invert().unwrap();
    let x2_new = &old_share.private.x2 * factor_inv;

    // check if the new pub_key is the same as old
    let pub_new = &x2_new * &new_x1_proof.Q;
    if pub_new != old_share.public.pub_key {
        error.reason = "new public key is not the same as old".to_string();
        return Err(error);
    }

    // d_log_proof for new x2
    let new_x2_proof = DLogProof::prove(&x2_new, None);


    // construct party2 share
    let party2_private = Party2Private {
        x2: x2_new,
    };
    let party2_public = Party2Public {
        encrypted_x1,
        paillier_ek: paillier_ek.clone(),
        pub_key: pub_new,
    };
    let new_share = Party2Share { public: party2_public, private: party2_private };

    Ok((
        Party2RotateMsg2 {
            new_x2_proof
        },
        new_share
    ))
}