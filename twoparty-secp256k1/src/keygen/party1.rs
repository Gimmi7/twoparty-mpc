use curv::BigInt;
use kzen_paillier::{EncryptionKey, EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;

use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};
use crate::generic::{self, DLogCommitment, DLogWitness, Secp256k1KeyPair};
use crate::generic::share::{Party1Private, Party1Public, Party1Share};
use crate::keygen::correct_encrypt_secret::{CorrectEncryptSecretProof, CorrectEncryptSecretStatement};
use crate::keygen::party2::Party2KeyGenMsg1;


pub type Party1KeyGenMsg1 = DLogCommitment;


/// party1_step1: generate public_share commitment
pub fn party1_step1() -> (Party1KeyGenMsg1, DLogWitness, Secp256k1KeyPair) {
    let (d_log_witness, d_log_commitment, keypair) = generic::generate_keypair_with_blind_dlog_proof();
    (
        d_log_commitment,
        d_log_witness,
        keypair
    )
}

//========================================================= below is step2

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1KeygenMsg2 {
    pub d_log_witness: DLogWitness,
    pub paillier_ek: EncryptionKey,
    pub encrypted_x1: BigInt,
    pub correct_paillier_key_proof: NiCorrectKeyProof,
    pub correct_encrypt_secret_proof: CorrectEncryptSecretProof,
}

/// init paillier keypair,  homomorphism encrypt x1 , proof paillier keypair generate correctly,
/// comm_witness was generate and stored by party1 at step1
pub fn party1_step2(party2_keygen_msg1: Party2KeyGenMsg1, d_log_witness: DLogWitness, secp256k1_keypair: Secp256k1KeyPair) -> Result<(Party1KeygenMsg2, Party1Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 1,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    // verify peer's public_share is not zero
    let peer_public_share = &party2_keygen_msg1.d_log_proof.Q;
    // verify peer's d_log_proof
    let flag =&party2_keygen_msg1.d_log_proof.verify(None);
    if !flag {
        error.reason = "fail to verify d_log_proof".to_string();
        return Err(error);
    }

    // party1 init paillier keypair
    let (ek, dk) = Paillier::keypair().keys();
    // party1 encrypt x1
    let randomness = Randomness::sample(&ek);
    let encrypted_x1 = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(secp256k1_keypair.secret.to_bigint()),
        &randomness,
    ).0.into_owned();
    let r_encrypting_x1 = randomness.0;
    // zkp of correct paillier key: None will use default salt
    let correct_paillier_key_proof = NiCorrectKeyProof::proof(&dk, None);
    // zkp of correct_encrypt_secret
    let statement = CorrectEncryptSecretStatement {
        paillier_ek: ek.clone(),
        c: encrypted_x1.clone(),
        Q: d_log_witness.d_log_proof.Q.clone(),
    };
    let correct_encrypt_secret_proof = CorrectEncryptSecretProof::prove(
        &secp256k1_keypair.secret.to_bigint(),
        &r_encrypting_x1,
        statement,
    );

    // construct party1 share
    let party1_private = Party1Private {
        x1: secp256k1_keypair.secret,
        r_encrypting_x1,
        paillier_dk: dk,
    };
    let pub_key = &party1_private.x1 * peer_public_share;
    let party1_public = Party1Public {
        paillier_ek: ek.clone(),
        pub_key,
    };
    let party1_share = Party1Share {
        public: party1_public,
        private: party1_private,
    };

    let party1_keygen_msg2 = Party1KeygenMsg2 {
        d_log_witness,
        paillier_ek: ek,
        encrypted_x1,
        correct_paillier_key_proof,
        correct_encrypt_secret_proof,
    };

    Ok((party1_keygen_msg2, party1_share))
}

