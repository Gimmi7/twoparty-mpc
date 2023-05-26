use curv::arithmetic::Integer;
use curv::BigInt;
use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{EncryptionKey, EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use common::DLogProof;
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};
use crate::{ChosenHash, generic};
use crate::generic::{DLogCommitment, DLogWitness, Secp256k1KeyPair};
use crate::generic::share::{Party1Private, Party1Public, Party1Share};
use crate::keygen::correct_encrypt_secret::{CorrectEncryptSecretProof, CorrectEncryptSecretStatement};
use crate::rotate::party2::Party2RotateMsg1;

pub type Party1RotateMsg1 = DLogCommitment;

pub fn party1_step1() -> (Party1RotateMsg1, DLogWitness, Secp256k1KeyPair) {
    let (d_log_witness, d_log_commitment, seed_keypair) = generic::generate_keypair_with_blind_dlog_proof();
    (
        d_log_commitment,
        d_log_witness,
        seed_keypair
    )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1RotateMsg2 {
    pub seed_d_log_witness: DLogWitness,
    pub paillier_ek: EncryptionKey,
    pub encrypted_x1: BigInt,
    pub correct_paillier_key_proof: NiCorrectKeyProof,
    pub correct_encrypt_secret_proof: CorrectEncryptSecretProof,
    pub new_x1_proof: DLogProof<Secp256k1, ChosenHash>,
}

pub fn party1_step2(party2_rotate_msg1: Party2RotateMsg1, seed_d_log_witness: DLogWitness, seed_keypair: Secp256k1KeyPair, old_share: &Party1Share) -> Result<(Party1RotateMsg2, Party1Share), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 1,
        action: "rotate".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let peer_seed_d_log_proof = party2_rotate_msg1.d_log_proof;
    // verify peer's seed is not zero
    let peer_seed = &peer_seed_d_log_proof.Q;
    // verify peer's seed_d_log_proof
    let flag = &peer_seed_d_log_proof.verify(None);
    if !flag {
        error.reason = "fail to verify seed_d_log_proof".to_string();
        return Err(error);
    }

    let q = Scalar::<Secp256k1>::group_order();
    let factor = (seed_keypair.secret * peer_seed).x_coord().unwrap().mod_floor(q);
    let factor_fe = Scalar::<Secp256k1>::from(factor);
    let x1_new = &old_share.private.x1 * factor_fe;

    // d_log_proof for new x1
    let new_x1_proof = DLogProof::prove(&x1_new, None);
    let x1_G = &new_x1_proof.Q;

    // party1 init new paillier keypair
    let (ek, dk) = Paillier::keypair().keys();
    // party1 encrypt x1_new
    let randomness = Randomness::sample(&ek);
    let encrypted_x1_new = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x1_new.to_bigint()),
        &randomness,
    ).0.into_owned();
    let r_encrypting_x1_new = randomness.0;
    // zkp of correct paillier key
    let correct_paillier_key_proof = NiCorrectKeyProof::proof(&dk, None);
    // zkp of correct encrypt_secret
    let statement = CorrectEncryptSecretStatement {
        paillier_ek: ek.clone(),
        c: encrypted_x1_new.clone(),
        Q: x1_G.clone(),
    };
    let correct_encrypt_secret_proof = CorrectEncryptSecretProof::prove(
        &x1_new.to_bigint(),
        &r_encrypting_x1_new,
        statement,
    );


    // construct party1 new share
    let party1_private = Party1Private {
        x1: x1_new,
        r_encrypting_x1: r_encrypting_x1_new,
        paillier_dk: dk,
    };
    let party1_public = Party1Public {
        paillier_ek: ek.clone(),
        pub_key: old_share.public.pub_key.clone(),
    };
    let new_share = Party1Share {
        public: party1_public,
        private: party1_private,
    };

    let party1_rotate_msg2 = Party1RotateMsg2 {
        seed_d_log_witness,
        paillier_ek: ek,
        encrypted_x1: encrypted_x1_new,
        correct_paillier_key_proof,
        correct_encrypt_secret_proof,
        new_x1_proof,
    };

    Ok((party1_rotate_msg2, new_share))
}