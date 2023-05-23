use curv::arithmetic::{Converter, Samplable};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{EncryptionKey, EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use common::errors::TwoPartyError;
use crate::ChosenHash;
use crate::keygen::{Secp256k1KeyPair, SECURITY_BITS};
use crate::keygen::correct_encrypt_secret::{CorrectEncryptSecretProof, CorrectEncryptSecretStatement};
use crate::keygen::party2::Party2KeyGenMsg1;
use crate::keygen::share::{Party1Private, Party1Public, Party1Share};


#[derive(Serialize, Deserialize, Clone, Debug, )]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1KeyGenMsg1 {
    // hash(public_share, pk_commitment_blind_factor)
    pub pk_commitment: BigInt,
    // hash( R, zk_pok_blind_factor)
    pub zk_pok_commitment: BigInt,
}

/// party1_step1: generate public_share commitment
pub fn party1_step1() -> (Party1KeyGenMsg1, CommWitness, Secp256k1KeyPair) {
    let secret_share = Scalar::<Secp256k1>::random();

    let d_log_proof = DLogProof::<Secp256k1, ChosenHash>::prove(&secret_share);
    let public_share = d_log_proof.pk.clone();


    let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
    let pk_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
            &pk_commitment_blind_factor,
        );

    let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
    let zk_pok_commitment =
        HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
            &zk_pok_blind_factor,
        );

    let ec_key_pair = Secp256k1KeyPair {
        public: public_share,
        secret: secret_share,
    };
    (
        Party1KeyGenMsg1 {
            pk_commitment,
            zk_pok_commitment,
        },
        CommWitness {
            pk_commitment_blind_factor,
            zk_pok_blind_factor,
            d_log_proof,
        },
        ec_key_pair
    )
}

//========================================================= below is step2

#[derive(Serialize, Deserialize, Debug)]
pub struct Party1KeygenMsg2 {
    pub comm_witness: CommWitness,
    pub paillier_ek: EncryptionKey,
    pub encrypted_x1: BigInt,
    pub correct_paillier_key_proof: NiCorrectKeyProof,
    pub correct_encrypt_secret_proof: CorrectEncryptSecretProof,
}

/// init paillier keypair,  homomorphism encrypt x1 , proof paillier keypair generate correctly,
/// comm_witness was generate and stored by party1 at step1
pub fn party1_step2(party2_keygen_msg1: Party2KeyGenMsg1, comm_witness: CommWitness, secp256k1_keypair: Secp256k1KeyPair) -> Result<(Party1KeygenMsg2, Party1Share), TwoPartyError> {
    let mut error = TwoPartyError {
        party: 1,
        action: "keygen".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    // verify peer's public_share is not zero
    let party2_public_share = &party2_keygen_msg1.d_log_proof.pk;
    if party2_public_share.is_zero() {
        error.reason = "peer's public_share is zero".to_string();
        return Err(error);
    }
    // verify peer's d_log_proof
    let result = DLogProof::verify(&party2_keygen_msg1.d_log_proof);
    if result.is_err() {
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
        Q: comm_witness.d_log_proof.pk.clone(),
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
    let party1_public = Party1Public {
        public_share: secp256k1_keypair.public,
        paillier_ek: ek.clone(),
    };
    let party1_share = Party1Share {
        public: party1_public,
        private: party1_private,
    };

    let party1_keygen_msg2 = Party1KeygenMsg2 {
        comm_witness,
        paillier_ek: ek,
        encrypted_x1,
        correct_paillier_key_proof,
        correct_encrypt_secret_proof,
    };

    Ok((party1_keygen_msg2, party1_share))
}

