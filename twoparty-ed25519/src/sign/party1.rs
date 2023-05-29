use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Ed25519, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogCommitment, DLogWitness};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use crate::ChosenHash;
use crate::generic::share::Ed25519Share;
use crate::sign::{add_signature_parts, EdDSASignature, PartialSigningParams};
use crate::sign::party2::{Party2SignMsg1, Party2SignMsg2};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Party1SignMsg1 {
    pub eph_commitment: DLogCommitment,
    pub message_digest: Vec<u8>,
}

pub fn party1_step1(share: &Ed25519Share, message_digest: &Vec<u8>) -> (Party1SignMsg1, CurveKeyPair<Ed25519>, DLogWitness<Ed25519>) {
    // https://github.com/MystenLabs/ed25519-unsafe-libs
    // we external hash agg_Q to avoid double public key oracle attack
    let mut ri_hash = ChosenHash::new()
        .chain(share.prefix)
        .chain(message_digest)
        .chain_point(&share.agg_Q)
        .finalize();
    // reverse because Bigint uses big-endian
    ri_hash.reverse();
    let ri=Scalar::<Ed25519>::from_bigint(&BigInt::from_bytes(&ri_hash));

    let (eph_keypair, eph_commitment, eph_witness) = CurveKeyPair::generate_keypair_and_blind_d_log_proof_with_x(&ri);
    let party1_sign_msg1 = Party1SignMsg1 {
        eph_commitment,
        message_digest: message_digest.clone(),
    };
    (
        party1_sign_msg1,
        eph_keypair,
        eph_witness,
    )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Party1SignMsg2 {
    pub eph_witness: DLogWitness<Ed25519>,
    pub partial_sig: EdDSASignature,
}

pub fn party1_step2(msg1: Party2SignMsg1, eph_witness: DLogWitness<Ed25519>, message_digest: &Vec<u8>, eph_keypair: CurveKeyPair<Ed25519>, share: &Ed25519Share) -> Result<Party1SignMsg2, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "sign".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let peer_eph_proof = msg1.eph_proof;
    let flag = peer_eph_proof.verify(None);
    if !flag {
        error.reason = "fail to verify peer ephemeral d_log_proof".to_string();
        return Err(error);
    }

    // calc agg_R
    let R1 = eph_keypair.public;
    let R2 = peer_eph_proof.Q;
    let agg_R = R1 + R2;

    let sign_params = PartialSigningParams {
        agg_R,
        message_digest: message_digest.clone(),
        ri: eph_keypair.secret,
    };
    let partial_sig = sign_params.partial_sign(share);

    let party1_sign_msg2 = Party1SignMsg2 {
        eph_witness,
        partial_sig,
    };

    Ok(party1_sign_msg2)
}

pub fn party1_step3(msg2: Party2SignMsg2, partial_sig: &EdDSASignature, share: &Ed25519Share, message_digest: &Vec<u8>) -> Result<EdDSASignature, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 1,
        action: "sign".to_string(),
        step: 3,
        reason: "".to_string(),
    };
    let agg_result = add_signature_parts(&[partial_sig.clone(), msg2.partial_sig]);
    if agg_result.is_err() {
        error.reason = "agg_R not consistent".to_string();
        return Err(error);
    }
    let sig = agg_result.unwrap();
    // verify sig
    let flag = sig.verify(message_digest, share);
    if !flag {
        error.reason = "fail to verify sig".to_string();
        return Err(error);
    }
    Ok(sig)
}