use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Ed25519, Scalar};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_EDDSA_ED25519, TwoPartyError};
use crate::ChosenHash;
use crate::generic::share::Ed25519Share;
use crate::sign::{EdDSASignature, PartialSigningParams};
use crate::sign::party1::{Party1SignMsg1, Party1SignMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2SignMsg1 {
    pub eph_proof: DLogProof<Ed25519>,
}

pub fn party2_step1(msg1: Party1SignMsg1, share: &Ed25519Share) -> (Party2SignMsg1, CurveKeyPair<Ed25519>) {
    // https://github.com/MystenLabs/ed25519-unsafe-libs
    // we external hash agg_Q to avoid double public key oracle attack
    let ri: Scalar<Ed25519> = ChosenHash::new()
        .chain(share.prefix)
        .chain_point(&share.agg_Q)
        .chain(msg1.message_digest)
        .result_scalar();
    let (eph_keypair, eph_proof) = CurveKeyPair::generate_keypair_and_d_log_proof_with_x(&ri);
    (
        Party2SignMsg1 {
            eph_proof
        },
        eph_keypair
    )
}

#[derive(Serialize,Deserialize,Debug,Clone)]
pub struct Party2SignMsg2 {
    pub partial_sig: EdDSASignature,
}

pub fn party2_step2(msg2: Party1SignMsg2, msg1: Party1SignMsg1, eph_keypair: CurveKeyPair<Ed25519>, share: &Ed25519Share) -> Result<Party2SignMsg2, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_EDDSA_ED25519.to_string(),
        party: 2,
        action: "sign".to_string(),
        step: 2,
        reason: "".to_string(),
    };
    // verify peer's eph d_log_proof_blind
    let peer_eph_witness = &msg2.eph_witness;
    let flag = peer_eph_witness.verify(msg1.eph_commitment, None);
    if !flag {
        error.reason = "fail to verify peer's eph d_log_proof_blind".to_string();
        return Err(error);
    }

    // calc agg_R
    let R1 = &peer_eph_witness.d_log_proof.Q;
    let R2 = eph_keypair.public;
    let agg_R = R1 + R2;
    if agg_R != msg2.partial_sig.R {
        error.reason = "agg_R not consistent".to_string();
        return Err(error);
    }

    let sign_params = PartialSigningParams {
        agg_R,
        message_digest: msg1.message_digest,
        ri: eph_keypair.secret,
    };
    let partial_sig = sign_params.partial_sign(share);

    Ok(
        Party2SignMsg2 {
            partial_sig,
        }
    )
}
