use curv::arithmetic::{BitManipulation, Converter, Integer};
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use kzen_paillier::{Decrypt, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};
use crate::{generic};
use crate::generic::{DLogCommitment, DLogWitness, Secp256k1KeyPair};
use crate::generic::share::Party1Share;
use crate::sign::ECDSASignature;
use crate::sign::party2::{Party2SignMsg1, Party2SignMsg2};
use subtle::ConstantTimeEq;

pub type Party1SignMsg1 = DLogCommitment;


pub fn party1_step1() -> (Party1SignMsg1, DLogWitness, Secp256k1KeyPair) {
    let (d_log_witness, d_log_commitment, eph_keypair) = generic::generate_keypair_with_blind_dlog_proof();

    (
        d_log_commitment,
        d_log_witness,
        eph_keypair
    )
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Party1SignMsg2 {
    pub d_log_witness: DLogWitness,
    pub message_hash: BigInt,
}

pub fn party1_step2(party2_sign_msg1: Party2SignMsg1, d_log_witness: DLogWitness, message_hash: &BigInt) -> Result<(Party1SignMsg2, Point<Secp256k1>), TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 1,
        action: "sign".to_string(),
        step: 2,
        reason: "".to_string(),
    };


    let peer_d_log_proof = party2_sign_msg1.d_log_proof;
    let k2_G = &peer_d_log_proof.pk;
    if k2_G.is_zero() {
        error.reason = "k2_G is zero".to_string();
        return Err(error);
    }

    let result = DLogProof::verify(&peer_d_log_proof);
    if result.is_err() {
        error.reason = "fail to verify d_log_proof".to_string();
        return Err(error);
    }

    Ok((
        Party1SignMsg2 {
            d_log_witness,
            message_hash: message_hash.clone(),
        },
        k2_G.clone()
    ))
}


// compute signature with encrypted_partial_s
pub fn party1_step3(party2_sign_msg2: Party2SignMsg2, party1_share: &Party1Share, eph_keypair: Secp256k1KeyPair, message_hash: &BigInt, k2_G: Point<Secp256k1>) -> Result<ECDSASignature, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 1,
        action: "sign".to_string(),
        step: 3,
        reason: "".to_string(),
    };


    let q = Scalar::<Secp256k1>::group_order();
    let k1 = &eph_keypair.secret;
    let R = k1 * k2_G;
    let r = R.x_coord().unwrap().mod_floor(q);
    let k1_inv = k1.invert().unwrap();

    let partial_s = Paillier::decrypt(&party1_share.private.paillier_dk, RawCiphertext::from(party2_sign_msg2.encrypted_partial_s)).0.into_owned();
    let partial_s_fe = Scalar::<Secp256k1>::from(partial_s);
    let s_bn = (partial_s_fe * k1_inv).to_bigint();

    let s = core::cmp::min(
        s_bn.clone(),
        q - &s_bn,
    );

    // calc recovery id: v
    // https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/libsecp256k1/src/ecdsa_impl.h#L306
    // because we get r with mod_floor(q), so r will never overflow q
    let ry = R.y_coord().unwrap().mod_floor(q);
    let is_ry_odd = ry.test_bit(0);
    let mut rec_id = if is_ry_odd { 1 } else { 0 };
    if s_bn.clone() > q - s_bn {
        rec_id ^= 1;
    }

    let signature = ECDSASignature {
        r,
        s,
        v: rec_id,
    };


    let verify_flag = verify_signature(&signature, &party1_share.public.pub_key, message_hash);
    if !verify_flag {
        error.reason = "fail to verify signature".to_string();
        return Err(error);
    }

    Ok(signature)
}

// P=s{−1}∗h(m)∗G + s{−1}∗r∗Q
pub fn verify_signature(
    signature: &ECDSASignature,
    pub_key: &Point<Secp256k1>,
    message_hash: &BigInt,
) -> bool {
    let q = Scalar::<Secp256k1>::group_order();
    let G = Point::<Secp256k1>::generator();

    let r_fe = Scalar::<Secp256k1>::from(&signature.r);
    let s_fe = Scalar::<Secp256k1>::from(&signature.s);

    let s_inv_fe = s_fe.invert().unwrap();
    let msg_fe = Scalar::<Secp256k1>::from(message_hash.mod_floor(q));

    let u1 = &s_inv_fe * msg_fe * G;
    let u2 = &s_inv_fe * r_fe * pub_key;
    let P = u1 + u2;

    // check if r == P.x
    let r_bytes = &BigInt::to_bytes(&signature.r)[..];
    let px_bytes = &BigInt::to_bytes(&P.x_coord().unwrap())[..];

    r_bytes.ct_eq(px_bytes).unwrap_u8() == 1
        && signature.s < (q - &signature.s)
}