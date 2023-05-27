use curv::arithmetic::{BasicOps, Converter, Integer, Modulo, Samplable};
use curv::BigInt;


use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{Add, Encrypt, Mul, Paillier, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use common::dlog::{CurveKeyPair, DLogProof};
use common::errors::{SCOPE_ECDSA_SECP256K1, TwoPartyError};

use crate::generic::share::Party2Share;
use crate::sign::party1::{Party1SignMsg1, Party1SignMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2SignMsg1 {
    pub d_log_proof: DLogProof<Secp256k1>,
}


pub fn party2_step1() -> (Party2SignMsg1, CurveKeyPair<Secp256k1>) {
    let (eph_keypair, d_log_proof) = CurveKeyPair::generate_keypair_and_d_log_proof();
    (
        Party2SignMsg1 {
            d_log_proof,
        },
        eph_keypair,
    )
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Party2SignMsg2 {
    pub encrypted_partial_s: BigInt,
}


pub fn party2_step2(party1_sign_msg2: Party1SignMsg2, party1_sign_msg1: Party1SignMsg1, party2_share: &Party2Share, eph_keypair: CurveKeyPair<Secp256k1>) -> Result<Party2SignMsg2, TwoPartyError> {
    let mut error = TwoPartyError {
        scope: SCOPE_ECDSA_SECP256K1.to_string(),
        party: 2,
        action: "sign".to_string(),
        step: 2,
        reason: "".to_string(),
    };


    // verify ephemeral d_log_proof & ephemeral same with prev commitment

    let d_log_witness = party1_sign_msg2.d_log_witness;
    // verify ephemeral d_log_proof_blind
    let Q_hash_commitment = &party1_sign_msg1.Q_hash_commitment;
    let R_hash_commitment = &party1_sign_msg1.R_hash_commitment;
    let flag = d_log_witness.verify(Q_hash_commitment, R_hash_commitment, None);
    if !flag {
        error.reason = "fail to very ephemeral d_log_proof_blind".to_string();
        return Err(error);
    }


    // verify party1 has the knowledge of x1, this can make sign operation based on the intractability of d_log problem
    let peer_d_log_proof = &d_log_witness.d_log_proof;
    let k1_G = &peer_d_log_proof.Q;
    let k2 = &eph_keypair.secret;
    let R = k2 * k1_G;
    let x1_d_log_proof = party1_sign_msg2.x1_d_log_proof;
    let flag = x1_d_log_proof.verify(Some(&BigInt::from_bytes(R.to_bytes(false).as_ref())));
    if !flag {
        error.reason = "fail to verify x1_d_log_proof with challenge= k1*k1*G".to_string();
        return Err(error);
    }

    // calc the encrypted version of:  k2^{-1}⋅H(m) + k2^{-1}⋅r⋅x1⋅x2 + rho.q
    let message_digest = party1_sign_msg2.message_digest;
    let q = Scalar::<Secp256k1>::group_order();
    let r = R.x_coord().unwrap().mod_floor(q);
    let k2_inv = BigInt::mod_inv(&k2.to_bigint(), q).unwrap();
    let rho = BigInt::sample_below(&q.pow(2));

    let partial_sig = rho * q.clone() + BigInt::mod_mul(&k2_inv, &message_digest, q);
    let c1 = Paillier::encrypt(&party2_share.public.paillier_ek, RawPlaintext::from(partial_sig));

    let k2_inv_r_x2 = BigInt::mod_mul(
        &k2_inv,
        &BigInt::mod_mul(&r, &party2_share.private.x2.to_bigint(), q),
        q,
    );
    let c2 = Paillier::mul(
        &party2_share.public.paillier_ek,
        RawCiphertext::from(&party2_share.public.encrypted_x1),
        RawPlaintext::from(k2_inv_r_x2),
    );

    let c3 = Paillier::add(&party2_share.public.paillier_ek, c1, c2).0.into_owned();


    Ok(
        Party2SignMsg2 {
            encrypted_partial_s: c3,
        }
    )
}