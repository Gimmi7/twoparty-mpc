use curv::arithmetic::{BasicOps, Converter, Integer, Modulo, Samplable};
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Scalar, Secp256k1};
use kzen_paillier::{Add, Encrypt, Mul, Paillier, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use common::errors::TwoPartyError;
use crate::{ChosenHash, generic};
use crate::generic::Secp256k1KeyPair;
use crate::generic::share::Party2Share;
use crate::sign::party1::{Party1SignMsg1, Party1SignMsg2};

#[derive(Serialize, Deserialize, Debug)]
pub struct Party2SignMsg1 {
    pub d_log_proof: DLogProof<Secp256k1, ChosenHash>,
}


pub fn party2_step1() -> (Party2SignMsg1, Secp256k1KeyPair) {
    let (d_log_proof, eph_keypair) = generic::generate_keypair_with_dlog_proof();
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


pub fn party2_step2(party1_sign_msg2: Party1SignMsg2, party1_sign_msg1: Party1SignMsg1, party2_share: &Party2Share, eph_keypair: Secp256k1KeyPair) -> Result<Party2SignMsg2, TwoPartyError> {
    let mut error = TwoPartyError {
        party: 2,
        action: "sign".to_string(),
        step: 2,
        reason: "".to_string(),
    };

    let d_log_witness = party1_sign_msg2.d_log_witness;
    let peer_d_log_proof = &d_log_witness.d_log_proof;
    // verify k1 is not zero
    let k1_G = &peer_d_log_proof.pk;
    if k1_G.is_zero() {
        error.reason = "k1 is zero".to_string();
        return Err(error);
    }
    // verify party1's pk_commitment= hash(k1_G, blind)
    let pk_commitment = &party1_sign_msg1.pk_commitment;
    let pk_commitment_blind_factor = &d_log_witness.pk_commitment_blind_factor;
    if pk_commitment != &HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(k1_G.to_bytes(true).as_ref()),
        pk_commitment_blind_factor,
    ) {
        error.reason = "fail to verify pk_commitment".to_string();
        return Err(error);
    }
    // verify party1's zk_pok_commitment = ( R, zk_pok_blind_factor)
    let zk_pok_commitment = &party1_sign_msg1.zk_pok_commitment;
    let point_r = &d_log_witness.d_log_proof.pk_t_rand_commitment;
    let zk_pok_commitment_blind_factor = &d_log_witness.zk_pok_blind_factor;
    if zk_pok_commitment != &HashCommitment::<ChosenHash>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(point_r.to_bytes(true).as_ref()),
        zk_pok_commitment_blind_factor,
    ) {
        error.reason = "fail to verify zk_pok_commitment".to_string();
        return Err(error);
    }
    // verify peer's d_log_proof
    let result = DLogProof::verify(peer_d_log_proof);
    if result.is_err() {
        error.reason = "fail to verify d_log_proof".to_string();
        return Err(error);
    }

    // calc the encrypted version of:  k2^{-1}⋅H(m) + k2^{-1}⋅r⋅x1⋅x2 + rho.q
    let msg_hash = party1_sign_msg2.message_hash;
    let q = Scalar::<Secp256k1>::group_order();
    let k2 = &eph_keypair.secret;
    let R = k2 * k1_G;
    let r = R.x_coord().unwrap().mod_floor(q);
    let k2_inv = BigInt::mod_inv(&k2.to_bigint(), q).unwrap();
    let rho = BigInt::sample_below(&q.pow(2));

    let partial_sig = rho * q.clone() + BigInt::mod_mul(&k2_inv, &msg_hash, q);
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