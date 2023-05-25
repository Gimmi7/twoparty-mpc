use curv::BigInt;
use crate::generic::share::{Party1Share, Party2Share};
use crate::keygen;
use crate::sign::{self, ECDSASignature};

pub fn full_keygen() -> (Party1Share, Party2Share) {
    // party1 step1
    let (party1_keygen_msg1, witness, party1_keypair) = keygen::party1::party1_step1();
    // party2 step1
    let (party2_keygen_msg1, party2_keypair) = keygen::party2::party2_step1();

    // party1 step2
    let result1 = keygen::party1::party1_step2(
        party2_keygen_msg1,
        witness,
        party1_keypair,
    );
    if result1.is_err() {
        println!("{}", result1.err().unwrap());
        panic!("");
    }
    let result1_tuple = result1.unwrap();
    let party1_share = result1_tuple.1;

    // party2 step2
    let result2 = keygen::party2::party2_step2(
        result1_tuple.0,
        party1_keygen_msg1,
        party2_keypair,
    );
    if result2.is_err() {
        println!("{}", result2.err().unwrap());
        panic!("");
    }
    let party2_share = result2.unwrap();

    (party1_share, party2_share)
}

pub fn sign_message(share1: &Party1Share, share2: &Party2Share, message_hash: &BigInt) -> ECDSASignature {
    // party1 step1
    let (
        party1_sign_msg1,
        d_log_witness,
        party1_eph_keypair
    ) = sign::party1::party1_step1();

    // party2 step1
    let (party2_sign_msg1, party2_eph_keypair) = sign::party2::party2_step1();


    // party1 step2
    let party1_result2 = sign::party1::party1_step2(
        party2_sign_msg1,
        d_log_witness,
        message_hash,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let (party1_sign_msg2, k2_G) = party1_result2.unwrap();


    //party2 step2
    let party2_result2 = sign::party2::party2_step2(party1_sign_msg2, party1_sign_msg1, share2, party2_eph_keypair);
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let party2_sign_msg2 = party2_result2.unwrap();


    // party1 step3
    let party1_result3 = sign::party1::party1_step3(
        party2_sign_msg2,
        share1,
        party1_eph_keypair,
        message_hash,
        k2_G,
    );
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let sig = party1_result3.unwrap();

    sig
}