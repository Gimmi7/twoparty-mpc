


use crate::generic::share::Ed25519Share;
use crate::keygen;
use crate::sign::{self, EdDSASignature};


#[test]
fn integrated_test_ed25519() {
    // keygen
    let (share1, share2) = full_keygen();
    println!("{}", serde_json::to_string(&share1).unwrap());
    println!("{}", serde_json::to_string(&share2).unwrap());
    println!("keygen success ======================");

    // sign
    let message_digest = vec![1, 2, 3, 4];
    let sig = sign_message(&share1, &share2, &message_digest);
    println!("{:?}", sig);
    println!("sign success ======================");
}

pub fn full_keygen() -> (Ed25519Share, Ed25519Share) {
    // party1 step1
    let (party1_msg1, asset1) = keygen::party1::party1_step1();
    // party2 step1
    let (party2_msg1, assets2) = keygen::party2::party2_step1();

    // party1 step2
    let party1_result2 = keygen::party1::party1_step2(
        party2_msg1,
        asset1,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let (party1_msg2, pending_share1) = party1_result2.unwrap();
    // party2 step2
    let party2_result2 = keygen::party2::party2_step2(
        party1_msg2,
        party1_msg1,
        assets2,
    );
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let (party2_msg2, share2) = party2_result2.unwrap();

    // party1 step3
    let party1_result3 = keygen::party1::party1_step3(
        party2_msg2,
        pending_share1,
    );
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let share1 = party1_result3.unwrap();


    (share1, share2)
}

pub fn sign_message(share1: &Ed25519Share, share2: &Ed25519Share, message_digest: &Vec<u8>) -> EdDSASignature {
    // party1 step1
    let (party1_sign_msg1,
        eph_keypair1,
        eph_witness) = sign::party1::party1_step1(share1, message_digest);
    // party2 step1
    let (party2_sign_msg1,
        eph_keypair2) = sign::party2::party2_step1(party1_sign_msg1.clone(), share2);

    // party1 step2
    let party1_result2 = sign::party1::party1_step2(party2_sign_msg1, eph_witness, message_digest, eph_keypair1, share1);
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let party1_sign_msg2 = party1_result2.unwrap();

    // party2 step2
    let party2_result2 = sign::party2::party2_step2(party1_sign_msg2.clone(), party1_sign_msg1, eph_keypair2, share2);
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let party2_sign_msg2 = party2_result2.unwrap();

    // party1 step3
    let party1_partial_sig = &party1_sign_msg2.partial_sig;
    let party1_result3 = sign::party1::party1_step3(party2_sign_msg2, party1_partial_sig, share1, message_digest);
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }

    party1_result3.unwrap()
}



