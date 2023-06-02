mod sui_verify;

use curv::elliptic::curves::{Ed25519, Point, Scalar};
use crate::generic::share::Ed25519Share;
use crate::keygen;
use crate::rotate;
use crate::sign::{self, EdDSASignature};


#[test]
fn integrated_test_ed25519() {
    // Keygen
    let (share1, share2) = full_keygen();
    println!("Keygen success ======================");

    // sign
    let message_digest = vec![1, 2, 3, 4];
    let sig = sign_message(&share1, &share2, &message_digest);
    println!("sign success ======================");

    // rotate
    let (share11, share22) = rotate_share(&share1, &share2);
    // sign after rotate
    let sig_after_rotate = sign_message(&share11, &share22, &message_digest);
    if sig_after_rotate.to_sig_bytes() != sig.to_sig_bytes(){
        panic!("after rotate, sign same digest produce another sig")
    }else {
        println!("rotate success ======================");
    }
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

pub fn rotate_share(share1: &Ed25519Share, share2: &Ed25519Share) -> (Ed25519Share, Ed25519Share) {
    // party1 step1
    let (party1_rotate_msg1,
        delta_keypair1,
        delta_witness) = rotate::party1::party1_step1();
    // party2 step1
    let (party2_rotate_msg1,
        delta_keypair2) = rotate::party2::party2_step1();

    // party1 step2
    let party1_result2 = rotate::party1::party1_step2(
        party2_rotate_msg1,
        delta_witness,
        delta_keypair1,
        share1,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let (party1_rotate_msg2, new_x1) = party1_result2.unwrap();

    // party2 step2
    let party2_result2 = rotate::party2::party2_step2(
        party1_rotate_msg2,
        party1_rotate_msg1,
        delta_keypair2,
        share2,
    );
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let (party2_rotate_msg2, new_share2) = party2_result2.unwrap();


    // party1 step3
    let party1_result3 = rotate::party1::party1_step3(
        party2_rotate_msg2,
        new_x1,
        share1,
    );
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let new_share1 = party1_result3.unwrap();

    (new_share1, new_share2)
}


#[test]
fn test_normal_agg() {
    let x1 = Scalar::<Ed25519>::random();
    let x2 = Scalar::<Ed25519>::random();
    let x12 = &x1 + &x2;

    let G = Point::<Ed25519>::generator();
    let Q1 = &x1 * G;
    let Q2 = &x2 * G;
    let Q12 = x12 * G;
    let agg_Q = &Q1 + &Q2;

    println!("{:?}", Q12.x_coord().unwrap());
    println!("{:?}", agg_Q.x_coord().unwrap());
}