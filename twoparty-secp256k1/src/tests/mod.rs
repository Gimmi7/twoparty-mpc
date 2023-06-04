use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use crate::generic::share::{Party1Share, Party2Share};
use crate::keygen;
use crate::sign::{self, ECDSASignature};
use crate::rotate;
use crate::export;

#[test]
fn integrated_test() {
    // Keygen
    let (share1, share2) = full_keygen();
    println!("Keygen success!");
    // get private key
    let x = export_private(&share1, &share2);
    println!("x={}", x);

    // sign
    let message_digest = vec![1, 2, 3, 4];
    let sig = sign_message(&share1, &share2, &message_digest);
    println!("sign success! v={}", sig.v);

    // rotate
    let (share11, share22) = rotate_share(share1, share2);
    println!("rotate success!");
    // get private key
    let x_rotate = export_private(&share11, &share22);
    println!("x_rotate={}", x_rotate);

    println!("integrated_test success ++++++++++++")
}

pub fn full_keygen() -> (Party1Share, Party2Share) {
    // party1 step1
    let (party1_keygen_msg1, witness, party1_keypair) = keygen::party1::party1_step1();
    // party2 step1
    let (party2_keygen_msg1, party2_keypair) = keygen::party2::party2_step1();

    // party1 step2
    let party1_result2 = keygen::party1::party1_step2(
        party2_keygen_msg1,
        witness,
        party1_keypair,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("");
    }
    let (party1_keygen_msg2, party1_share)=party1_result2.unwrap();

    // party2 step2
    let party2_result2 = keygen::party2::party2_step2(
        party1_keygen_msg2,
        party1_keygen_msg1,
        party2_keypair,
    );
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("");
    }
    let party2_share = party2_result2.unwrap();

    (party1_share, party2_share)
}

pub fn sign_message(share1: &Party1Share, share2: &Party2Share, message_digest: &[u8]) -> ECDSASignature {
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
        message_digest,
        &party1_eph_keypair,
        share1,
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
        message_digest,
        k2_G,
    );
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }


    party1_result3.unwrap()
}

fn rotate_share(share1: Party1Share, share2: Party2Share) -> (Party1Share, Party2Share) {
    // party1 step1
    let (party1_rotate_msg1, seed_witness, party1_seed_keypair) = rotate::party1::party1_step1();

    // party2 step1
    let (party2_rotate_msg1, party2_seed_keypair) = rotate::party2::party2_step1();

    // party1 step2
    let party1_result2 = rotate::party1::party1_step2(
        party2_rotate_msg1,
        seed_witness,
        party1_seed_keypair,
        &share1,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let (party1_rotate_msg2, pending_share) = party1_result2.unwrap();


    // party2 step2
    let party2_result2 = rotate::party2::party2_step2(
        party1_rotate_msg2,
        party1_rotate_msg1,
        party2_seed_keypair,
        &share2,
    );
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let (party2_rotate_msg2, share22) = party2_result2.unwrap();

    // party1 step3
    let party1_result3 = rotate::party1::party1_step3(party2_rotate_msg2, pending_share);
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let share11 = party1_result3.unwrap();
    (share11, share22)
}

fn export_private(share1: &Party1Share, share2: &Party2Share) -> BigInt {
    let x1 = &share1.private.x1;
    let x2 = &share2.private.x2;
    let x = (x1 * x2).to_bigint();

    // party1 step1: request party2 for challenge
    // party2 step1
    let party2_export_msg1 = export::party2::party2_step1();
    let challenge = party2_export_msg1.challenge.clone();

    // party1 step2
    let party1_export_msg2 = export::party1::party1_step2(party2_export_msg1, share1);

    // party2 step2
    let party2_result2 = export::party2::party2_step2(party1_export_msg2, &challenge, share2);
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let party2_export_msg2 = party2_result2.unwrap();

    // party1 step3
    let party1_result3 = export::party1::party1_step3(party2_export_msg2, share1);
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let export_x = party1_result3.unwrap();

    if x != export_x {
        panic!("x={}, export_x={}", x, export_x)
    }

    let G = Point::<Secp256k1>::generator();
    let Q = Scalar::<Secp256k1>::from(x) * G;
    if Q != share1.public.pub_key {
        panic!("x * G != pub_key")
    }

    export_x
}