use curv::arithmetic::Integer;
use curv::BigInt;


use crate::sign;
use crate::tests;

#[test]
fn test_sign() {
    // generate share
    let (party1_share, party2_share) = tests::full_keygen();
    println!("{:?}", serde_json::to_string(&party1_share).unwrap());
    println!("{:?}", serde_json::to_string(&party2_share).unwrap());

    println!("===============================");

    // party1 step1
    let (
        party1_sign_msg1,
        d_log_witness,
        party1_eph_keypair
    ) = sign::party1::party1_step1();

    // party2 step1
    let (party2_sign_msg1, party2_eph_keypair) = sign::party2::party2_step1();


    // party1 step2
    let message_hash = BigInt::from(1234);
    let party1_result2 = sign::party1::party1_step2(
        party2_sign_msg1,
        d_log_witness,
        &message_hash,
    );
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let (party1_sign_msg2, k2_G) = party1_result2.unwrap();


    //party2 step2
    let party2_result2 = sign::party2::party2_step2(party1_sign_msg2, party1_sign_msg1, &party2_share, party2_eph_keypair);
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let party2_sign_msg2 = party2_result2.unwrap();


    // party1 step3
    let party1_result3 = sign::party1::party1_step3(
        party2_sign_msg2,
        &party1_share,
        party1_eph_keypair,
        &message_hash,
        k2_G,
    );
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let sig = party1_result3.unwrap();

    println!("sig={:?}", sig)
}


#[test]
pub fn test_mod_floor() {
    let modulus = BigInt::from(-2);
    for v in [5, -5] {
        let v_bn = BigInt::from(v);
        let mf = v_bn.mod_floor(&modulus);
        println!("{} mod_floor {} ={}", v, modulus, mf);
    }
}