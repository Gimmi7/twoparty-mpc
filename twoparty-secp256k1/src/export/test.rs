use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use crate::tests;
use crate::export;

#[test]
fn test_export() {
    let (share1, share2) = tests::full_keygen();
    let x1 = &share1.private.x1;
    let x2 = &share2.private.x2;
    let x = (x1 * x2).to_bigint();

    // party1 step1: request party2 for challenge
    // party2 step1
    let party2_export_msg1 = export::party2::party2_step1();
    let challenge = party2_export_msg1.challenge.clone();

    // party1 step2
    let party1_export_msg2 = export::party1::party1_step2(party2_export_msg1, &share1);

    // party2 step2
    let party2_result2 = export::party2::party2_step2(party1_export_msg2, &challenge, &share2);
    if party2_result2.is_err() {
        println!("{}", party2_result2.err().unwrap());
        panic!("")
    }
    let party2_export_msg2 = party2_result2.unwrap();

    // party1 step3
    let party1_result3 = export::party1::party1_step3(party2_export_msg2, &share1);
    if party1_result3.is_err() {
        println!("{}", party1_result3.err().unwrap());
        panic!("")
    }
    let export_x = party1_result3.unwrap();

    if x == export_x {
        println!("export success, x={}", x)
    } else {
        panic!("x={}, export_x={}", x, export_x)
    }

    let G = Point::<Secp256k1>::generator();
    let Q = Scalar::<Secp256k1>::from(x) * G;
    if Q == share1.public.pub_key {
        println!("x * G == pub_key")
    } else {
        panic!("x * G != pub_key")
    }
}