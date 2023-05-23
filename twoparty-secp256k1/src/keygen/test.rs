use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use kzen_paillier::{EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext};

use crate::keygen::correct_encrypt_secret::{CorrectEncryptSecretProof, CorrectEncryptSecretStatement};
use crate::keygen::party1::{party1_step1, party1_step2};
use crate::keygen::party2::{party2_step1, party2_step2};


#[test]
fn test_correct_encrypt_secret() {
    let x1 = Scalar::<Secp256k1>::random();
    let G = Point::<Secp256k1>::generator().to_point();
    let Q = &x1 * G;
    let (ek, _dk) = Paillier::keypair().keys();
    // party1 encrypt x1
    let randomness = Randomness::sample(&ek);
    let encrypted_x1 = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x1.to_bigint()),
        &randomness,
    ).0.into_owned();
    let r = randomness.0;


    let statement = CorrectEncryptSecretStatement {
        paillier_ek: ek,
        c: encrypted_x1,
        Q,
    };

    let proof = CorrectEncryptSecretProof::prove(&x1.to_bigint(), &r, statement.clone());
    let result = proof.verify(&statement);
    if result.is_err() {
        println!("{}", result.err().unwrap());
    } else {
        println!("success");
    }
}

#[test]
fn test_full_keygen() {
    // party1 step1
    let (party1_keygen_msg1, witness, party1_keypair) = party1_step1();
    // party2 step1
    let (party2_keygen_msg1, party2_keypair) = party2_step1();

    // party1 step2
    let result1 = party1_step2(
        party2_keygen_msg1,
        witness,
        party1_keypair,
    );
    if result1.is_err() {
        println!("{}", result1.err().unwrap());
        panic!("");
    }
    let result1_tuple = result1.unwrap();
    let party1_share = &result1_tuple.1;
    println!("party1 share:{}", serde_json::to_string(&party1_share).unwrap());

    // party2 step2
    let result2 = party2_step2(
        result1_tuple.0,
        party1_keygen_msg1,
        party2_keypair,
    );
    if result2.is_err() {
        println!("{}", result2.err().unwrap());
        panic!("");
    }
    println!("party2 share:{}", serde_json::to_string(&result2.unwrap()).unwrap());
}