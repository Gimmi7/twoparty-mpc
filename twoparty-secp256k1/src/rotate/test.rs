use crate::generic::share::{Party1Share, Party2Share};
use crate::tests;
use crate::rotate;

#[test]
pub fn test_rotate() {
    let (share1, share2) = tests::full_keygen();
    let x1 = &share1.private.x1;
    let x2 = &share2.private.x2;
    let x = (x1 * x2).to_bigint();


    let (share11, share22) = rotate_share(share1, share2);
    let x11 = share11.private.x1;
    let x22 = share22.private.x2;
    let x_new = (x11 * x22).to_bigint();

    if x != x_new {
        panic!(" x not eq x_new")
    } else {
        println!("rotate success");
    }
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