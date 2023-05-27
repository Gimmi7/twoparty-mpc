use crate::generic::share::Ed25519Share;
use crate::keygen;

#[test]
fn test_keygen() {
    let (share1, share2) = full_keygen();
    println!("{}", serde_json::to_string(&share1).unwrap());
    println!("{}", serde_json::to_string(&share2).unwrap());
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