use crate::tests;
use crate::export;

#[test]
fn test_export() {
    let (share1, share2) = tests::full_keygen();
    let x1 = &share1.private.x1;
    let x2 = &share2.private.x2;
    let x = (x1 * x2).to_bigint();

    // party1 step1
    let party1_export_msg1 = export::party1::party1_step1(&share1);

    // party2 step1
    let party2_result1 = export::party2::party2_step1(party1_export_msg1, &share2);
    if party2_result1.is_err() {
        println!("{}", party2_result1.err().unwrap());
        panic!("")
    }
    let party2_export_msg1 = party2_result1.unwrap();

    // party1 step2
    let party1_result2 = export::party1::party1_step2(party2_export_msg1, &share1);
    if party1_result2.is_err() {
        println!("{}", party1_result2.err().unwrap());
        panic!("")
    }
    let export_x = party1_result2.unwrap();

    if x == export_x {
        println!("export success, x={}", x)
    } else {
        panic!("x={}, export_x={}", x, export_x)
    }
}