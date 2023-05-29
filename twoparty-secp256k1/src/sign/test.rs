use curv::arithmetic::Integer;
use curv::BigInt;


use crate::tests;

#[test]
fn test_sign() {
    // generate share
    let (share1, share2) = tests::full_keygen();
    println!("{:?}", serde_json::to_string(&share1).unwrap());
    println!("{:?}", serde_json::to_string(&share2).unwrap());

    println!("===============================");

    let message_digest = vec![1, 2, 3, 4];
    let sig = tests::sign_message(&share1, &share2, &message_digest);

    println!("sig={:?}", sig)
}

#[test]
pub fn sign_for_recovery() {
    let (share1, share2) = tests::full_keygen();
    let x1 = &share1.private.x1;
    let x2 = &share2.private.x2;
    let x = (x1 * x2).to_bigint();

    let digest = vec![1, 2, 3, 4];
    let sig = tests::sign_message(&share1, &share2, &digest);
    println!("x={}", x);
    println!("digest={:?}", digest);
    println!("r={}", &sig.r);
    println!("s={}", &sig.s);
    println!("v={}", &sig.v);
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