use curv::arithmetic::{BasicOps, Converter};
use curv::BigInt;

#[test]
fn test_edwards25519() {
    // edwards25519 parameters: [https://datatracker.ietf.org/doc/html/rfc7748#section-4.1]

    let suffix_bn = BigInt::from_str_radix("14def9dea2f79cd65812631a5cf5d3ed", 16).unwrap();
    println!("suffix_bn={}", &suffix_bn);

    let q = BigInt::from(2).pow(255) - 19;
    println!("{}", &q);
    let order_g = BigInt::from(2).pow(252) + suffix_bn;

    let cofactor = BigInt::from(8);
    let order_factor = &order_g * cofactor;
    println!("{}", order_factor);

    if order_factor == q {
        println!("order_g * cofactor = q")
    } else {
        println!("order_g * cofactor != q")
    }

}