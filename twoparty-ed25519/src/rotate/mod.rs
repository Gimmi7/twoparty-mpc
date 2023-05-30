pub mod party1;
pub mod party2;

#[cfg(test)]
mod test {
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::elliptic::curves::{Ed25519, Scalar, Secp256k1};

    #[test]
    fn test_random_scalar() {
        // ed25519 scalar uses little-endian
        let ed_scalar = Scalar::<Ed25519>::from(258);
        println!("{:?}", ed_scalar.to_bytes().as_ref());
        let ed_mul_2 = ed_scalar * Scalar::<Ed25519>::from(2);
        println!("{:?}", ed_mul_2.to_bytes().as_ref());

        // secp256k1 scalar uses big-endian
        let secp_scalar = Scalar::<Secp256k1>::from(258);
        println!("{:?}", secp_scalar.to_bytes().as_ref());
        let secp_mul_2 = secp_scalar * Scalar::<Secp256k1>::from(2);
        println!("{:?}", secp_mul_2.to_bytes().as_ref());

        let cofactor = Scalar::<Ed25519>::from(8);
        for _i in 1..=100 {
            let scalar = Scalar::<Ed25519>::random();
            let scalar_8 = &scalar * &cofactor;

            let first_byte = scalar_8.to_bytes()[0];
            let last_byte = scalar_8.to_bytes()[31];
            if first_byte > 248 || last_byte > 127 {
                println!("{}, {}", first_byte, last_byte);
                println!("{:?}", scalar.to_bytes().as_ref());
                panic!("scalar clamping bug")
            }
        }
    }

    #[test]
    fn big_int_overflow() {
        let big_bytes = [255u8; 32];
        let bn = BigInt::from_bytes(&big_bytes);
        println!("{:?}", bn.to_bytes());
        let over = bn + BigInt::from(1);
        println!("{:?}", over.to_bytes());
    }
}