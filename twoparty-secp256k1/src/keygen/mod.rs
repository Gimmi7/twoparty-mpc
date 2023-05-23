


use curv::elliptic::curves::{Point, Scalar, Secp256k1};


const SECURITY_BITS: usize = 256;

/// Sensitive secret can only access via getter
pub struct Secp256k1KeyPair {
    pub public: Point<Secp256k1>,
    secret: Scalar<Secp256k1>,
}


#[cfg(test)]
mod test;

pub mod share;
pub mod party1;
pub mod party2;
pub mod correct_encrypt_secret;