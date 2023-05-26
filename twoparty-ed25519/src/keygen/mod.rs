use curv::elliptic::curves::{Ed25519, Scalar};

pub mod party1;
pub mod party2;


pub fn create_secret_scalar_and_prefix() -> (Scalar<Ed25519>, [u8; 32]) {

}