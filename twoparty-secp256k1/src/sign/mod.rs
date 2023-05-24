use curv::BigInt;
use serde::{Deserialize, Serialize};

pub mod party1;
pub mod party2;
#[cfg(test)]
mod test;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ECDSASignature {
    pub r: BigInt,
    pub s: BigInt,
    pub v: u8,
}