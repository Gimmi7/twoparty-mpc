#![allow(non_snake_case)]

pub mod keygen;
pub mod generic;
pub mod sign;

type ChosenHash = sha3::Keccak256;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
pub mod tests;
