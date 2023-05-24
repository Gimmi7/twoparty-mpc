#![allow(non_snake_case)]

extern crate core;

pub mod keygen;
pub mod generic;
pub mod sign;
pub mod export;

type ChosenHash = sha3::Keccak256;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
pub mod tests;
