#![allow(non_snake_case)]



type ChosenHash= sha2::Sha512;

#[cfg(test)]
mod tests;

pub mod keygen;
pub mod generic;
pub mod sign;
pub mod rotate;
