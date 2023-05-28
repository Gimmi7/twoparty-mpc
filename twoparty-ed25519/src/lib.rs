#![allow(non_snake_case)]


extern crate core;

type ChosenHash= sha2::Sha512;

#[cfg(test)]
mod tests;

pub mod keygen;
pub mod generic;
pub mod sign;
