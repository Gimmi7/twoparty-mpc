#![allow(non_snake_case)]

extern crate core;

pub mod keygen;
pub mod generic;

type ChosenHash = sha3::Keccak512;