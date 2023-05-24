use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use kzen_paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Party1Private {
    pub x1: Scalar<Secp256k1>,
    // r used for encrypting x1
    pub r_encrypting_x1: BigInt,
    pub paillier_dk: DecryptionKey,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party1Public {
    pub public_share: Point<Secp256k1>,
    pub paillier_ek: EncryptionKey,
    pub pub_key: Point<Secp256k1>,
}

#[derive(Serialize, Deserialize)]
pub struct Party1Share {
    pub public: Party1Public,
    pub private: Party1Private,
}


//========================================================================

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party2Public {
    pub public_share: Point<Secp256k1>,
    pub encrypted_x1: BigInt,
    pub paillier_ek: EncryptionKey,
    pub pub_key: Point<Secp256k1>,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Private {
    pub x2: Scalar<Secp256k1>,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Share {
    pub public: Party2Public,
    pub private: Party2Private,
}