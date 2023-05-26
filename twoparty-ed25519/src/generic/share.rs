use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};

/// An Ed25519 signing key
#[derive(Serialize, Deserialize)]
pub struct Ed25519Share {
    pub prefix: [u8; 32],
    pub x: Scalar<Ed25519>,
    // public_key of x
    pub P: Point<Ed25519>,
    // aggregated public_key
    pub agg_P: Point<Ed25519>,
    // aggregated -public_key
    pub agg_P_minus: Point<Ed25519>,
    // hash(P1,P2,...,Pn), this should change when rotate
    pub agg_hash_P: Scalar<Ed25519>,
}