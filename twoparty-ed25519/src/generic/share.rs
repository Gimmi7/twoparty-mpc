use curv::elliptic::curves::{Ed25519, Point, Scalar};
use serde::{Deserialize, Serialize};

/// An Ed25519 signing key
#[derive(Serialize, Deserialize)]
pub struct Ed25519Share {
    pub prefix: [u8; 32],
    pub x: Scalar<Ed25519>,
    // hash(P1,P2), this shouldn't change when rotate, other wise the agg_P would change
    pub agg_hash_Q: Scalar<Ed25519>,
    // aggregated public_key
    pub agg_Q: Point<Ed25519>,
    // aggregated -public_key
    pub agg_Q_minus: Point<Ed25519>,

}