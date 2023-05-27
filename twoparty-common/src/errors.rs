use std::error;
use std::fmt::{Display, Formatter};
use serde::Serialize;

pub const SCOPE_ECDSA_SECP256K1: &str = "ecdsa-secp256k1";
pub const SCOPE_EDDSA_ED25519: &str = "eddsa-edd25519";

#[derive(Serialize, Debug)]
pub struct TwoPartyError {
    pub scope: String,
    pub party: u8,
    pub action: String,
    pub step: u8,
    pub reason: String,
}

impl Display for TwoPartyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TwoPartyError: scope={}, party-{} {} at step-{}: {}", self.scope, self.party, self.action, self.step, self.reason)
    }
}

impl error::Error for TwoPartyError {}