use std::error;
use std::fmt::{Display, Formatter};
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct TwoPartyError {
    pub party: u8,
    pub action: String,
    pub step: u8,
    pub reason: String,
}

impl Display for TwoPartyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TwoPartyError: party-{} {} at step-{}: {}", self.party, self.action, self.step, self.reason)
    }
}

impl error::Error for TwoPartyError {}