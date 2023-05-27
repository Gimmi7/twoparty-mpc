use curv::elliptic::curves::{Ed25519, Scalar};
use rand::Rng;
use sha3::Digest;

pub mod share;

// https://www.jcraige.com/an-explainer-on-ed25519-clamping
pub fn clamping_seed() -> (Scalar<Ed25519>, [u8; 32]) {
    let seed: [u8; 32] = rand::thread_rng().gen();
    // expand the seed to 64 bytes
    let h = sha3::Keccak512::digest(&seed[..]);

    // convert the low half to a ed25519 scalar
    let x = {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[..].copy_from_slice(&h.as_slice()[0..32]);
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        Scalar::<Ed25519>::from_bytes(&scalar_bytes).unwrap()
    };

    // convert the high half as prefix
    let prefix = {
        let mut prefix = [0u8; 32];
        prefix[..].copy_from_slice(&h.as_slice()[32..64]);
        prefix
    };

    Scalar::<Ed25519>::random();

    (x, prefix)
}
