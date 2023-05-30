use curv::cryptographic_primitives::hashing::Digest;
use curv::elliptic::curves::{Ed25519, Scalar};
use rand::Rng;
use crate::ChosenHash;

pub mod share;

pub fn clamping_seed() -> (Scalar<Ed25519>, [u8; 32], [u8; 32]) {
    let seed: [u8; 32] = rand::thread_rng().gen();
    let (x, prefix) = clamping_with_seed(&seed);
    (x, prefix, seed)
}


// https://www.jcraige.com/an-explainer-on-ed25519-clamping
pub fn clamping_with_seed(seed: &[u8; 32]) -> (Scalar<Ed25519>, [u8; 32]) {
    // expand the seed to 64 bytes
    let h = ChosenHash::digest(&seed[..]);

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

#[cfg(test)]
mod test {
    use crate::generic::clamping_seed;

    #[test]
    fn test_clamping() {
        for _i in 1..=100 {
            let (x, _prefix, _seed) = clamping_seed();
            let first_byte = x.to_bytes()[0];
            let last_byte = x.to_bytes()[31];
            if first_byte > 248 || last_byte > 127 {
                panic!("clamping bug")
            }
        }
        println!("pass through clamping test");
    }
}