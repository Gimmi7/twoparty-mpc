use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use crate::ChosenHash;

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeDLogProof {
    pub pk: Point<Secp256k1>,
    pub pk_t_rand_commitment: Point<Secp256k1>,
    pub challenge_response: Scalar<Secp256k1>,
}

impl ChallengeDLogProof {
    pub fn prove(sk: &Scalar<Secp256k1>, challenge: &BigInt) -> Self {
        let G = Point::<Secp256k1>::generator();

        let sk_t_rand_commitment = Scalar::random();
        let pk_t_rand_commitment = &sk_t_rand_commitment * G;

        let pk = sk * G;

        let e = ChosenHash::new()
            .chain_point(&pk_t_rand_commitment)
            .chain_point(&G.to_point())
            .chain_point(&pk)
            .chain_bigint(challenge)
            .result_scalar();

        let e_mul_sk = e * sk;
        let challenge_response = &sk_t_rand_commitment - e_mul_sk;
        ChallengeDLogProof {
            pk,
            pk_t_rand_commitment,
            challenge_response,
        }
    }

    pub fn verify(&self, challenge: &BigInt) -> bool {
        let G = Point::<Secp256k1>::generator();

        let e = ChosenHash::new()
            .chain_point(&self.pk_t_rand_commitment)
            .chain_point(&G.to_point())
            .chain_point(&self.pk)
            .chain_bigint(challenge)
            .result_scalar();

        let e_mul_Q = e * &self.pk;
        let R_v = &self.challenge_response * G + e_mul_Q;
        R_v == self.pk_t_rand_commitment
    }
}

#[cfg(test)]
mod test {
    use curv::arithmetic::Samplable;
    use curv::BigInt;
    use curv::elliptic::curves::{Scalar, Secp256k1};
    use crate::generic::challenge_dlog::ChallengeDLogProof;

    #[test]
    fn test_challenge_d_log_proof() {
        let sk = Scalar::<Secp256k1>::random();
        let challenge = BigInt::sample(2048);

        let proof = ChallengeDLogProof::prove(&sk, &challenge);
        let flag = proof.verify(&challenge);
        println!("{:?}", proof);
        assert!(flag)

    }
}