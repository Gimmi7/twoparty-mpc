//!     prover:
//!     q is the group oder of secp256k1;
//!      g is the base element of paillier, n is composite number n of paillier, r is the randomness used to encrypt x1 with paillier;
//!     Q= x1 * G, c= g^{x1} r^n
//!     alpha \in  Z_q ,  beta \in Z_q^*
//!     u1= alpha * G ,
//!     u2=g^{alpha} beta^{n} (mod n^2)
//!     e= hash(G,Q,c,u1,u2)
//!     s1 = e x1 + alpha ,
//!     s2= r^e beta (mod n)
//!
//!     verifier:
//!     u1 ?= s1 * G - e * Q ,  u2= g^{s1} s2^n c^{-e} (mod n^2) & u2 != 0 (prevent beta was set to 0)
//!
//!     u1 check that: x1 * G = Q
//!     u2 check that: Dec(c)= x1
//! The proof is a variant version of [https://eprint.iacr.org/2016/013.pdf] The Proof Πi,
//! remove the range proof, because it is slack.
//! Todo: modify bulletproofs to support range proof for v in range [0, 2^256)


use curv::arithmetic::{Modulo, One, Samplable, Zero};
use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use kzen_paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use crate::ChosenHash;


#[derive(Serialize, Deserialize, Debug)]
pub struct CorrectEncryptSecretProof {
    u1: Point<Secp256k1>,
    u2: BigInt,
    s1: BigInt,
    s2: BigInt,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CorrectEncryptSecretStatement {
    pub paillier_ek: EncryptionKey,
    pub c: BigInt,
    pub Q: Point<Secp256k1>,
}


impl CorrectEncryptSecretProof {
    pub fn prove(x1: &BigInt, r: &BigInt, statement: CorrectEncryptSecretStatement) -> Self {
        // secp256k1 parameters
        let q = Scalar::<Secp256k1>::group_order();
        let G = Point::<Secp256k1>::generator();

        // paillier parameters
        let n = statement.paillier_ek.n;
        let g = &n + BigInt::one();
        let nn = statement.paillier_ek.nn;

        let alpha = BigInt::sample_below(q);
        let beta = BigInt::sample_range(&BigInt::one(), q);

        let u1 = Scalar::<Secp256k1>::from(&alpha) * &G.to_point();
        let u2 = encrypt_with_modulus(&g, &beta, &nn, &alpha, &n);

        let e = ChosenHash::new()
            .chain_point(&G)
            .chain_point(&statement.Q)
            .chain_bigint(&statement.c)
            .chain_point(&u1)
            .chain_bigint(&u2)
            .result_bigint();

        let s1 = &e * x1 + alpha;
        let s2 = encrypt_with_modulus(r, &beta, &n, &e, &BigInt::one());

        CorrectEncryptSecretProof {
            u1,
            u2,
            s1,
            s2,
        }
    }

    pub fn verify(&self, statement: &CorrectEncryptSecretStatement) -> Result<(), String> {
        if self.u2.is_zero() {
            return Err("correct_encrypt_secret verify fail: u2 is zero".to_string());
        }

        let G = Point::<Secp256k1>::generator();

        // paillier parameters
        let n = &statement.paillier_ek.n;
        let g = n.clone() + BigInt::one();
        let nn = &statement.paillier_ek.nn;


        let e = ChosenHash::new()
            .chain_point(&G)
            .chain_point(&statement.Q)
            .chain_bigint(&statement.c)
            .chain_point(&self.u1)
            .chain_bigint(&self.u2)
            .result_bigint();

        // u1 ?= s1 * G - e * Q
        let q = Scalar::<Secp256k1>::group_order();
        let e_neg = Scalar::<Secp256k1>::from(q - &e);
        let u1_test = Scalar::<Secp256k1>::from(&self.s1) * &G.to_point() + e_neg * &statement.Q;
        if self.u1 != u1_test {
            return Err("correct_encrypt_secret verify fail: u1 != u1_test".to_string());
        }

        // u2= g^{s1} s2^n c^{-e} (mod n^2)
        let u2_test_tmp = encrypt_with_modulus(
            &g,
            &self.s2,
            nn,
            &self.s1,
            n,
        );
        let u2_test = encrypt_with_modulus(
            &u2_test_tmp,
            &statement.c,
            nn,
            &BigInt::one(),
            &(-&e),
        );
        if self.u2 != u2_test {
            return Err("correct_encrypt_secret verify fail: u2 != u2_test".to_string());
        }

        Ok(())
    }
}

//  h1^{x1} h2^{x2} (mod N)
pub fn encrypt_with_modulus(h1: &BigInt, h2: &BigInt, N: &BigInt, x1: &BigInt, x2: &BigInt) -> BigInt {
    let h1_pow_x1 = BigInt::mod_pow(h1, x1, N);
    let h2_pow_x2 = {
        if x2 < &BigInt::zero() {
            let h2_inv = BigInt::mod_inv(h2, N).unwrap();
            BigInt::mod_pow(&h2_inv, &(-x2), N)
        } else {
            BigInt::mod_pow(h2, x2, N)
        }
    };
    BigInt::mod_mul(&h1_pow_x1, &h2_pow_x2, N)
}