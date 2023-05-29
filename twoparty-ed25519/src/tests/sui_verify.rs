use std::fs::File;
use std::io::Read;

use curv::elliptic::curves::{Ed25519, Point};


use fastcrypto::hash::HashFunction;
use fastcrypto::traits::{Signer, ToFromBytes};

use crate::generic::share::Ed25519Share;
use hex::ToHex;

use crate::generic::{clamping_with_seed};
use crate::sign::normal_sign;
use crate::tests::sign_message;


#[test]
fn sign_digest_with_mpc() {
    let (share1, share2) = load_share();
    let agg_hash_Q = &share1.agg_hash_Q;
    let secret = agg_hash_Q * (&share1.x + &share2.x);
    let G = Point::<Ed25519>::generator();

    let pub_key = &secret * G;
    let agg_Q = &share1.agg_Q;
    if pub_key.x_coord().unwrap() == agg_Q.x_coord().unwrap() {
        println!("calc_pub_key == agg_Q");
    } else {
        panic!("calc_pub_key != agg_Q")
    }
    println!("agg_Q_x: {:?}", agg_Q.to_bytes(true).as_ref());

    let sui_address = calc_sui_address(pub_key.to_bytes(true).as_ref());
    println!("sui_address= 0x{}", sui_address);

    let hex_message_digest = "72e5f7c0f5ca6728d7e155e5705d2dfc1b41c4bff3c54c4951a0e6d77a21b25d";
    let message_digest = hex::decode(hex_message_digest).unwrap();

    let sig = sign_message(&share1, &share2, &message_digest);

    // Form the signature of the concatenation of R (32 octets) and the
    // little-endian encoding of S (32 octets; the three most
    // significant bits of the final octet are always zero).

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(sig.R.to_bytes(true).as_ref());
    sig_bytes[32..].copy_from_slice(sig.s.to_bytes().as_ref());
    println!("sig_bytes={:?}", sig_bytes)
}

fn load_share() -> (Ed25519Share, Ed25519Share) {
    let current_dir = std::env::current_dir().expect("fail to get current_dir");

    let mut share_vec = Vec::with_capacity(2);
    for i in [1, 2] {
        let file_path = current_dir.join(format!("src/tests/share{}.json", i));
        let mut share_file = File::open(file_path).expect("fail to open share file");
        let mut share_json = String::new();
        share_file.read_to_string(&mut share_json).expect("fail to read share file");
        let share: Ed25519Share = serde_json::from_str(share_json.as_str()).unwrap();
        share_vec.push(share);
    }

    (share_vec.pop().unwrap(), share_vec.pop().unwrap())
}


#[test]
fn compare_normal_sign_with_sui_sign() {
    // let seed: [u8; 32] = rand::thread_rng().gen();
    let seed = [206, 40, 47, 196, 249, 151, 104, 156, 80, 188, 200, 250, 169, 18, 190, 226, 173, 150, 1, 36, 113, 28, 79, 210, 225, 229, 57, 131, 69, 166, 151, 15];
    let (x, prefix) = clamping_with_seed(&seed);

    let signing_key = ed25519_consensus::SigningKey::from(seed);
    let pub_key = signing_key.verification_key().to_bytes();

    let G = Point::<Ed25519>::generator();
    let calc_pub = &x * G;
    if calc_pub.to_bytes(false).as_ref() != pub_key {
        panic!("pub_key not consistent");
    }

    println!("seed={:?}", seed);
    println!("pub_key={:?}", pub_key);
    let sui_address = calc_sui_address(&pub_key);
    println!("sui_address={}", format!("0x{}", sui_address));

    let kp_private = fastcrypto::ed25519::Ed25519PrivateKey::from_bytes(signing_key.as_bytes()).unwrap();
    let kp = fastcrypto::ed25519::Ed25519KeyPair::from(kp_private);

    // sign
    let hex_digest = "3581f71f09f9a0bcbb7c1933940f51bfccc40c30ce2a19d14216eeda5329e4f6";
    let digest = hex::decode(hex_digest).unwrap();
    let sig = kp.sign(&digest);
    let sig_bytes = sig.sig.to_bytes();
    println!("sig={}", sig);
    println!("{:?}", sig_bytes);

    // normal sign
    let normal_sig = normal_sign(&x, &prefix, &digest);
    println!("{:?}", normal_sig);

    if normal_sig != sig_bytes {
        panic!("normal sign implements incorrectly")
    }
}


#[test]
fn test_sui_address() {
    let (share1, _share2) = load_share();
    let agg_Q = share1.agg_Q;
    let address = calc_sui_address(agg_Q.to_bytes(true).as_ref());
    println!("sui address={}", address)
}

fn calc_sui_address(pk_x: &[u8]) -> String {
    let mut hasher = fastcrypto::hash::Blake2b256::default();
    hasher.update([0x00]);
    hasher.update(pk_x);
    let g_arr = hasher.finalize();
    let address32 = g_arr.digest;
    let hex_address: String = address32.encode_hex();
    hex_address
}