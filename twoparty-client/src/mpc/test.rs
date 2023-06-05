use crate::mpc::ed25519::{ed25519_keygen, ed25519_rotate, ed25519_sign};
use crate::mpc::secp256k1::{secp256k1_export, secp256k1_rotate, secp256k1_sign, Secp256k1Sig};
use super::secp256k1;

#[tokio::test(flavor = "multi_thread")]
async fn test_secp256k1_ecdsa() {
    let identity_id = "wangcy";
    let url = "ws://localhost:8822/ws";
    let saved_share = secp256k1::secp256k1_keygen(identity_id.to_string(), url.to_string()).await.unwrap();
    println!("secp256k1 keygen success, share_id={}", &saved_share.share_id);
    let x = secp256k1_export(url.to_string(), &saved_share).await.unwrap();
    println!("export success x={}", x);

    let message_digest = vec![1, 2, 3, 4];
    let sig = secp256k1_sign(url.to_string(), &saved_share, message_digest).await.unwrap();
    let secp256k1_sig = serde_json::from_slice::<Secp256k1Sig>(&sig).unwrap();
    println!("{:?}", secp256k1_sig);

    let new_share = secp256k1_rotate(url.to_string(), &saved_share).await.unwrap();
    println!("rotate success, new_share_id={}", new_share.share_id);

    let x_rotate = secp256k1_export(url.to_string(), &new_share).await.unwrap();
    println!("export new_share success, x={}", x_rotate);

    if x != x_rotate {
        panic!("x_rotate != x");
    }
}


#[tokio::test(flavor = "multi_thread")]
async fn test_ed25519_eddsa() {
    let identity_id = "wangcy";
    let url = "ws://localhost:8822/ws";
    let saved_share = ed25519_keygen(identity_id.to_string(), url.to_string()).await.unwrap();
    println!("ed25519 keygen success, share_id={}", &saved_share.share_id);

    let message_digest = vec![1, 2, 3, 4];
    let sig = ed25519_sign(url.to_string(), &saved_share, message_digest.clone()).await.unwrap();
    println!("sig length={}", sig.len());

    let rotated_share = ed25519_rotate(url.to_string(), &saved_share).await.unwrap();
    println!("ed25519 rotate success, share_id={}", &rotated_share.share_id);

    let sig2 = ed25519_sign(url.to_string(), &rotated_share, message_digest).await.unwrap();
    println!("sig length={}", sig2.len());

    if sig2 != sig {
        panic!("sig not deterministic after rotate");
    }
}


#[test]
fn test_serde() {
    let share_id = "hello".to_string();
    let bytes = share_id.clone().into_bytes();

    let json_bytes = serde_json::to_vec(&share_id).unwrap();
    if bytes == json_bytes {
        println!("all the same");
    } else {
        println!("{:?}", bytes);
        println!("{:?}", json_bytes);
    }
}