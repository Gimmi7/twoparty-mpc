use crate::mpc::secp256k1::{secp256k1_sign, Secp256k1Sig};
use super::secp256k1;

#[tokio::test(flavor = "multi_thread")]
async fn test_secp256k1_ecdsa() {
    let identity_id = "wangcy";
    let url = "ws://localhost:8822/ws";
    let saved_share = secp256k1::secp256k1_keygen(identity_id.to_string(), url.to_string()).await.unwrap();
    println!("{}", serde_json::to_string(&saved_share).unwrap());

    let message_digest = vec![1, 2, 3, 4];
    let sig = secp256k1_sign(identity_id.to_string(), url.to_string(), &saved_share, message_digest).await.unwrap();
    let secp256k1_sig = serde_json::from_slice::<Secp256k1Sig>(&sig).unwrap();
    println!("{:?}", secp256k1_sig);
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