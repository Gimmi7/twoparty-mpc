use super::ecdsa;

#[tokio::test(flavor = "multi_thread")]
async fn test_secp256k1_ecdsa() {
    let identity_id = "wangcy";
    let url = "ws://localhost:8822/ws";
    let saved_share = ecdsa::keygen(identity_id.to_string(), url.to_string()).await.unwrap();
    println!("{}", serde_json::to_string(&saved_share).unwrap());
}


#[test]
fn test_serde() {
    let share_id = "hello".to_string();
    let bytes = share_id.clone().into_bytes();

    let json_bytes = serde_json::to_vec(&share_id).unwrap();
    if bytes == json_bytes {
        println!("all the same");
    }else {
        println!("{:?}", bytes);
        println!("{:?}", json_bytes);
    }
}