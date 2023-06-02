use curv::elliptic::curves::{Ed25519, Point, Secp256k1};

#[test]
fn test_point_bytes() {
    let secp256k1_point = Point::<Secp256k1>::generator().to_point();
    let ed25519_point = Point::<Ed25519>::generator().to_point();

    // https://medium.com/asecuritysite-when-bob-met-alice/02-03-or-04-so-what-are-compressed-and-uncompressed-public-keys-6abcb57efeb6
    let sec256k1_uncompressed_bytes = secp256k1_point.to_bytes(false);
    let sec256k1_uncompressed_hex = hex::encode(sec256k1_uncompressed_bytes);
    println!("{:?}", sec256k1_uncompressed_hex);
    println!("{:?}", secp256k1_point);
    let sec256k1_decode_bytes = hex::decode(sec256k1_uncompressed_hex).unwrap();
    let sec256k1_deserialize_point = Point::<Secp256k1>::from_bytes(&sec256k1_decode_bytes).unwrap();
    println!("{:?}", sec256k1_deserialize_point);


    println!(" ");
    let ed25519_bytes = ed25519_point.to_bytes(false);
    let ed25519_hex = hex::encode(ed25519_bytes);
    println!("{}", ed25519_hex);
    println!("{:?}", ed25519_point);
    let ed25519_decode_bytes = hex::decode(ed25519_hex).unwrap();
    let ed25519_deserialize_point = Point::<Ed25519>::from_bytes(&ed25519_decode_bytes).unwrap();
    println!("{:?}", ed25519_deserialize_point);
}