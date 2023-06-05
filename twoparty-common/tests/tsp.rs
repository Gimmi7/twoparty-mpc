use std::time::SystemTime;
use curv::arithmetic::Converter;
use curv::BigInt;

#[test]
fn test_tsp() {
    let tsp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    println!("{}, length={}", tsp, tsp.to_string().len());
}

#[test]
fn bigint_to_string() {
    let b = BigInt::from(100);
    println!("{}", b.to_string());

    let r = "3531303634393336303236393130303936333434343534303135363939383033323433393835333138383339313937353531373933303030313932373338383130343632353238383137363339".to_string();
    let r_bn = BigInt::from_str_radix(&r, 10).unwrap();
    let hex = r_bn.to_hex();
    println!("{}", hex);
}