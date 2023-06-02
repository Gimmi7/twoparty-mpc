use std::time::SystemTime;

#[test]
fn test_tsp() {
    let tsp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    println!("{}, length={}", tsp, tsp.to_string().len());
}