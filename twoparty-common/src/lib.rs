#![allow(non_snake_case)]


use std::time::SystemTime;
use uuid::Uuid;

pub mod errors;
pub mod dlog;
pub mod socketmsg;


pub fn get_tsp() -> u128 {
    
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis()
}


pub fn get_uuid() -> String {
    let v4 = Uuid::new_v4();
    let v4id = v4.as_simple().to_string();
    v4id
}