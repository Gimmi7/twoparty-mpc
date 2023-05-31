#![feature(lazy_cell)]

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::thread;

// https://stackoverflow.com/questions/27791532/how-do-i-create-a-global-mutable-singleton
static CACHED_CONNECTION: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

#[test]
fn test_mutex_map() {
    println!("test mutex map in multi threads");

    let mut handles = vec![];
    for i in 0..10 {
        let handle = thread::spawn(move || {
            let mut map = CACHED_CONNECTION.lock().unwrap();
            map.insert(format!("key{i}"), format!("value{i}"));
        });
        handles.push(handle);
    }

    // wait for all threads finish
    for handle in handles {
        handle.join().unwrap();
    }
    println!("{:?}", CACHED_CONNECTION.lock().unwrap());
}
