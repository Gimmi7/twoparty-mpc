use std::sync::atomic::{AtomicU32, Ordering};

// normal u32 overflow will panic
#[test]
fn test_u32_overflow() {
    let max = u32::MAX;
    println!("max={}", max);
    let max_one = max + 1;
    println!("max_one={}", max_one)
}

// atomic overflow will ring to 0
#[test]
fn test_atomic_overflow() {
    let max = AtomicU32::new(u32::MAX);
    println!("max={:?}", max);
    for _i in 0..10 {
        let max_one = max.fetch_add(1, Ordering::SeqCst);
        println!("max_one={}", max_one);
    }
}