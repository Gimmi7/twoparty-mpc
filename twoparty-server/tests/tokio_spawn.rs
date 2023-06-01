use std::thread;
use std::thread::sleep;
use std::time::Duration;

// if not set flavor="multi_thread", spawn task will not work
#[tokio::test(flavor="multi_thread")]
async fn test_tokio_spawn() {
    println!("start: {:?}", thread::current().id());
     tokio::spawn(async {
        println!("spawn 1: {:?}", thread::current().id());
        sleep(Duration::from_secs(3));
        println!("after sleep 3s: {:?}", thread::current().id());
    });

    println!("main thread:{:?}", thread::current().id());
    sleep(Duration::from_secs(5));
}