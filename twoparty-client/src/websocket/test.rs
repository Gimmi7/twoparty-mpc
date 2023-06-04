use std::cell::{RefCell};

use std::string::ToString;
use std::sync::{Arc, LazyLock};
use std::thread::sleep;
use std::time::Duration;

use common::socketmsg::REQ_CODE_MPC22;
use crate::websocket::SyncClient;
use tokio::sync::{oneshot, mpsc, RwLock};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;

#[test]
fn single_thread_rt() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build().unwrap();
    // spawn the root task
    rt.block_on(async {
        let url = "ws://localhost:8822/ws";
        let identity_id = "wangcy";
        let connect_result = SyncClient::connect_server(identity_id.to_string(), url.to_string(), 3).await;
        let sync_client = connect_result.expect("connect fail");

        let req_result = sync_client.send_req(REQ_CODE_MPC22, vec![], None).await;
        let rsp = req_result.unwrap();
        println!("{:?}", rsp);


        tokio::time::sleep(Duration::from_secs(10)).await;
        println!("after sleep 10s");

        drop(sync_client);

        // // hang the client
        // let (hang_tx, hang_rx) = oneshot::channel::<()>();
        // let _ = hang_rx.await;
    });

    println!("return to main");
    sleep(Duration::from_secs(10));
    println!("after sleep 10s in main");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_websocket() {
    let url = "ws://localhost:8822/ws";
    let identity_id = "wangcy";
    let connect_result = SyncClient::connect_server(identity_id.to_string(), url.to_string(), 3).await;
    let sync_client = connect_result.expect("connect fail");

    let req_result = sync_client.send_req(REQ_CODE_MPC22, vec![], None).await;
    let rsp = req_result.unwrap();
    println!("{:?}", rsp);

    //  hang the client
    let (_hang_tx, hang_rx) = oneshot::channel::<()>();
    let _ = hang_rx.await;
}

#[test]
fn assign_cell_pointer() {
    let value = RefCell::new("hello".to_string());

    let mut_pointer = value.as_ptr();

    unsafe {
        *mut_pointer = "world++".to_string(); // Unsafe assignment through the pointer
    }

    println!("Updated value: {}", value.borrow());
}

#[test]
fn assign_raw_pointer() {
    let mut value = "hello".to_string();

    let mut_ptr = &mut value as *mut String;

    unsafe {
        *mut_ptr = "world++".to_string();
    }
    println!("Updated value: {}", value);
}

struct ChannelWrapper {
    tx: UnboundedSender<()>,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_reassign_drop() {
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();

    tokio::spawn(async move {
        loop {
            match timeout(Duration::from_secs(3), rx.recv()).await {
                Err(_elapsed) => {
                    println!("trigger timeout")
                }
                Ok(msg) => {
                    if msg.is_none() {
                        println!("channel get none, channel closed");
                        return;
                    }
                }
            }
        }
    });

    sleep(Duration::from_secs(10));

    // proactive drop can send none to channel
    // drop(tx);
    // println!("dropped the tx");

    // dropped the wrapper with tx can send none to channel
    // let wrapper = ChannelWrapper {
    //     tx
    // };
    // drop(wrapper);
    // println!("dropped the wrapper with tx");

    // reassign the tx in struct will drop the old one
    // let mut wrapper = ChannelWrapper {
    //     tx
    // };
    // let (new_tx, new_rx) = mpsc::unbounded_channel::<()>();
    // wrapper.tx = new_tx;
    // println!("reassign the tx in struct");

    // reassign struct with tx will drop old struct
    let mut _wrapper = ChannelWrapper {
        tx
    };
    let (new_tx, _new_rx) = mpsc::unbounded_channel::<()>();
    let new_wrapper = ChannelWrapper {
        tx: new_tx
    };
    _wrapper = new_wrapper;
    _wrapper.tx;
    println!("reassign struct with tx");



    //  hang the client
    let (_hang_tx, hang_rx) = oneshot::channel::<()>();
    let _ = hang_rx.await;
}

// #[tokio::test(flavor = "multi_thread")]
// async fn test_mut_arc() {
//     let value = "hello".to_string();
//     let arc_value = Arc::new(RefCell::new(value));
//
//     let write = arc_value.clone();
//     tokio::spawn(async move {
//         let mut mut_value = write.borrow_mut();
//         // cannot borrow data in an `Arc` as mutable
//         mut_value.push_str("world");
//     });
//
//     sleep(Duration::from_secs(2));
//     let read = arc_value.clone();
//     println!("read value={}", read.borrow());
//
//
//     //  hang the client
//     let (hang_tx, hang_rx) = oneshot::channel::<()>();
//     let _ = hang_rx.await;
// }

pub static MYS: LazyLock<Arc<RwLock<String>>> = LazyLock::new(|| {
    Arc::new(RwLock::new("".to_string()))
});

#[tokio::test(flavor = "multi_thread")]
async fn test_mutable_static() {
    {
        let read = MYS.read().await;
        println!("read value={}", read);
    }

    let mut write = MYS.write().await;
    tokio::spawn(async move {
        write.push_str("hello world");
    });

    sleep(Duration::from_secs(3));

    {
        let after_read = MYS.read().await;
        println!("after_read value={}", after_read);
    }

    //  hang the client
    let (_hang_tx, hang_rx) = oneshot::channel::<()>();
    let _ = hang_rx.await;
}