use crate::websocket::inbound_dispatcher::InboundWithTx;

pub async fn mpc22_handler(inbound: InboundWithTx) {
    let req = &inbound.msg_wrapper;
    println!("{:?}", req);
    inbound.success_rsp(None).await;
}