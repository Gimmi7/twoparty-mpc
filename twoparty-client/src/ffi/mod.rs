// This is the interface to the JVM that we'll call the majority of our
// methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native
// function. They carry extra lifetime information to prevent them escaping
// this context and getting used after being GC'd.
use jni::objects::{JClass, JObjectArray, JString, JObject};

// This is just a pointer. We'll be returning it from our function. We
// can't return one of the objects with lifetime information because the
// lifetime checker won't let us.

use tokio::runtime::Runtime;
use crate::mpc::{secp256k1, ed25519};


// This keeps Rust from "mangling" the name and making it unique for this crate.
#[no_mangle]
pub extern "system" fn Java_twoparty_mpc_NativeMpc_seec256k1Keygen<'local>
(mut env: JNIEnv<'local>, _class: JClass<'local>, j_identity_id: JString, j_ws_url: JString) -> JObjectArray<'local> {
    let identity_id: String = env
        .get_string(&j_identity_id)
        .expect("Couldn't get java string!")
        .into();

    let ws_url: String = env
        .get_string(&j_ws_url)
        .expect("Couldn't get java string!")
        .into();

    let rt = get_runtime();
    let result = rt.block_on(async {
        let result = secp256k1::keygen(identity_id, ws_url).await;
        result
    });

    return if let Ok(share) = result {
        let share_bytes = serde_json::to_vec(&share).unwrap();
        fill_j_obj_arr(env, share_bytes, None)
    } else {
        let err = result.err().unwrap();
        fill_j_obj_arr(env, vec![], Some(err))
    };
}

fn fill_j_obj_arr(mut env: JNIEnv, data: Vec<u8>, option_err: Option<String>) -> JObjectArray {
    let mut array_length = 1;
    if option_err.is_some() {
        array_length = 2;
    }
    let array_class = env.find_class("[B").expect("Failed to find byte array class");
    let result = env.new_object_array(array_length, array_class, JObject::null()).expect("Failed to create jobjectArray");

    let data_array = env.byte_array_from_slice(&data).expect("Failed to create data_array");
    env.set_object_array_element(&result, 0, data_array).expect("Failed to set object array element");

    if let Some(err) = option_err {
        let err_array = env.byte_array_from_slice(err.as_bytes()).expect("Failed to create err_array");
        env.set_object_array_element(&result, 1, err_array).expect("Failed to set object array element");
    }

    result
}

fn get_runtime() -> Runtime {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build().unwrap();
    rt
}