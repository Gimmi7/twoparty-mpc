use common::socketmsg::types::SavedShare;
use std::fs::File;
use std::io::{Read, Write};

// `async` trait functions are not currently supported
// pub trait ShareStorageTrait {
//     async fn save_share(share: SavedShare) -> Result<(), String>;
//
//     async fn load_share(share_id: String) -> Result<SavedShare, String>;
// }


pub struct FileShareStorage;

impl FileShareStorage {
    pub(crate) async fn save_share(share: SavedShare) -> Result<(), String> {
        let share_bytes_result = serde_json::to_vec(&share);
        if share_bytes_result.is_err() {
            return Err(share_bytes_result.unwrap_err().to_string());
        }
        let share_bytes = share_bytes_result.unwrap();

        let path = format!("share_{}.share", share.share_id);
        let file_result = File::create(path);
        if file_result.is_err() {
            return Err(file_result.unwrap_err().to_string());
        }
        let mut file = file_result.unwrap();

        let result = file.write_all(&share_bytes);
        if result.is_err() {
            return Err(result.unwrap_err().to_string());
        }

        Ok(())
    }

    pub(crate) async fn load_share(share_id: String) -> Result<SavedShare, String> {
        let path = format!("share_{}.share", share_id);
        let file_result = File::open(path);
        if file_result.is_err() {
            return Err(file_result.unwrap_err().to_string());
        }
        let mut file = file_result.unwrap();

        let mut share_bytes = vec![];
        let result = file.read_to_end(&mut share_bytes);
        if result.is_err() {
            return Err(result.unwrap_err().to_string());
        }

        let share_result = serde_json::from_slice::<SavedShare>(&share_bytes);
        if share_result.is_err() {
            return Err(share_result.err().unwrap().to_string());
        }

        Ok(share_result.unwrap())
    }
}