use std::{
    error::Error,
    io::{Read, Write},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use sha3::{digest::generic_array::GenericArray, Digest, Sha3_256};

const NONCE_BYTES_LEN: usize = 12;

#[inline]
fn run(args_vec_ref: &Vec<String>) -> Result<(), Box<dyn Error>> {
    let mut key_string = match rpassword::read_password() {
        Ok(key_string) => key_string,
        Err(_) => return Err("An error has occurred when reading the secret key.".into()),
    };

    let from_file_path_string_ref = if let Some(from_file_path_string_ref) = args_vec_ref.get(1) {
        from_file_path_string_ref
    } else {
        return Err("It seems the first argument \"read from file path\" is missing...".into());
    };
    let to_file_path_string_ref = if let Some(to_file_path_string_ref) = args_vec_ref.get(2) {
        to_file_path_string_ref
    } else {
        return Err("It seems the second argument \"write to file path\" is missing...".into());
    };

    let mut hasher = Sha3_256::new();
    hasher.update(key_string.as_bytes());
    let key_bytes_ref = &hasher.finalize()[..];

    for byte_mut_ref in unsafe { key_string.as_bytes_mut() } {
        *byte_mut_ref = 0;
    }

    let mut from_file = std::fs::File::open(from_file_path_string_ref)?;
    let mut file_buf: Vec<u8> = Vec::new();
    from_file.read_to_end(&mut file_buf)?;

    let cipher_key = GenericArray::clone_from_slice(key_bytes_ref); // ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce: Nonce = GenericArray::clone_from_slice(&key_bytes_ref[..NONCE_BYTES_LEN]); // 96-bits; unique per message
    let plaintext = match cipher.decrypt(&nonce, file_buf.as_ref()) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(format!("Decrypt Error: {}", err).into());
        }
    };

    let mut to_file = std::fs::File::create(to_file_path_string_ref)?;
    to_file.write_all(&plaintext)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Err(err_info) = run(&args) {
        eprintln!("An error has occurred: {}", err_info);
        std::process::exit(1);
    };
    std::process::exit(0);
}
