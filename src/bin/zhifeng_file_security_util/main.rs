// Zhifeng's Security Utilities
// Copyright (C) 2024 Zhifeng Wang 王之枫
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{error::Error, ffi::OsString, fs::File, io::Read, path::PathBuf, str::FromStr};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha3::digest::generic_array::GenericArray;

use zhifeng_security_util::{read_secret_key_line_in_private, ByteString, ConsoleHelper};

mod util;
use util::save_file;

fn encrypt(
    cipher: &ChaCha20Poly1305,
    plain_bytes: &[u8],
    nonce_bytes: Nonce,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher_bytes = match cipher.encrypt(&nonce_bytes, plain_bytes) {
        Ok(bytes_vec) => bytes_vec,
        Err(err) => {
            return Err(format!("Error during encryption: {}", err).into());
        }
    };

    Ok(cipher_bytes)
}

fn decrypt(
    cipher: &ChaCha20Poly1305,
    cipher_bytes: &[u8],
    nonce_bytes: Nonce,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let plain_bytes = match cipher.decrypt(&nonce_bytes, cipher_bytes) {
        Ok(bytes_vec) => bytes_vec,
        Err(err) => {
            return Err(format!("Error during encryption: {}", err).into());
        }
    };

    Ok(plain_bytes)
}

const CMD_I: usize = 1;
const FROM_I: usize = 2;
const TO_I: usize = 3;

const NONCE_BYTES_LEN: usize = 12;

fn run(args_vec_ref: &Vec<String>) -> Result<(), Box<dyn Error>> {
    let mut console_helper = ConsoleHelper::new()?;

    console_helper.print_tty(b"Secret Key (will not show): ")?;
    let cipher_key_bytes = read_secret_key_line_in_private()?;
    let cipher = ChaCha20Poly1305::new(&cipher_key_bytes);
    let nonce_bytes: Nonce = GenericArray::clone_from_slice(&cipher_key_bytes[..NONCE_BYTES_LEN]); // 96-bits;

    let (encrypt_flag, byte_string_flag) = if let Some(cmd_string_ref) = args_vec_ref.get(CMD_I) {
        if cmd_string_ref == "e" || cmd_string_ref == "encrypt" {
            (true, false)
        } else if cmd_string_ref == "d" || cmd_string_ref == "decrypt" {
            (false, false)
        } else if cmd_string_ref == "es" {
            (true, true)
        } else if cmd_string_ref == "ds" {
            (false, true)
        } else {
            return Err("It seems the first argument \"cmd\" is missing.... It's either \"e\" for encryption or \"d\" for decryption.".into());
        }
    } else {
        return Err("It seems the first argument \"cmd\" is missing.... It's either \"e\" for encryption or \"d\" for decryption.".into());
    };

    let from_file_path_pathbuf = if let Some(from_path_string_ref) = args_vec_ref.get(FROM_I) {
        let from_path_pathbuf_res = PathBuf::from_str(from_path_string_ref.as_str());
        if let Err(err) = from_path_pathbuf_res {
            return Err(
                format!("It seems the second argument is not a valid path: {}", err).into(),
            );
        }
        let from_path_pathbuf = unsafe { from_path_pathbuf_res.unwrap_unchecked() };
        if from_path_pathbuf.is_file() == false {
            return Err(format!(
                "It seems the second argument is not a path to a valid file. Path: {}",
                from_path_pathbuf.to_string_lossy()
            )
            .into());
        }
        from_path_pathbuf
    } else {
        return Err("It seems the second argument \"read from file path\" is missing...".into());
    };
    let to_file_path_pathbuf = if let Some(to_file_path_string_ref) = args_vec_ref.get(TO_I) {
        PathBuf::from_str(to_file_path_string_ref.as_str())?
    } else {
        let mut to_file_pathbuf = from_file_path_pathbuf.clone();
        let to_file_ext = unsafe { to_file_pathbuf.extension().unwrap_unchecked() }; //("Should have extension because checked");
        let mut new_ext = OsString::from(to_file_ext);
        if encrypt_flag {
            new_ext.push(".encrypted");
        } else {
            new_ext.push(".decrypted");
        }

        to_file_pathbuf.set_extension(&new_ext);
        to_file_pathbuf
    };

    let mut from_bytes_raw: Vec<u8> = Vec::new();
    let mut from_file = File::open(from_file_path_pathbuf)?;
    from_file.read_to_end(&mut from_bytes_raw)?;

    let to_bytes = if encrypt_flag {
        let to_bytes_raw = encrypt(&cipher, &from_bytes_raw, nonce_bytes)?;
        if byte_string_flag {
            ByteString::new(to_bytes_raw)
                .to_string()
                .as_bytes()
                .to_vec()
        } else {
            to_bytes_raw
        }
    } else {
        let from_bytes = if byte_string_flag {
            ByteString::try_from(String::from_utf8(from_bytes_raw)?.as_str())?.leak_bytes_vec()
        } else {
            from_bytes_raw
        };
        decrypt(&cipher, &from_bytes, nonce_bytes)?
    };

    save_file(to_file_path_pathbuf, &to_bytes)?;
    Ok(())
}

fn main() {
    let args_vec: Vec<String> = std::env::args().collect();
    if let Err(err_box) = run(&args_vec) {
        eprintln!("{}", err_box);
        std::process::exit(1);
    }
}
