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

use std::{error::Error, io::Read};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    consts::U32,
    ChaCha20Poly1305, Nonce,
};
use sha3::{digest::generic_array::GenericArray, Digest, Sha3_256};

use zhifeng_security_util::{
    pop_newline_from_string_mut_ref, read_line_in_private, ByteString, SafeString,
};

fn read_secret_key_line_in_private() -> Result<GenericArray<u8, U32>, Box<dyn Error>> {
    let secret_string = match read_line_in_private() {
        Ok(secret_string) => secret_string,
        Err(_) => return Err("Error when reading the secret key.".into()),
    };

    let mut hasher = Sha3_256::new();
    hasher.update(secret_string.as_bytes());
    Ok(hasher.finalize())
}

fn encrypt(cipher: &ChaCha20Poly1305) -> Result<(), Box<dyn Error>> {
    let mut plain_string = SafeString::new();
    std::io::stdin().read_line(&mut plain_string)?;
    pop_newline_from_string_mut_ref(&mut plain_string);

    let nonce_bytes: Nonce = ChaCha20Poly1305::generate_nonce(OsRng);

    let cipher_bytes = match cipher.encrypt(&nonce_bytes, plain_string.as_bytes()) {
        Ok(bytes_vec) => bytes_vec,
        Err(err) => {
            return Err(format!("Error during encryption: {}", err).into());
        }
    };

    let cipher_bytestring = ByteString::new(cipher_bytes);
    let nonce_bytestring = ByteString::try_from(nonce_bytes.bytes())?;

    println!(
        "[(Encrypted)](#{}{})\n",
        nonce_bytestring, cipher_bytestring
    );

    Ok(())
}

const NONCE_BYTES_LEN: usize = 12;

fn decrypt(cipher: &ChaCha20Poly1305) -> Result<(), Box<dyn Error>> {
    let mut info_string = SafeString::new();
    std::io::stdin().read_line(&mut info_string)?;
    pop_newline_from_string_mut_ref(&mut info_string);

    let seq_i = NONCE_BYTES_LEN * 2;

    let cipher_bytestring = ByteString::try_from(&info_string[seq_i..])?;
    let nonce_bytestring = ByteString::try_from(&info_string[..seq_i])?;

    let nonce: Nonce = GenericArray::clone_from_slice(nonce_bytestring.as_bytes());

    let plaintext_bytes = match cipher.decrypt(&nonce, cipher_bytestring.as_bytes()) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(format!("Error when decrypting: {}", err).into());
        }
    };

    println!("{}", String::from_utf8(plaintext_bytes)?);
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let cipher_key_bytes = read_secret_key_line_in_private()?;
    let cipher = ChaCha20Poly1305::new(&cipher_key_bytes);

    let mut line_string = SafeString::new();

    while let Ok(_) = std::io::stdin().read_line(&mut line_string) {
        pop_newline_from_string_mut_ref(&mut line_string);
        if *line_string == "e" {
            encrypt(&cipher)?;
        } else if *line_string == "d" {
            decrypt(&cipher)?;
        } else {
            return Ok(());
        }
        line_string.clear();
    }
    Ok(())
}

fn main() {
    if let Err(err_box) = run() {
        eprintln!("{}", err_box);
        std::process::exit(1);
    }
}
