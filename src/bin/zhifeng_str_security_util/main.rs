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
    aead::{Aead, AeadCore, OsRng},
    ChaCha20Poly1305, Nonce,
};
use sha3::digest::generic_array::GenericArray;

use zhifeng_security_util::{
    pop_newline_from_string_mut_ref, read_secret_key_line_in_private, ByteString, ConsoleHelper,
    SafeString,
};

fn encrypt(
    cipher: &ChaCha20Poly1305,
    console_helper_mut_ref: &mut ConsoleHelper,
    md_flag: bool,
) -> Result<(), Box<dyn Error>> {
    let mut plain_string = SafeString::new();
    let mut curr_line_string = SafeString::new();
    let mut empty_count: usize = 0;

    while empty_count < 2 {
        std::io::stdin().read_line(&mut curr_line_string)?;
        pop_newline_from_string_mut_ref(&mut curr_line_string);
        if curr_line_string.len() == 0 {
            empty_count += 1;
        } else {
            empty_count = 0;
        }
        plain_string.push_str(&curr_line_string);
        plain_string.push('\n');
        curr_line_string.clear();
    }

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

    if md_flag {
        console_helper_mut_ref.print_tty(b"[(Encrypted)](#")?;
        console_helper_mut_ref.print_tty(&nonce_bytestring.to_string().as_bytes())?;
        console_helper_mut_ref.print_tty(&cipher_bytestring.to_string().as_bytes())?;
        console_helper_mut_ref.print_tty(b")\n")?;
    } else {
        console_helper_mut_ref.print_tty(&nonce_bytestring.to_string().as_bytes())?;
        console_helper_mut_ref.print_tty(&cipher_bytestring.to_string().as_bytes())?;
        console_helper_mut_ref.print_tty(b"\n")?;
    }

    Ok(())
}

const NONCE_BYTES_LEN: usize = 12;

fn decrypt(
    cipher: &ChaCha20Poly1305,
    console_helper_mut_ref: &mut ConsoleHelper,
) -> Result<(), Box<dyn Error>> {
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

    console_helper_mut_ref.print_tty(&plaintext_bytes)?;
    console_helper_mut_ref.print_tty(b"\n")?;
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut console_helper = ConsoleHelper::new()?;
    console_helper.print_tty(b"Secret Key (will not show): ")?;
    let cipher_key_bytes = read_secret_key_line_in_private()?;
    let cipher = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&cipher_key_bytes);

    let mut line_string = SafeString::new();

    while let Ok(_) = std::io::stdin().read_line(&mut line_string) {
        pop_newline_from_string_mut_ref(&mut line_string);
        if *line_string == "e" {
            encrypt(&cipher, &mut console_helper, false)?;
        } else if *line_string == "mde" {
            encrypt(&cipher, &mut console_helper, true)?;
        } else if *line_string == "d" {
            decrypt(&cipher, &mut console_helper)?;
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
