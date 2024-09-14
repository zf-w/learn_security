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

use std::{env, error::Error, io::Read};

use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    consts::U32,
    ChaCha20Poly1305, Nonce,
};
use sha3::{
    digest::{generic_array::GenericArray, DynDigest},
    Digest, Sha3_256,
};

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

fn hash(
    cipher_key_bytes: &GenericArray<u8, U32>,
    console_helper_mut_ref: &mut ConsoleHelper,
) -> Result<(), Box<dyn Error>> {
    let mut hasher = Sha3_256::new();
    DynDigest::update(&mut hasher, cipher_key_bytes);
    let mut input_string = SafeString::new();
    std::io::stdin().read_line(&mut input_string)?;
    pop_newline_from_string_mut_ref(&mut input_string);
    for part_str_ref in input_string.split(' ') {
        if part_str_ref.is_empty() {
            continue;
        }
        DynDigest::update(&mut hasher, part_str_ref.as_bytes());
    }
    let hash_res_bytes_vec = hasher.finalize().to_vec();
    let output_bytestring = ByteString::new(hash_res_bytes_vec);
    console_helper_mut_ref.print_tty(output_bytestring.to_string().as_bytes())?;
    console_helper_mut_ref.print_tty(b"\n")?;
    Ok(())
}

const INPUT_SECRET_KEY_PROMPT_STR_REF: &'static [u8] = b"Secret Key (will not show): ";

fn run() -> Result<(), Box<dyn Error>> {
    let mut console_helper = ConsoleHelper::new()?;
    let args: Vec<String> = env::args().collect();
    if let Some(first_arg_ref) = args.get(1) {
        if first_arg_ref == "-v" || first_arg_ref == "--version" {
            console_helper.print_tty(b"version: ")?;
            console_helper.print_tty(env!("CARGO_PKG_VERSION").as_bytes())?;
            return Ok(());
        }
    }

    console_helper.print_tty(INPUT_SECRET_KEY_PROMPT_STR_REF)?;
    let mut cipher_key_bytes = read_secret_key_line_in_private()?;
    let mut cipher = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&cipher_key_bytes);


    let mut line_string = SafeString::new();

    while let Ok(_) = std::io::stdin().read_line(&mut line_string) {
        pop_newline_from_string_mut_ref(&mut line_string);
        if *line_string == "d" || *line_string == "decrypt" {
            if let Err(e) = decrypt(&cipher, &mut console_helper) {
                console_helper.print_tty(e.to_string().as_bytes())?;
                console_helper.print_tty(b"\n")?;
            }
        } else if *line_string == "e" || *line_string == "encrypt" {
            encrypt(&cipher, &mut console_helper, false)?;
        } else if *line_string == "h" || *line_string == "hash" {
            hash(&cipher_key_bytes, &mut console_helper)?;
        } else if *line_string == "mde" || *line_string == "markdown_encrypt" {
            encrypt(&cipher, &mut console_helper, true)?;
        } else if *line_string == "s" || *line_string == "switch" {
            console_helper.print_tty(INPUT_SECRET_KEY_PROMPT_STR_REF)?;
            cipher_key_bytes = read_secret_key_line_in_private()?;
            cipher = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&cipher_key_bytes);
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
