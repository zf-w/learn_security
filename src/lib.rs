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

mod byte_string;

use std::error::Error;

#[path = "./io/io.rs"]
pub mod io;

pub use byte_string::ByteString;

mod safe_string;

use chacha20poly1305::consts::U32;
pub use safe_string::SafeString;

use sha3::{digest::generic_array::GenericArray, Digest, Sha3_256};

pub fn read_secret_key_line_in_private() -> Result<GenericArray<u8, U32>, Box<dyn Error>> {
    let secret_string = match crate::io::read_line_in_private() {
        Ok(secret_string) => secret_string,
        Err(_) => return Err("Error when reading the secret key.".into()),
    };

    let mut hasher = Sha3_256::new();
    hasher.update(secret_string.as_bytes());
    Ok(hasher.finalize())
}

#[path = "ciphers/ciphers.rs"]
pub mod ciphers_mod;

pub fn write_volatile_to_all_bytes_of_iter_mut_with_zero<'src>(
    bytes_iter_mut: impl Iterator<Item = &'src mut u8>,
) {
    for byte_mut_ref in bytes_iter_mut {
        unsafe { std::ptr::write_volatile(byte_mut_ref, 0) };
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
