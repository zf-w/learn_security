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

use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha3::{Digest, Sha3_256};

pub struct CipherV20241124 {
    chacha_cipher: ChaCha20Poly1305,
}

const VERSION_BYTES_LEN: usize = 4;
const NONCE_BYTES_LEN: usize = 12;
const TOTAL_ADDITIONAL_BYTES_LEN: usize = VERSION_BYTES_LEN + NONCE_BYTES_LEN;

const VERSION_BYTES: [u8; 4] = [0x01, 0x34, 0xda, 0xe4];

type CipherKeyBytes = sha3::digest::generic_array::GenericArray<
    u8,
    sha3::digest::generic_array::typenum::consts::U32,
>;

impl CipherV20241124 {
    /// Create the cipher with a passphrase &[str].
    pub fn new_with_passphrase(passphrase_str_ref: &str) -> Self {
        let mut hasher = Sha3_256::new();

        hasher.update(passphrase_str_ref.as_bytes());
        let cipher_key_bytes: CipherKeyBytes = hasher.finalize();
        let chacha_cipher = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&cipher_key_bytes);
        Self { chacha_cipher }
    }

    pub fn new_wtih_cipher_key_bytes(cipher_key_bytes: CipherKeyBytes) -> Self {
        let chacha_cipher = <ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&cipher_key_bytes);
        Self { chacha_cipher }
    }

    pub fn encrypt(&self, plain_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        let nonce_bytes: Nonce = <ChaCha20Poly1305 as chacha20poly1305::AeadCore>::generate_nonce(
            chacha20poly1305::aead::OsRng,
        );

        let cipher_bytes = match chacha20poly1305::aead::Aead::encrypt(
            &self.chacha_cipher,
            &nonce_bytes,
            plain_bytes,
        ) {
            Ok(bytes_vec) => bytes_vec,
            Err(_) => {
                return Err("Encryption failed...");
            }
        };
        let mut ans_bytes: Vec<u8> =
            Vec::with_capacity(cipher_bytes.len() + TOTAL_ADDITIONAL_BYTES_LEN);

        for byte_ref in VERSION_BYTES.iter() {
            ans_bytes.push(*byte_ref);
        }
        for nonce_byte in nonce_bytes.into_iter() {
            ans_bytes.push(nonce_byte);
        }
        for byte in cipher_bytes.into_iter() {
            ans_bytes.push(byte);
        }
        Ok(ans_bytes)
    }

    pub fn decrypt(&self, cipher_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        if cipher_bytes[..VERSION_BYTES_LEN] != VERSION_BYTES {
            return Err("The cipher bytes are not encrypted by v20241124...");
        }

        let nonce_bytes: Nonce = sha3::digest::generic_array::GenericArray::clone_from_slice(
            &cipher_bytes[VERSION_BYTES_LEN..TOTAL_ADDITIONAL_BYTES_LEN],
        );

        let plain_bytes = match chacha20poly1305::aead::Aead::decrypt(
            &self.chacha_cipher,
            &nonce_bytes,
            &cipher_bytes[TOTAL_ADDITIONAL_BYTES_LEN..],
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err("Decryption failed...");
            }
        };

        Ok(plain_bytes)
    }
}

#[cfg(test)]
mod tests_mod {
    use super::CipherV20241124;

    #[test]
    fn check_simple() {
        let cipher = CipherV20241124::new_with_passphrase("hahaha");
        let plain_bytes = b"Hello World!";
        let cipher_bytes_res = cipher.encrypt(plain_bytes.as_slice());
        assert!(cipher_bytes_res.is_ok());
        let cipher_bytes = cipher_bytes_res.unwrap();
        let decrypted_plain_bytes_res = cipher.decrypt(cipher_bytes.as_slice());
        assert!(decrypted_plain_bytes_res.is_ok());
        assert_eq!(decrypted_plain_bytes_res.unwrap(), plain_bytes);
    }
}
