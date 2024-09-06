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

use std::{
    fmt::{Display, Write},
    io::Bytes,
};

pub struct ByteString {
    bytes: Vec<u8>,
}

impl ByteString {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn leak_bytes_vec(self) -> Vec<u8> {
        self.bytes
    }
}

const UPPER_A_U8: u8 = 'A' as u8;

impl Display for ByteString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.bytes.iter().cloned() {
            f.write_char((UPPER_A_U8 + (byte >> 4)) as char)?;
            f.write_char((UPPER_A_U8 + (byte & 15)) as char)?;
        }
        Ok(())
    }
}

impl TryFrom<&str> for ByteString {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() % 2 == 1 {
            return Err("Odd len");
        }
        let bytes_len = value.len() / 2;
        let mut bytes: Vec<u8> = Vec::with_capacity(bytes_len);
        let mut is_first_half = true;
        let mut curr_byte: u8 = 0;
        for c in value.chars() {
            let curr_half_byte = c as u8 - UPPER_A_U8;
            if curr_half_byte > 15 {
                return Err("Invalid character...");
            }
            if is_first_half {
                curr_byte |= curr_half_byte << 4;
                is_first_half = false;
            } else {
                curr_byte |= curr_half_byte;
                bytes.push(curr_byte);
                curr_byte = 0;
                is_first_half = true;
            }
        }
        Ok(Self { bytes })
    }
}

impl TryFrom<Bytes<&[u8]>> for ByteString {
    type Error = std::io::Error;
    fn try_from(value: Bytes<&[u8]>) -> Result<Self, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();
        for byte_res in value {
            let byte = byte_res?;
            bytes.push(byte);
        }
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod tests {
    use crate::ByteString;

    #[test]
    fn check_to_string() {
        let bytestring = ByteString::new(vec![0, 1, 2, 3]);
        assert_eq!(bytestring.to_string(), "AAABACAD");
    }

    #[test]
    fn check_from_string() {
        let bytestring_res = ByteString::try_from("AAABACAD");
        assert!(bytestring_res.is_ok());
        let bytestring = bytestring_res.unwrap();
        assert_eq!(bytestring.to_string(), "AAABACAD");
    }

    #[test]
    fn check_from_string_1() {
        let bytestring_res = ByteString::try_from("HFKMAEMKKDBOOLIOMOKFJGHP");
        assert!(bytestring_res.is_ok());
        let bytestring = bytestring_res.unwrap();
        assert_eq!(bytestring.to_string(), "HFKMAEMKKDBOOLIOMOKFJGHP");
    }
}
