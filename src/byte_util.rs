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

//! # Byte Utility Module
//!
//! This module is about reading byte strings into [Vec<u8>] or [[u8]] and writing bytes into [String];

const MAGIC_VEC_INIT_CAPACITY: usize = 128;

const CHAR_0_U8: u8 = b'0';
const CHAR_9_U8: u8 = b'9';
const CHAR_LOWER_A_U8: u8 = b'a';
const CHAR_LOWER_F_U8: u8 = b'f';
const CHAR_LOWER_P_U8: u8 = b'p';
const CHAR_UPPER_A_U8: u8 = b'A';
const CHAR_UPPER_F_U8: u8 = b'F';
const CHAR_UPPER_P_U8: u8 = b'P';

#[inline]
fn hex_char_u8_to_u8(c_u8: u8) -> Result<u8, &'static str> {
    if (CHAR_0_U8..=CHAR_9_U8).contains(&c_u8) {
        Ok(c_u8 - CHAR_0_U8)
    } else if (CHAR_LOWER_A_U8..=CHAR_LOWER_F_U8).contains(&c_u8) {
        Ok(10 + c_u8 - CHAR_LOWER_A_U8)
    } else if (CHAR_UPPER_A_U8..=CHAR_UPPER_F_U8).contains(&c_u8) {
        Ok(10 + c_u8 - CHAR_UPPER_A_U8)
    } else {
        Err("Not a valid hex char...")
    }
}

pub fn make_byte_arr_from_hex_str_ref<const L: usize>(
    hex_str_ref: &str,
) -> Result<[u8; L], &'static str> {
    let mut str_char_iter = hex_str_ref.chars();
    let mut ans_bytes: [u8; L] = [0; L];
    for byte_mut_ref in ans_bytes.iter_mut() {
        if let Some(first_half_u4_char) = str_char_iter.next() {
            *byte_mut_ref |= hex_char_u8_to_u8(first_half_u4_char as u8)? << 4;
        } else {
            return Err("Str not long enough");
        }
        if let Some(second_half_u4_char) = str_char_iter.next() {
            *byte_mut_ref |= hex_char_u8_to_u8(second_half_u4_char as u8)?;
        } else {
            return Err("Str not long enough, not even.");
        }
    }
    Ok(ans_bytes)
}

pub fn make_byte_vec_from_hex_str_ref(hex_str_ref: &str) -> Result<Vec<u8>, &'static str> {
    let mut char_u8_iter = hex_str_ref.as_bytes().iter().cloned();
    let mut ans_byte_vec: Vec<u8> = Vec::with_capacity(MAGIC_VEC_INIT_CAPACITY);
    loop {
        let mut curr_byte: u8 = 0;
        if let Some(first_half_u4_char) = char_u8_iter.next() {
            curr_byte |= hex_char_u8_to_u8(first_half_u4_char)? << 4;
        } else {
            break;
        }
        if let Some(second_half_u4_char) = char_u8_iter.next() {
            curr_byte |= hex_char_u8_to_u8(second_half_u4_char)?;
        } else {
            return Err("Str len not even.");
        }
        ans_byte_vec.push(curr_byte);
    }
    Ok(ans_byte_vec)
}

pub fn make_hex_byte_string_from_bytes_ref(hex_bytes_ref: &[u8]) -> String {
    fn u8_to_hex_char(byte: u8) -> char {
        if byte < 10 {
            (CHAR_0_U8 + byte) as char
        } else if byte < 16 {
            (CHAR_LOWER_A_U8 + (byte - 10)) as char
        } else {
            'z'
        }
    }
    let mut ans_string: String = String::with_capacity(hex_bytes_ref.len());
    for byte in hex_bytes_ref {
        let first_half = byte >> 4;
        let second_half = byte & 0b1111;

        ans_string.push(u8_to_hex_char(first_half));
        ans_string.push(u8_to_hex_char(second_half));
    }
    ans_string
}

#[inline]
fn letter_char_u8_to_u8(c_u8: u8) -> Result<u8, &'static str> {
    if (CHAR_LOWER_A_U8..=CHAR_LOWER_P_U8).contains(&c_u8) {
        Ok(c_u8 - CHAR_LOWER_A_U8)
    } else if (CHAR_UPPER_A_U8..=CHAR_UPPER_P_U8).contains(&c_u8) {
        Ok(c_u8 - CHAR_UPPER_A_U8)
    } else {
        Err("Not a valid char for letter byte str...")
    }
}

pub fn make_byte_arr_from_letter_str_ref<const L: usize>(
    letter_str_ref: &str,
) -> Result<[u8; L], &'static str> {
    let mut str_char_iter = letter_str_ref.chars();
    let mut ans_bytes: [u8; L] = [0; L];
    for byte_mut_ref in ans_bytes.iter_mut() {
        if let Some(first_half_u4_char) = str_char_iter.next() {
            *byte_mut_ref |= letter_char_u8_to_u8(first_half_u4_char as u8)? << 4;
        } else {
            return Err("Str not long enough");
        }
        if let Some(second_half_u4_char) = str_char_iter.next() {
            *byte_mut_ref |= letter_char_u8_to_u8(second_half_u4_char as u8)?;
        } else {
            return Err("Str not long enough, not even.");
        }
    }
    Ok(ans_bytes)
}

pub fn make_byte_vec_from_letter_str_ref(letter_str_ref: &str) -> Result<Vec<u8>, &'static str> {
    let mut char_u8_iter = letter_str_ref.as_bytes().iter().cloned();
    let mut ans_byte_vec: Vec<u8> = Vec::with_capacity(MAGIC_VEC_INIT_CAPACITY);
    loop {
        let mut curr_byte: u8 = 0;
        if let Some(first_half_u4_char) = char_u8_iter.next() {
            curr_byte |= letter_char_u8_to_u8(first_half_u4_char)? << 4;
        } else {
            break;
        }
        if let Some(second_half_u4_char) = char_u8_iter.next() {
            curr_byte |= letter_char_u8_to_u8(second_half_u4_char)?;
        } else {
            return Err("Str len not even.");
        }
        ans_byte_vec.push(curr_byte);
    }
    Ok(ans_byte_vec)
}

pub fn make_letter_byte_string_from_bytes_ref(bytes_ref: &[u8]) -> String {
    let mut ans_string = String::with_capacity(bytes_ref.len() * 2);
    for byte_ref in bytes_ref {
        ans_string.push((CHAR_UPPER_A_U8 + (byte_ref >> 4)) as char);
        ans_string.push((CHAR_UPPER_A_U8 + (byte_ref & 15)) as char);
    }
    ans_string
}

#[cfg(test)]
mod texts_mod {
    use crate::byte_util_mod::{
        make_byte_arr_from_hex_str_ref, make_byte_arr_from_letter_str_ref,
        make_byte_vec_from_hex_str_ref, make_byte_vec_from_letter_str_ref,
        make_hex_byte_string_from_bytes_ref, make_letter_byte_string_from_bytes_ref,
    };

    #[test]
    fn check_from_letters_str() {
        let byte_arr_res = make_byte_arr_from_letter_str_ref::<4>("AAABACAD");
        assert!(byte_arr_res.is_ok());
        assert_eq!(
            make_letter_byte_string_from_bytes_ref(&byte_arr_res.unwrap()),
            "AAABACAD"
        );
    }

    #[test]
    fn check_from_letters_str_case_mixed_lower() {
        let byte_arr_res = make_byte_arr_from_letter_str_ref::<4>("AaaBACAD");
        assert!(byte_arr_res.is_ok());
        assert_eq!(
            make_letter_byte_string_from_bytes_ref(&byte_arr_res.unwrap()),
            "AAABACAD"
        );
    }

    #[test]
    fn check_from_letters_str_to_byte_vec() {
        let byte_arr_res = make_byte_vec_from_letter_str_ref("AaaBACAD");
        assert!(byte_arr_res.is_ok());
        assert_eq!(
            make_letter_byte_string_from_bytes_ref(&byte_arr_res.unwrap()),
            "AAABACAD"
        );
    }

    #[test]
    fn check_from_hex_str() {
        let byte_arr_res = make_byte_arr_from_hex_str_ref::<4>("1AfFff9c");
        assert!(byte_arr_res.is_ok());
        assert_eq!(
            make_hex_byte_string_from_bytes_ref(&byte_arr_res.unwrap()),
            "1affff9c"
        );
    }

    #[test]
    fn check_from_hex_str_to_byte_vec() {
        let byte_arr_res = make_byte_vec_from_hex_str_ref("1AffFf9c");
        assert!(byte_arr_res.is_ok());
        assert_eq!(
            make_hex_byte_string_from_bytes_ref(&byte_arr_res.unwrap()),
            "1affff9c"
        );
    }
}
