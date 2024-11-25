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

use std::io::BufRead;

#[path = "./io/io.rs"]
pub mod io;

pub use byte_string::ByteString;

#[path = "ciphers/ciphers.rs"]
pub mod ciphers_mod;

/// Setting everything to the default value.
pub fn write_volatile_to_all_elem_of_iter_to_default<'src, T: Default + 'src>(
    elem_mut_ref_iter: impl Iterator<Item = &'src mut T>,
) {
    for elem_mut_ref in elem_mut_ref_iter {
        unsafe { std::ptr::write_volatile(elem_mut_ref, T::default()) };
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

const MAGIC_CAPACITY_FOR_A_LINE: usize = 12;

/// Trying to safely read a line to a [String].
pub fn safely_read_line_from_buf_reader(mut buf_reader: impl BufRead) -> std::io::Result<String> {
    let mut buf: [u8; MAGIC_CAPACITY_FOR_A_LINE] = [0; MAGIC_CAPACITY_FOR_A_LINE];
    let mut line_string = String::with_capacity(MAGIC_CAPACITY_FOR_A_LINE);
    let mut endline_flag: bool = false;

    loop {
        let buf_size = buf_reader.read(&mut buf)?;
        let mut buf_string = String::from_utf8(buf[..buf_size].to_vec())
            .map_err(|_| std::io::Error::other("UTF-8 Error"))?;

        let line_len = line_string.len();
        let buf_len = buf_string.len();

        if line_len + buf_len < line_string.capacity() {
            let mut temp_string = line_string;
            line_string = String::with_capacity((line_len + buf_len) * 2);
            for temp_c in temp_string.chars() {
                line_string.push(temp_c);
            }
            write_volatile_to_all_elem_of_iter_to_default(unsafe {
                temp_string.as_bytes_mut().iter_mut()
            });
        }

        for c in buf_string.chars() {
            line_string.push(c);
            if c == '\n' {
                endline_flag = true;
                break;
            }
        }
        write_volatile_to_all_elem_of_iter_to_default(unsafe {
            buf_string.as_bytes_mut().iter_mut()
        });
        buf_string.clear();
        if endline_flag == true {
            break;
        }
    }

    write_volatile_to_all_elem_of_iter_to_default(buf.iter_mut());

    Ok(line_string)
}
