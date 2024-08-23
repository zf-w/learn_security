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

use sha3::{Digest, Sha3_256};

const BASE: u8 = 'A' as u8;
fn main() {
    let mut args_buf: String = String::with_capacity(100);
    let args_res = std::io::stdin().read_line(&mut args_buf);
    if let Err(e) = args_res {
        println!("An error has occurred: {}", e);
    }
    let mut hasher = Sha3_256::new();
    let args = args_buf.split_whitespace();
    for arg in args {
        hasher.update(arg);
    }
    let result = &hasher.finalize()[..];

    for byte in result.iter() {
        let c0 = ((byte & 15) + BASE) as char;
        let c1 = ((byte >> 4) + BASE) as char;
        print!("{}{}", c0, c1);
    }
}
