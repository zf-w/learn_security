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

use std::{error::Error, fs::File, io::Write};

pub struct ConsoleHelper {
    tty_out: File,
}

impl ConsoleHelper {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let stream_file = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
        Ok(Self {
            tty_out: stream_file,
        })
    }

    pub fn print_tty(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        self.tty_out.write_all(buf)?;
        self.tty_out.flush()?;
        Ok(())
    }
}
