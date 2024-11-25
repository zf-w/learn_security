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

#[path = "console_helper/console_helper.rs"]
mod console_helper_mod;
pub use console_helper_mod::ConsoleHelper;

#[path = "read_line_in_private.rs"]
mod read_line_in_private_mod;
pub use read_line_in_private_mod::{read_line_in_private, read_secret_key_from_line_in_private};
