// The Code Was Adapted from Rust Crate "rtoolbox = 0.0.2"

pub fn pop_newline_from_string_mut_ref(string_mut_ref: &mut String) {
    if string_mut_ref.ends_with('\n') {
        string_mut_ref.pop();
    }
    if string_mut_ref.ends_with('\r') {
        string_mut_ref.pop();
    }
}

#[cfg(target_family = "wasm")]
mod wasm {
    use std::io::Write;

    /// Displays a message on the STDOUT
    pub fn print_tty(prompt: impl ToString) -> std::io::Result<()> {
        let mut stdout = std::io::stdout();
        write!(stdout, "{}", prompt.to_string().as_str())?;
        stdout.flush()?;
        Ok(())
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use std::io::Write;

    /// Displays a message on the TTY
    pub fn print_tty(prompt: impl ToString) -> std::io::Result<()> {
        let mut stream = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
        stream
            .write_all(prompt.to_string().as_str().as_bytes())
            .and_then(|_| stream.flush())
    }
}

#[cfg(target_family = "windows")]
mod windows {
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::core::PCSTR;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileA, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    /// Displays a message on the TTY
    pub fn print_tty(prompt: impl ToString) -> std::io::Result<()> {
        let handle = unsafe {
            CreateFileA(
                b"CONOUT$\x00".as_ptr() as PCSTR,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                INVALID_HANDLE_VALUE,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let mut stream = unsafe { std::fs::File::from_raw_handle(handle as _) };

        stream
            .write_all(prompt.to_string().as_str().as_bytes())
            .and_then(|_| stream.flush())
    }
}

#[cfg(target_family = "unix")]
pub use unix::print_tty;
#[cfg(target_family = "wasm")]
pub use wasm::print_tty;
#[cfg(target_family = "windows")]
pub use windows::print_tty;
