// The Code Was Adapted from Rust Crate "rpassword = 7.3.1"

use crate::SafeString;

#[cfg(target_family = "wasm")]
mod wasm {
    use std::io::{self, BufRead};

    use crate::{pop_newline_from_string_mut_ref, SafeString};
    /// Reads a line from a given file descriptor
    fn read_line_from_fd_with_hidden_input(
        reader: &mut impl BufRead,
    ) -> std::io::Result<SafeString> {
        let mut line = super::SafeString::new();

        reader.read_line(&mut line)?;
        pop_newline_from_string_mut_ref(&mut line);

        Ok(line)
    }

    /// Reads a line from the TTY
    pub fn read_line() -> std::io::Result<SafeString> {
        let tty = std::fs::File::open("/dev/tty")?;
        let mut reader = io::BufReader::new(tty);

        read_line_from_fd_with_hidden_input(&mut reader)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use libc::{c_int, tcsetattr, termios, ECHO, ECHONL, TCSANOW};
    use std::os::unix::io::AsRawFd;
    use std::{
        io::{self, BufRead},
        mem,
    };

    use crate::{pop_newline_from_string_mut_ref, SafeString};

    struct HiddenInput {
        fd: i32,
        term_orig: termios,
    }

    impl HiddenInput {
        fn new(fd: i32) -> io::Result<HiddenInput> {
            // Make two copies of the terminal settings. The first one will be modified
            // and the second one will act as a backup for when we want to set the
            // terminal back to its original state.
            let mut term = safe_tcgetattr(fd)?;
            let term_orig = safe_tcgetattr(fd)?;

            // Hide the line. This is what makes this function useful.
            term.c_lflag &= !ECHO;

            // But don't hide the NL character when the user hits ENTER.
            term.c_lflag |= ECHONL;

            // Save the settings for now.
            io_result(unsafe { tcsetattr(fd, TCSANOW, &term) })?;

            Ok(HiddenInput { fd, term_orig })
        }
    }

    impl Drop for HiddenInput {
        fn drop(&mut self) {
            // Set the the mode back to normal
            unsafe {
                tcsetattr(self.fd, TCSANOW, &self.term_orig);
            }
        }
    }

    /// Turns a C function return into an IO Result
    fn io_result(ret: c_int) -> std::io::Result<()> {
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    fn safe_tcgetattr(fd: c_int) -> std::io::Result<termios> {
        let mut term = mem::MaybeUninit::<termios>::uninit();
        io_result(unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) })?;
        Ok(unsafe { term.assume_init() })
    }

    /// Reads a line from a given file descriptor
    fn read_line_from_fd_with_hidden_input(
        reader: &mut impl BufRead,
        fd: i32,
    ) -> std::io::Result<SafeString> {
        let mut line = super::SafeString::new();

        let hidden_input = HiddenInput::new(fd)?;

        reader.read_line(&mut line)?;

        std::mem::drop(hidden_input);

        pop_newline_from_string_mut_ref(&mut line);
        Ok(line)
    }

    /// Reads a line from the TTY
    pub fn read_line_in_private() -> std::io::Result<SafeString> {
        let tty = std::fs::File::open("/dev/tty")?;
        let fd = tty.as_raw_fd();
        let mut reader = io::BufReader::new(tty);

        read_line_from_fd_with_hidden_input(&mut reader, fd)
    }
}

#[cfg(target_family = "windows")]
mod windows {
    use std::io::BufRead;
    use std::io::{self, BufReader};
    use std::os::windows::io::FromRawHandle;

    use windows_sys::{
        core::PCSTR,
        Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{CreateFileA, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
            System::Console::{
                GetConsoleMode, SetConsoleMode, CONSOLE_MODE, ENABLE_LINE_INPUT,
                ENABLE_PROCESSED_INPUT,
            },
        },
    };

    use crate::{util::pop_newline_from_string_mut_ref, SafeString};

    struct HiddenInput {
        mode: u32,
        handle: HANDLE,
    }

    impl HiddenInput {
        fn new(handle: HANDLE) -> io::Result<HiddenInput> {
            let mut mode = 0;

            // Get the old mode so we can reset back to it when we are done
            if unsafe { GetConsoleMode(handle, &mut mode as *mut CONSOLE_MODE) } == 0 {
                return Err(std::io::Error::last_os_error());
            }

            // We want to be able to read line by line, and we still want backspace to work
            let new_mode_flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if unsafe { SetConsoleMode(handle, new_mode_flags) } == 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(HiddenInput { mode, handle })
        }
    }

    impl Drop for HiddenInput {
        fn drop(&mut self) {
            // Set the the mode back to normal
            unsafe {
                SetConsoleMode(self.handle, self.mode);
            }
        }
    }

    /// Reads a line from a given file handle
    fn read_line_from_handle_with_hidden_input(
        reader: &mut impl BufRead,
        handle: HANDLE,
    ) -> io::Result<SafeString> {
        let mut line = super::SafeString::new();

        let hidden_input = HiddenInput::new(handle)?;

        let reader_return = reader.read_line(&mut line);

        // Newline for windows which otherwise prints on the same line.
        println!();

        if reader_return.is_err() {
            return Err(reader_return.unwrap_err());
        }

        std::mem::drop(hidden_input);

        pop_newline_from_string_mut_ref(&mut line);

        Ok(line)
    }

    /// Reads a line from the TTY
    pub fn read_line_in_private() -> std::io::Result<SafeString> {
        let handle = unsafe {
            CreateFileA(
                b"CONIN$\x00".as_ptr() as PCSTR,
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

        let mut stream = BufReader::new(unsafe { std::fs::File::from_raw_handle(handle as _) });
        read_line_from_handle_with_hidden_input(&mut stream, handle)
    }
}

#[cfg(target_family = "unix")]
pub use unix::read_line_in_private;
#[cfg(target_family = "wasm")]
pub use wasm::read_line_in_private;
#[cfg(target_family = "windows")]
pub use windows::read_line_in_private;
