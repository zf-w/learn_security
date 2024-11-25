// The Code Was Adapted from Rust Crate "rpassword = 7.3.1"

fn pop_newlines_from_string_mut_ref(string_mut_ref: &mut String) {
    while string_mut_ref.ends_with('\n') {
        string_mut_ref.pop();
        if string_mut_ref.ends_with('\r') {
            string_mut_ref.pop();
        }
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

    use crate::safely_read_line_from_buf_reader;

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
    #[inline]
    fn read_line_from_fd_with_hidden_input(
        reader: &mut impl BufRead,
        fd: i32,
    ) -> std::io::Result<String> {
        let hidden_input = HiddenInput::new(fd)?;

        let mut line_string = safely_read_line_from_buf_reader(reader)?;

        std::mem::drop(hidden_input);

        super::pop_newlines_from_string_mut_ref(&mut line_string);
        Ok(line_string)
    }

    /// Reads a line from the TTY
    pub fn read_line_in_private() -> std::io::Result<String> {
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

    use crate::safely_read_line_from_buf_reader;

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
    #[inline]
    fn read_line_from_handle_with_hidden_input(
        reader: &mut impl BufRead,
        handle: HANDLE,
    ) -> io::Result<String> {
        let hidden_input = HiddenInput::new(handle)?;

        let mut line_string = safely_read_line_from_buf_reader(reader)?;

        // Newline for windows which otherwise prints on the same line.
        println!();

        std::mem::drop(hidden_input);

        super::pop_newlines_from_string_mut_ref(&mut line_string);

        Ok(line_string)
    }

    /// Reads a line from the TTY
    pub fn read_line_in_private() -> std::io::Result<String> {
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

use sha3::Sha3_256;
#[cfg(target_family = "unix")]
pub use unix::read_line_in_private;

#[cfg(target_family = "windows")]
pub use windows::read_line_in_private;

/// Read a key in private.
pub fn read_secret_key_from_line_in_private() -> Result<
    sha3::digest::generic_array::GenericArray<
        u8,
        sha3::digest::generic_array::typenum::consts::U32,
    >,
    &'static str,
> {
    let mut secret_string = match crate::io_mod::read_line_in_private() {
        Ok(secret_string) => secret_string,
        Err(_) => return Err("Error when reading the secret key."),
    };

    let mut hasher = <Sha3_256 as sha3::Digest>::new();
    sha3::Digest::update(&mut hasher, secret_string.as_bytes());
    crate::write_volatile_to_all_elem_of_iter_to_default(unsafe {
        secret_string.as_bytes_mut().iter_mut()
    });
    Ok(sha3::Digest::finalize(hasher))
}
