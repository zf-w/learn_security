// The Code Was Adapted from Rust Crate "rtoolbox = 0.0.2"

use std::{
    ops::{Deref, DerefMut},
    sync::atomic,
};

pub struct SafeString {
    inner: String,
}

impl SafeString {
    pub fn new_with_capacity(len: usize) -> Self {
        Self {
            inner: String::with_capacity(len),
        }
    }

    pub fn clear(&mut self) {
        for byte_mut_ref in unsafe { self.inner.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(byte_mut_ref, 0) };
        }
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
        self.inner.clear();
    }
}

impl From<String> for SafeString {
    fn from(value: String) -> Self {
        Self { inner: value }
    }
}

impl Drop for SafeString {
    fn drop(&mut self) {
        for byte_mut_ref in unsafe { self.inner.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(byte_mut_ref, 0) };
        }
        atomic::fence(atomic::Ordering::SeqCst); // Not understanding how this works exactly.
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Deref for SafeString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SafeString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
