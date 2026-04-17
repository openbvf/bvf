use crate::errors::BvfError;
use libsodium_rs::utils::{mlock, munlock};
use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

/// For types whose memory can be mlocked and munlocked.
pub trait Lockable {
    /// Locks the memory region to prevent swapping.
    ///
    /// # Errors
    /// Returns `BvfError::MemoryLockFailed` if `mlock` fails.
    fn lock(&mut self) -> Result<(), BvfError>;

    /// Unlocks the memory region.
    ///
    /// # Errors
    /// Returns `BvfError::MemoryLockFailed` if `munlock` fails.
    fn unlock(&mut self) -> Result<(), BvfError>;
}

// Unsafe: not mutating, just passing mut ref
impl Lockable for String {
    fn lock(&mut self) -> Result<(), BvfError> {
        unsafe {
            let tolock = self.as_bytes_mut();
            mlock(tolock).map_err(|_| BvfError::MemoryLockFailed)?;
        }
        Ok(())
    }
    fn unlock(&mut self) -> Result<(), BvfError> {
        unsafe {
            let tolock = self.as_bytes_mut();
            munlock(tolock).map_err(|_| BvfError::MemoryLockFailed)?;
        }
        Ok(())
    }
}

impl Lockable for Vec<u8> {
    fn lock(&mut self) -> Result<(), BvfError> {
        let tolock = self.as_mut_slice();
        mlock(tolock).map_err(|_| BvfError::MemoryLockFailed)?;
        Ok(())
    }
    fn unlock(&mut self) -> Result<(), BvfError> {
        let tolock = self.as_mut_slice();
        munlock(tolock).map_err(|_| BvfError::MemoryLockFailed)?;
        Ok(())
    }
}

/// Wrapper for sensitive values: mlocked on creation, zeroized and munlocked on drop.
pub struct Locked<T: Lockable + Zeroize> {
    value: Zeroizing<T>,
}

impl<T: Lockable + Zeroize> Locked<T> {
    /// Wraps a value in memory-locked, zeroize-on-drop storage.
    ///
    /// # Errors
    /// Returns `BvfError::MemoryLockFailed` if `mlock` fails.
    pub fn new(thing: T) -> Result<Locked<T>, BvfError> {
        let mut zeroized_thing = Zeroizing::new(thing);
        zeroized_thing.lock()?;
        Ok(Locked {
            value: zeroized_thing,
        })
    }
}

impl<T: Lockable + Zeroize> Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: Lockable + Zeroize> Drop for Locked<T> {
    fn drop(&mut self) {
        let _ = self.value.unlock();
    }
}
