use std::fs::File;
use std::io;
use std::path::Path;

use fs2::FileExt;

use Result;

/// A minimalistic flock-based mutex.
///
/// This just barely implements enough what we need from a mutex.
pub struct FlockMutexGuard {
    file: File,
}

impl FlockMutexGuard {
    pub fn lock(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        while let Err(e) = file.lock_exclusive() {
            // According to flock(2), possible errors returned are:
            //
            //   EBADF  fd is not an open file descriptor.
            //
            //   EINTR  While  waiting  to acquire a lock, the call
            //          was interrupted by delivery of a signal
            //          caught by a handler; see signal(7).
            //
            //   EINVAL operation is invalid.
            //
            //   ENOLCK The kernel ran out of memory for allocating
            //          lock records.
            //
            //   EWOULDBLOCK
            //          The file is locked and the LOCK_NB flag was
            //          selected.
            //
            // We entrust Rust's type system with keeping the file
            // handle valid, therefore flock should not fail with
            // EBADF.  We use only valid operations, we don't use
            // LOCK_NB, and we don't handle resource exhaustion.
            //
            // Therefore, only EINTR needs to be handled, which we do
            // by retrying.
            assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        }
        Ok(Self { file })
    }
}

impl Drop for FlockMutexGuard {
    fn drop(&mut self) {
        while let Err(e) = self.file.unlock() {
            // See above.
            assert_eq!(e.kind(), io::ErrorKind::Interrupted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn flock_dir() {
        let tempdir = TempDir::new().unwrap();
        let file = tempdir.path();

        assert!(File::open(file).unwrap().try_lock_exclusive().is_ok());
        let _lock = FlockMutexGuard::lock(file).unwrap();
        assert!(File::open(file).unwrap().try_lock_exclusive().is_err());
        assert!(File::open(file).unwrap().try_lock_shared().is_err());
    }

    #[test]
    fn flock_file() {
        let tempfile = NamedTempFile::new().unwrap();
        let file = tempfile.path();

        assert!(File::open(file).unwrap().try_lock_exclusive().is_ok());
        let _lock = FlockMutexGuard::lock(file).unwrap();
        assert!(File::open(file).unwrap().try_lock_exclusive().is_err());
        assert!(File::open(file).unwrap().try_lock_shared().is_err());
    }

    #[test]
    fn flock_drop() {
        let tempfile = NamedTempFile::new().unwrap();
        let file = tempfile.path();

        assert!(File::open(file).unwrap().try_lock_exclusive().is_ok());
        {
            let _lock = FlockMutexGuard::lock(file).unwrap();
            assert!(File::open(file).unwrap().try_lock_exclusive().is_err());
        }
        assert!(File::open(file).unwrap().try_lock_exclusive().is_ok());
    }

    #[test]
    fn flock_nonexistent() {
        assert!(FlockMutexGuard::lock("nonexistent").is_err());
    }
}
