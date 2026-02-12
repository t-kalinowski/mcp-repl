use std::cell::Cell;
use std::io;
use std::sync::{Mutex, MutexGuard};

static OUTPUT_LOCK: Mutex<()> = Mutex::new(());
thread_local! {
    static OUTPUT_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn with_output_lock<T>(f: impl FnOnce() -> T) -> T {
    OUTPUT_DEPTH.with(|depth| {
        let _guard = OutputLockGuard::new(depth);
        f()
    })
}

struct OutputLockGuard<'a> {
    depth: &'a Cell<usize>,
    guard: Option<MutexGuard<'static, ()>>,
}

impl<'a> OutputLockGuard<'a> {
    fn new(depth: &'a Cell<usize>) -> Self {
        let guard = if depth.get() == 0 {
            Some(OUTPUT_LOCK.lock().unwrap())
        } else {
            None
        };
        depth.set(depth.get().saturating_add(1));
        Self { depth, guard }
    }
}

impl Drop for OutputLockGuard<'_> {
    fn drop(&mut self) {
        let current = self.depth.get();
        if current > 0 {
            self.depth.set(current - 1);
        }
        if self.depth.get() == 0 {
            self.guard.take();
        }
    }
}

pub(crate) fn write_stdout_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    with_output_lock(|| {
        let _ = write_fd(libc::STDOUT_FILENO, bytes);
    });
}

pub(crate) fn write_stderr_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    with_output_lock(|| {
        let _ = write_fd(libc::STDERR_FILENO, bytes);
    });
}

fn write_fd(fd: i32, bytes: &[u8]) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let chunk = &bytes[offset..];
        let result = unsafe { libc::write(fd, chunk.as_ptr().cast(), chunk.len()) };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        offset = offset.saturating_add(result as usize);
    }
    Ok(())
}
