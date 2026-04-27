//! Stdout helpers: closed pipelines (EPIPE) must not panic or spuriously fail
//! real work — same convention as `rg` / `head`.

use anyhow::Result;

/// Write to stdout. [`std::io::ErrorKind::BrokenPipe`] is treated as success.
pub(crate) fn try_write_stdout(data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(data) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Wraps a [`std::io::Write`] so [`std::io::ErrorKind::BrokenPipe`] is treated
/// as a full, successful write. Use **only** for process stdout when the
/// consumer may close early — not for file handles.
pub(crate) struct SilenceBrokenPipe<W: std::io::Write> {
    pub(crate) inner: W,
}

impl<W: std::io::Write> std::io::Write for SilenceBrokenPipe<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(buf.len()),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(e),
        }
    }
}
