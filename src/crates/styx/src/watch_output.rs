//! Bounded diagnostic output, with no detached pipe/TTY writer. A new Linux open
//! file description protects the shell's shared stdout flags from O_NONBLOCK.
//! Cancellation may abandon a frame; it never cancels Tokio filesystem work
//! already submitted to its blocking pool. finish() waits for that work and
//! reports incomplete framing rather than pretending the final JSON was sent.
#![cfg(target_os = "linux")]
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl, open},
    sys::stat::{Mode, SFlag, fstat},
    unistd::{Whence, lseek},
};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
};
use tokio::{
    fs,
    io::{AsyncWriteExt, unix::AsyncFd},
};
const MAX_FRAME: usize = 64 * 1024;

pub(crate) struct WatchOutput {
    sink: Sink,
    /// Remains set across cancellation/error: a later frame must not silently
    /// concatenate onto a partial JSON line. No caller input can clear it.
    in_progress: bool,
}
enum Sink {
    Pollable(AsyncFd<File>),
    Regular(fs::File),
}
struct Frame(Vec<u8>);
impl Write for Frame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n < MAX_FRAME)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "watch JSON frame exceeds 64KiB")
            })?;
        self.0.reserve(end - self.0.len());
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
impl WatchOutput {
    pub(crate) fn open() -> io::Result<Self> {
        let stdout = io::stdout();
        let original = fstat(&stdout).map_err(errno)?;
        let kind = SFlag::from_bits_truncate(original.st_mode);
        if kind != SFlag::S_IFREG && kind != SFlag::S_IFIFO && kind != SFlag::S_IFCHR {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stdout type cannot be safely reopened",
            ));
        }
        let original_flags =
            OFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFL).map_err(errno)?);
        let mut flags = OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC | OFlag::O_NOCTTY;
        // Opening /proc/self/fd/N creates a distinct OFD. Preserve append only
        // on that new OFD; never F_SETFL/dup a shell-shared description.
        if kind == SFlag::S_IFREG && original_flags.contains(OFlag::O_APPEND) {
            flags |= OFlag::O_APPEND;
        }
        let descriptor = open("/proc/self/fd/1", flags, Mode::empty()).map_err(errno)?;
        let observed = fstat(&descriptor).map_err(errno)?;
        if original.st_dev != observed.st_dev
            || original.st_ino != observed.st_ino
            || SFlag::from_bits_truncate(observed.st_mode) != kind
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reopened stdout identity changed",
            ));
        }
        let mut file = File::from(descriptor);
        let sink = if kind == SFlag::S_IFREG {
            // A regular reopen otherwise begins at offset zero and could
            // overwrite earlier diagnostic bytes. SEEK_CUR(0) reads the old
            // offset; seeking changes only the new description, not stdout.
            if !original_flags.contains(OFlag::O_APPEND) {
                let offset = u64::try_from(lseek(&stdout, 0, Whence::SeekCur).map_err(errno)?)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid stdout offset")
                    })?;
                file.seek(SeekFrom::Start(offset))?;
            }
            Sink::Regular(fs::File::from_std(file))
        } else {
            Sink::Pollable(AsyncFd::with_interest(
                file,
                tokio::io::Interest::WRITABLE | tokio::io::Interest::ERROR,
            )?)
        };
        Ok(Self {
            sink,
            in_progress: false,
        })
    }
    /// A pipe reader can disappear while discovery has no new event to emit.
    /// ERROR readiness waits without consuming keyboard data or busy-looping
    /// on ordinary WRITABLE readiness. Regular files have no remote consumer.
    pub(crate) async fn disconnected(&self) {
        match &self.sink {
            Sink::Pollable(file) => {
                let _ = file.ready(tokio::io::Interest::ERROR).await;
            }
            Sink::Regular(_) => std::future::pending::<()>().await,
        }
    }
    pub(crate) async fn write_json<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        if self.in_progress {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous watch output frame incomplete",
            ));
        }
        // Serialize completely within the cap before touching stdout. Reserve
        // a byte for newline. There is no unbounded intermediate to_vec/string.
        let mut frame = Frame(Vec::with_capacity(MAX_FRAME));
        serde_json::to_writer(&mut frame, value).map_err(|error| {
            io::Error::new(
                error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
                error,
            )
        })?;
        frame.0.push(b'\n');
        self.in_progress = true;
        match &mut self.sink {
            Sink::Regular(file) => {
                file.write_all(&frame.0).await?;
                // Tokio poll_write can acknowledge a submitted blocking job;
                // flush waits for the real job, not filesystem durability.
                file.flush().await?;
            }
            Sink::Pollable(file) => {
                let mut written = 0;
                while written < frame.0.len() {
                    let mut readiness = file.writable().await?;
                    match readiness.try_io(|inner| {
                        let mut output = inner.get_ref();
                        output.write(&frame.0[written..])
                    }) {
                        Ok(Ok(0)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "stdout made no progress",
                            ));
                        }
                        Ok(Ok(count)) => written += count,
                        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Ok(Err(error)) => return Err(error),
                        Err(_would_block) => continue,
                    }
                }
            }
        }
        self.in_progress = false;
        Ok(())
    }
    pub(crate) async fn finish(&mut self) -> io::Result<()> {
        if let Sink::Regular(file) = &mut self.sink {
            // A cancelled filesystem write may still be running. Keep the File
            // until it actually finishes; this wait has no hard-abort promise.
            file.flush().await?;
        }
        if self.in_progress {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "watch frame completion unconfirmed",
            ));
        }
        Ok(())
    }
}
