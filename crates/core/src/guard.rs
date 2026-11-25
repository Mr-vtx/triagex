//! Hang protection. Triagex is the tool you run when a server is unhealthy, so it must not
//! be the thing that hangs with it. Everything here exists to turn "blocked forever" into
//! "skipped, with a reason":
//!
//! - a total-run deadline: cooperative (`clamp`, `expired`) plus a hard watchdog as the last resort;
//! - `run_command`: a child process with a deadline that never waits on a killed child;
//! - `unix_connect`: a Unix-socket connect that cannot block on a full or wedged listener;
//! - `GuardedReader`: reads on a helper thread, so a dead disk or mount costs a timeout, not the run;
//! - `run_with_timeout`: the same idea for any single blocking call (`statvfs`, for one);
//! - `hang_prone_mounts`: network and automounted filesystems a directory walk must not enter.
//!
//! A thread stuck in the kernel cannot be cancelled from user space. When a guarded call
//! times out, its helper thread is abandoned (it exits whenever the call finally returns)
//! and the run carries on without it.

use std::{
    collections::HashMap,
    io::{self, Read},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

/// Exit code of the watchdog, the same one `timeout(1)` uses.
pub const WATCHDOG_EXIT_CODE: i32 = 124;

/// How long a finished command may keep its output pipes open (a daemonised grandchild
/// inherits them) before we stop waiting for more output.
const OUTPUT_GRACE: Duration = Duration::from_millis(500);
/// How long to wait for a SIGKILLed child to disappear before leaving it to a reaper thread.
const KILL_GRACE: Duration = Duration::from_millis(300);
const CHUNK: usize = 64 * 1024;

// ------------------------------ total-run deadline ------------------------------

static RUN_DEADLINE: OnceLock<Instant> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);

/// Starts the clock for the whole run. Collectors shorten their own timeouts to fit
/// (`clamp`) and skip themselves once it has passed (`expired`). Only the first call counts.
pub fn set_run_deadline(total: Duration) {
    RUN_DEADLINE.set(Instant::now() + total).ok();
}

/// Time left in the run, or None when no deadline is set.
pub fn remaining() -> Option<Duration> {
    RUN_DEADLINE
        .get()
        .map(|d| d.saturating_duration_since(Instant::now()))
}

pub fn expired() -> bool {
    remaining().is_some_and(|r| r.is_zero())
}

fn clamp_to(timeout: Duration, remaining: Option<Duration>) -> Duration {
    let t = match remaining {
        Some(r) => timeout.min(r),
        None => timeout,
    };
    // Never zero: `connect_timeout` and `set_read_timeout` reject a zero duration.
    t.max(Duration::from_millis(1))
}

/// A per-operation timeout, shortened so it cannot outlast the run deadline.
pub fn clamp(timeout: Duration) -> Duration {
    clamp_to(timeout, remaining())
}

/// Starts the run deadline and a watchdog thread. If the run is still going `grace` after the
/// deadline, something is blocked in a way no timeout caught: print why and exit with 124
/// instead of hanging. Call `disarm` once collection is done, so reading the output in a
/// pager is never cut short.
pub fn arm_watchdog(total: Duration, grace: Duration) {
    set_run_deadline(total);
    ARMED.store(true, Ordering::SeqCst);
    let limit = total + grace;
    thread::Builder::new()
        .name("triagex-watchdog".into())
        .spawn(move || {
            let start = Instant::now();
            while ARMED.load(Ordering::SeqCst) {
                if start.elapsed() >= limit {
                    eprintln!(
                        "triagex: still running {} s after the {} s run deadline; something is not responding (a hung mount or process?). Exiting.",
                        grace.as_secs(),
                        total.as_secs()
                    );
                    // SAFETY: _exit ends the process immediately and touches no Rust state.
                    unsafe { libc::_exit(WATCHDOG_EXIT_CODE) };
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
        .ok();
}

/// Stops the watchdog. Output printing is not covered by the deadline.
pub fn disarm() {
    ARMED.store(false, Ordering::SeqCst);
}

// ------------------------------ one blocking call ------------------------------

/// Runs `f` on a helper thread and waits at most `timeout` (shortened to the run deadline).
/// None means it did not finish; the thread is left behind and ends when `f` returns.
pub fn run_with_timeout<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("triagex-guarded".into())
        .spawn(move || {
            tx.send(f()).ok();
        })
        .ok()?;
    rx.recv_timeout(clamp(timeout)).ok()
}

// ------------------------------ child processes ------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// stdout and stderr, in that order, the way `nginx -t` output is parsed.
    pub fn combined(&self) -> String {
        [self.stdout.as_str(), self.stderr.as_str()].join("\n")
    }
}

/// Kills the child and reaps it without ever blocking: a process in uninterruptible sleep
/// (dead storage, usually) survives SIGKILL, so if it is still there after a short grace
/// it is handed to a thread that waits for it.
pub fn reap(mut child: Child) {
    child.kill().ok();
    let until = Instant::now() + KILL_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        if Instant::now() >= until {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    thread::Builder::new()
        .name("triagex-reaper".into())
        .spawn(move || {
            child.wait().ok();
        })
        .ok();
}

/// Waits for a child to exit, at most `timeout`. True means it exited. On false the caller
/// should `reap` it.
pub fn wait_timeout(child: &mut Child, timeout: Duration) -> bool {
    let until = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) => {}
        }
        if Instant::now() >= until {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Runs a command to completion with a deadline and returns its output (each stream capped
/// at `max_bytes`). Ok(None) means the deadline passed and the child was killed.
///
/// Neither a killed child nor a daemonised grandchild holding the output pipes open can make
/// this wait: the child is reaped by `reap`, and output that has not arrived `OUTPUT_GRACE`
/// after the child exited is left behind.
pub fn run_command(
    mut cmd: Command,
    timeout: Duration,
    max_bytes: usize,
) -> io::Result<Option<Output>> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    // (is_stderr, Some(bytes) for data or None for end of stream)
    let (tx, rx) = mpsc::channel::<(bool, Option<Vec<u8>>)>();
    let mut streams = 0;
    if let Some(o) = child.stdout.take() {
        spawn_pipe_reader(o, false, max_bytes, tx.clone());
        streams += 1;
    }
    if let Some(e) = child.stderr.take() {
        spawn_pipe_reader(e, true, max_bytes, tx.clone());
        streams += 1;
    }
    drop(tx);

    let deadline = Instant::now() + clamp(timeout);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                reap(child);
                return Err(e);
            }
        }
        if Instant::now() >= deadline {
            reap(child);
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    };

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let drain_until = Instant::now() + OUTPUT_GRACE;
    while streams > 0 {
        let left = drain_until.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((is_err, Some(bytes))) => {
                let dst = if is_err { &mut err } else { &mut out };
                let room = max_bytes.saturating_sub(dst.len());
                dst.extend_from_slice(&bytes[..bytes.len().min(room)]);
            }
            Ok((_, None)) => streams -= 1,
            Err(_) => break,
        }
    }
    Ok(Some(Output {
        success: status.success(),
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }))
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut pipe: R,
    is_err: bool,
    max_bytes: usize,
    tx: mpsc::Sender<(bool, Option<Vec<u8>>)>,
) {
    let spawned = thread::Builder::new().name("triagex-pipe".into()).spawn({
        let tx = tx.clone();
        move || {
            let mut buf = vec![0u8; 8192];
            let mut total = 0usize;
            while total < max_bytes {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if tx.send((is_err, Some(buf[..n].to_vec()))).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            tx.send((is_err, None)).ok();
        }
    });
    if spawned.is_err() {
        // No thread, no output from this stream: say it ended so nothing waits for it.
        tx.send((is_err, None)).ok();
    }
}

// ------------------------------ sockets ------------------------------

/// `UnixStream::connect` with a timeout. The standard one blocks without limit when the
/// listener's backlog is full, which is exactly what a wedged daemon looks like (docker and
/// redis sockets). A non-blocking connect to a full backlog fails with EAGAIN; this retries
/// that for up to `timeout` and then reports `TimedOut`.
pub fn unix_connect(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain data; all-zero is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is too long or contains a NUL byte",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;

    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor that nothing else owns; OwnedFd closes it on drop.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `addr` outlives the call and `len` covers exactly the bytes filled in above.
        let rc = unsafe {
            libc::connect(
                raw,
                (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                len,
            )
        };
        if rc == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the socket did not accept the connection in time (is the daemon hung?)",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            _ => return Err(err),
        }
    }

    // Reads and writes after this point use the stream's own timeouts, so go back to blocking.
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 || libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(UnixStream::from(fd))
}

/// Test helper: a listening Unix socket with backlog 0 that never calls accept(). Once its one
/// queued slot is taken, any further connect() would block forever, like a wedged daemon's.
#[cfg(test)]
pub(crate) fn wedged_listener(path: &Path) -> OwnedFd {
    // SAFETY: plain socket calls on a descriptor owned (and closed) by the returned OwnedFd.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (d, s) in addr.sun_path.iter_mut().zip(path.as_os_str().as_bytes()) {
            *d = *s as libc::c_char;
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + path.as_os_str().len() + 1)
            as libc::socklen_t;
        assert_eq!(
            libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len),
            0
        );
        assert_eq!(libc::listen(fd, 0), 0);
        OwnedFd::from_raw_fd(fd)
    }
}

// ------------------------------ guarded reads ------------------------------

/// A reader whose reads happen on a helper thread. If no data arrives for `stall` (or the
/// optional `deadline` passes, or the run deadline does), `read` fails with `TimedOut`
/// instead of blocking. Opening is done on the helper thread too, because `open(2)` on a hung
/// mount blocks just as hard as `read(2)`.
pub struct GuardedReader {
    rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
    stall: Duration,
    deadline: Option<Instant>,
}

impl GuardedReader {
    pub fn spawn<R: Read + Send + 'static>(
        open: impl FnOnce() -> io::Result<R> + Send + 'static,
        stall: Duration,
        deadline: Option<Instant>,
    ) -> io::Result<Self> {
        // A small bound keeps memory flat: the helper waits when the consumer is behind.
        let (tx, rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(8);
        thread::Builder::new()
            .name("triagex-read".into())
            .spawn(move || {
                let mut source = match open() {
                    Ok(s) => s,
                    Err(e) => {
                        tx.send(Err(e)).ok();
                        return;
                    }
                };
                let mut buf = vec![0u8; CHUNK];
                loop {
                    match source.read(&mut buf) {
                        // Dropping the sender is how the reading side learns it is the end.
                        Ok(0) => return,
                        Ok(n) => {
                            if tx.send(Ok(buf[..n].to_vec())).is_err() {
                                return;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            tx.send(Err(e)).ok();
                            return;
                        }
                    }
                }
            })?;
        Ok(GuardedReader {
            rx,
            buf: Vec::new(),
            pos: 0,
            stall,
            deadline,
        })
    }
}

impl Read for GuardedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            let mut wait = clamp(self.stall);
            if let Some(d) = self.deadline {
                wait = wait.min(d.saturating_duration_since(Instant::now()));
            }
            match self.rx.recv_timeout(wait.max(Duration::from_millis(1))) {
                Ok(Ok(chunk)) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let why = if expired() {
                        "the run deadline passed".to_string()
                    } else if self.deadline.is_some_and(|d| Instant::now() >= d) {
                        "it took too long".to_string()
                    } else {
                        format!(
                            "no data for {} s; the storage or process may be hung",
                            self.stall.as_secs().max(1)
                        )
                    };
                    return Err(io::Error::new(io::ErrorKind::TimedOut, why));
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

// ------------------------------ mounts ------------------------------

/// Filesystems whose `stat`, `open` and `readdir` can block for as long as the server on the
/// other end is unreachable (or, for autofs, trigger a mount that blocks).
pub fn is_hang_prone_fs(fstype: &str) -> bool {
    let t = fstype.to_ascii_lowercase();
    t.starts_with("nfs")
        || t.starts_with("fuse.")
        || matches!(
            t.as_str(),
            "autofs"
                | "cifs"
                | "smb3"
                | "smbfs"
                | "afs"
                | "ceph"
                | "glusterfs"
                | "lustre"
                | "gpfs"
                | "beegfs"
                | "orangefs"
                | "9p"
                | "ncpfs"
                | "davfs"
                | "fuse"
        )
}

fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = u32::from(b[i + 1] - b'0') * 64
                + u32::from(b[i + 2] - b'0') * 8
                + u32::from(b[i + 3] - b'0');
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mount points (path, filesystem type) from the text of `/proc/self/mountinfo`.
pub fn parse_mountinfo(text: &str) -> Vec<(PathBuf, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mount = left.split_whitespace().nth(4)?;
            let fstype = right.split_whitespace().next()?;
            Some((PathBuf::from(unescape_octal(mount)), fstype.to_string()))
        })
        .collect()
}

/// Every mount point on this machine whose filesystem can hang, with its type. Reading
/// `/proc/self/mountinfo` touches no mounted storage, so this cannot hang itself. Empty if
/// the file cannot be read.
pub fn hang_prone_mounts() -> HashMap<PathBuf, String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| {
            parse_mountinfo(&t)
                .into_iter()
                .filter(|(_, fs)| is_hang_prone_fs(fs))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::BufRead, os::unix::net::UnixListener};

    fn tmp_sock(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("triagex-guard-{}-{name}.sock", std::process::id()));
        std::fs::remove_file(&p).ok();
        p
    }

    #[test]
    fn clamp_never_exceeds_what_is_left_and_never_hits_zero() {
        let s = Duration::from_secs;
        assert_eq!(clamp_to(s(5), None), s(5));
        assert_eq!(clamp_to(s(5), Some(s(2))), s(2));
        assert_eq!(clamp_to(s(5), Some(s(9))), s(5));
        assert_eq!(
            clamp_to(s(5), Some(Duration::ZERO)),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn a_command_that_hangs_is_killed_at_the_deadline() {
        let t = Instant::now();
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        let r = run_command(cmd, Duration::from_millis(200), 1024).unwrap();
        assert!(r.is_none());
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_command_finishes_with_its_output() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo out; echo err >&2; exit 3"]);
        let o = run_command(cmd, Duration::from_secs(5), 1024)
            .unwrap()
            .unwrap();
        assert!(!o.success);
        assert_eq!(o.stdout.trim(), "out");
        assert_eq!(o.stderr.trim(), "err");
        assert_eq!(o.combined().trim(), "out\n\nerr");
    }

    #[test]
    fn a_grandchild_holding_the_pipes_does_not_hold_us() {
        // `sleep` is left running in the background with our stdout open. The command itself
        // exits at once; waiting for end-of-stream would take 30 s.
        let t = Instant::now();
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30 & echo hello"]);
        let o = run_command(cmd, Duration::from_secs(5), 1024)
            .unwrap()
            .unwrap();
        assert!(o.success);
        assert_eq!(o.stdout.trim(), "hello");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "took {:?}",
            t.elapsed()
        );
    }

    #[test]
    fn output_is_capped() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "head -c 100000 /dev/zero | tr '\\0' 'a'"]);
        let o = run_command(cmd, Duration::from_secs(5), 1000)
            .unwrap()
            .unwrap();
        assert_eq!(o.stdout.len(), 1000);
    }

    #[test]
    fn a_missing_binary_is_an_error_not_a_timeout() {
        let e = run_command(
            Command::new("/nonexistent/triagex-test"),
            Duration::from_secs(1),
            10,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn run_with_timeout_returns_the_value_or_gives_up() {
        assert_eq!(run_with_timeout(Duration::from_secs(2), || 7), Some(7));
        let t = Instant::now();
        let r = run_with_timeout(Duration::from_millis(100), || {
            thread::sleep(Duration::from_secs(5));
            1
        });
        assert_eq!(r, None);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn unix_connect_reaches_a_listener() {
        let path = tmp_sock("ok");
        let _l = UnixListener::bind(&path).unwrap();
        assert!(unix_connect(&path, Duration::from_secs(1)).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unix_connect_reports_a_missing_socket() {
        let e = unix_connect(
            Path::new("/nonexistent/triagex.sock"),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn unix_connect_gives_up_on_a_full_backlog() {
        let path = tmp_sock("full");
        let listener = wedged_listener(&path);

        let t = Instant::now();
        let mut kept = Vec::new();
        let mut timed_out = false;
        for _ in 0..4 {
            match unix_connect(&path, Duration::from_millis(150)) {
                Ok(s) => kept.push(s),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
                    timed_out = true;
                    break;
                }
            }
        }
        assert!(
            timed_out,
            "every connect succeeded; the backlog never filled"
        );
        assert!(t.elapsed() < Duration::from_secs(3));
        drop(listener);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_guarded_reader_delivers_lines() {
        let data: &'static [u8] = b"one\ntwo\nthree";
        let r = GuardedReader::spawn(move || Ok(data), Duration::from_secs(2), None).unwrap();
        let lines: Vec<String> = io::BufReader::new(r).lines().map(|l| l.unwrap()).collect();
        assert_eq!(lines, ["one", "two", "three"]);
    }

    #[test]
    fn a_guarded_reader_passes_open_errors_through() {
        let mut r = GuardedReader::spawn(
            || -> io::Result<&'static [u8]> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            },
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        let e = r.read(&mut [0u8; 8]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_guarded_reader_times_out_when_the_open_hangs() {
        let t = Instant::now();
        let mut r = GuardedReader::spawn(
            || -> io::Result<&'static [u8]> {
                thread::sleep(Duration::from_secs(5));
                Ok(b"late")
            },
            Duration::from_millis(150),
            None,
        )
        .unwrap();
        let e = r.read(&mut [0u8; 8]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_guarded_reader_honours_its_own_deadline() {
        // Data keeps arriving, but slower than the overall limit allows.
        struct Drip;
        impl Read for Drip {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                thread::sleep(Duration::from_millis(50));
                b[0] = b'x';
                Ok(1)
            }
        }
        let t = Instant::now();
        let r = GuardedReader::spawn(
            || Ok(Drip),
            Duration::from_secs(5),
            Some(Instant::now() + Duration::from_millis(300)),
        )
        .unwrap();
        let res = io::BufReader::new(r).lines().next();
        let e = res.unwrap().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn mountinfo_is_parsed_and_network_mounts_are_found() {
        let sample = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:35 / /home rw,relatime shared:5 - nfs4 srv:/export/home rw,vers=4.2
41 22 0:36 / /mnt/my\\040share rw - cifs //srv/share rw
42 22 0:37 / /net rw - autofs /etc/auto.net rw
43 22 0:38 / /mnt/ssh rw - fuse.sshfs me@host:/ rw
44 22 8:2 / /data rw - xfs /dev/sdb1 rw
45 22 0:39 / /mnt/ntfs rw - fuseblk /dev/sdc1 rw
";
        let all = parse_mountinfo(sample);
        assert_eq!(all.len(), 7);
        assert_eq!(all[2].0, PathBuf::from("/mnt/my share"));

        let mut bad: Vec<String> = all
            .iter()
            .filter(|(_, fs)| is_hang_prone_fs(fs))
            .map(|(p, _)| p.display().to_string())
            .collect();
        bad.sort();
        assert_eq!(bad, ["/home", "/mnt/my share", "/mnt/ssh", "/net"]);
    }

    #[test]
    fn local_filesystems_are_not_hang_prone() {
        for fs in [
            "ext4", "xfs", "btrfs", "tmpfs", "proc", "overlay", "vfat", "fuseblk", "zfs",
        ] {
            assert!(!is_hang_prone_fs(fs), "{fs}");
        }
        for fs in [
            "nfs",
            "nfs4",
            "CIFS",
            "smb3",
            "autofs",
            "fuse.sshfs",
            "ceph",
            "9p",
        ] {
            assert!(is_hang_prone_fs(fs), "{fs}");
        }
    }

    #[test]
    fn this_machines_mountinfo_can_be_read() {
        // Not asserting on content: containers differ. It must simply not panic or hang.
        let _ = hang_prone_mounts();
    }
}
