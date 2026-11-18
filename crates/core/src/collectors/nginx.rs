//! nginx: the config test (`nginx -t`), whether it is running, and `stub_status` over loopback.
//!
//! What this touches, so there are no surprises:
//! - It runs `nginx -v` and `nginx -t`, nginx's own checks. `-t` reads the configuration and
//!   can create empty log files or temp directories that the configuration names.
//!   It does not reload, restart or signal anything.
//! - It sends one `GET` to a loopback `stub_status` URL, if one exists. Never anything but
//!   loopback; an address that resolves elsewhere is refused.
//!
//! Set TRIAGEX_NGINX=off to skip all of it, TRIAGEX_NGINX_BIN to point at a binary, and
//! TRIAGEX_NGINX_STATUS_URL (http://127.0.0.1:8080/status) to point at the status page.

use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

const BINARY_CANDIDATES: [&str; 6] = [
    "/usr/sbin/nginx",
    "/usr/local/sbin/nginx",
    "/usr/bin/nginx",
    "/usr/local/bin/nginx",
    "/usr/local/nginx/sbin/nginx",
    "/opt/nginx/sbin/nginx",
];
const DEFAULT_STATUS_URLS: [&str; 2] = [
    "http://127.0.0.1/nginx_status",
    "http://127.0.0.1/stub_status",
];
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_OUTPUT: u64 = 64 * 1024;
const MAX_RESPONSE: u64 = 4096;
const MAX_LINE: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigState {
    Passed,
    Failed,
    /// The test could not read what it needs (log files, certificates) without root.
    NeedsRoot,
    TimedOut,
    /// There is no nginx binary on this host (it may run in a container).
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigTest {
    pub state: ConfigState,
    /// nginx said the syntax is ok, even if the test failed later (a socket, a certificate).
    pub syntax_ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StubStatus {
    pub active: u64,
    pub accepts: u64,
    pub handled: u64,
    pub requests: u64,
    pub reading: u64,
    pub writing: u64,
    pub waiting: u64,
}

impl StubStatus {
    /// Connections nginx accepted but did not handle, counted since it started.
    pub fn dropped(&self) -> u64 {
        self.accepts.saturating_sub(self.handled)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NginxInfo {
    /// None means nginx is running here but has no binary on this host (a container).
    pub binary: Option<String>,
    pub version: Option<String>,
    /// nginx processes: the master plus its workers.
    pub processes: usize,
    pub config: ConfigTest,
    pub status: Option<StubStatus>,
    pub status_url: Option<String>,
}

impl NginxInfo {
    pub fn running(&self) -> bool {
        self.processes > 0
    }
}

/// Process output is untrusted text: no control characters, bounded length.
fn clean(s: &str) -> String {
    let t: String = s
        .trim()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if t.chars().count() > MAX_LINE {
        let mut cut: String = t.chars().take(MAX_LINE - 1).collect();
        cut.push('~');
        cut
    } else {
        t
    }
}

/// Parses what `nginx -t` prints (to stderr). `exit_ok` is the exit status.
pub fn parse_test_output(text: &str, exit_ok: bool) -> ConfigTest {
    let mut syntax_ok = false;
    let mut success = false;
    let mut failed_line = false;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for raw in text.lines() {
        let line = raw.trim().trim_start_matches("nginx:").trim();
        if line.is_empty() {
            continue;
        }
        if line.contains("syntax is ok") {
            syntax_ok = true;
        } else if line.contains("test is successful") {
            success = true;
        } else if line.contains("test failed") {
            failed_line = true;
        } else if line.starts_with("[emerg]")
            || line.starts_with("[alert]")
            || line.starts_with("[crit]")
        {
            errors.push(clean(line));
        } else if line.starts_with("[warn]") {
            warnings.push(clean(line));
        }
    }

    let state = if success && errors.is_empty() && exit_ok {
        ConfigState::Passed
    } else if !errors.is_empty() && errors.iter().all(|e| e.contains("Permission denied")) {
        ConfigState::NeedsRoot
    } else {
        if errors.is_empty() {
            let first = text.lines().map(str::trim).find(|l| !l.is_empty());
            errors.push(match first {
                Some(l) => clean(l),
                None if failed_line => "nginx -t reported a failure".to_string(),
                None => "nginx -t printed nothing and did not succeed".to_string(),
            });
        }
        ConfigState::Failed
    };
    ConfigTest {
        state,
        syntax_ok,
        errors,
        warnings,
    }
}

pub fn parse_version(text: &str) -> Option<String> {
    let after = text.split("nginx/").nth(1)?;
    let v: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    (!v.is_empty()).then_some(v)
}

pub fn parse_stub_status(body: &str) -> Option<StubStatus> {
    let mut lines = body.lines();
    let active = lines
        .next()?
        .strip_prefix("Active connections:")?
        .trim()
        .parse()
        .ok()?;
    lines
        .next()?
        .trim()
        .strip_prefix("server accepts handled requests")?;
    let mut counts = lines.next()?.split_whitespace().map(|n| n.parse::<u64>());
    let (accepts, handled, requests) = (
        counts.next()?.ok()?,
        counts.next()?.ok()?,
        counts.next()?.ok()?,
    );
    let last = lines.next()?;
    let mut words = last.split_whitespace();
    let mut grab = |label: &str| -> Option<u64> {
        if words.next()? == label {
            words.next()?.parse().ok()
        } else {
            None
        }
    };
    Some(StubStatus {
        active,
        accepts,
        handled,
        requests,
        reading: grab("Reading:")?,
        writing: grab("Writing:")?,
        waiting: grab("Waiting:")?,
    })
}

/// `http://127.0.0.1:8080/status` -> ("127.0.0.1", 8080, "/status"). Only plain http, and
/// nothing that could smuggle extra header lines into the request.
pub fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    if rest.chars().any(|c| c.is_control() || c == ' ') {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        (h, after.strip_prefix(':').map(str::parse).transpose().ok()?)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p.parse().ok()?)),
            None => (authority, None),
        }
    };
    (!host.is_empty()).then(|| (host.to_string(), port.unwrap_or(80), path.to_string()))
}

fn loopback_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| !a.ip().is_loopback()) {
        return Err(format!(
            "{host} is not a loopback address; Triagex only talks to this machine"
        ));
    }
    Ok(addrs[0])
}

pub fn fetch_status(url: &str) -> Result<StubStatus, String> {
    let (host, port, path) =
        parse_url(url).ok_or_else(|| format!("not a plain http URL: {url}"))?;
    let addr = loopback_addr(&host, port)?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("cannot connect to {addr}: {e}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    // One buffer, one write: a request split into several small packets can make a simple
    // server answer before it has read everything.
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: localhost\r\nUser-Agent: triagex\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;

    let mut raw = Vec::new();
    // A reset after the answer arrived is harmless: keep what was read.
    if let Err(e) = stream.take(MAX_RESPONSE).read_to_end(&mut raw)
        && raw.is_empty()
    {
        return Err(format!("read failed: {e}"));
    }
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "not an HTTP response".to_string())?;
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!("{}", clean(status_line)));
    }
    parse_stub_status(body).ok_or_else(|| "the page is not nginx stub_status output".to_string())
}

struct Captured {
    ok: bool,
    text: String,
}

/// Runs a command with a deadline and returns stdout and stderr together.
fn run_capture(bin: &str, arg: &str, timeout: Duration) -> io::Result<Option<Captured>> {
    let mut child = Command::new(bin)
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut readers = Vec::new();
    if let Some(o) = child.stdout.take() {
        readers.push(thread::spawn(move || read_limited(o)));
    }
    if let Some(e) = child.stderr.take() {
        readers.push(thread::spawn(move || read_limited(e)));
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let text: String = readers
        .into_iter()
        .filter_map(|h| h.join().ok())
        .collect::<Vec<_>>()
        .join("\n");
    Ok(status.map(|s| Captured {
        ok: s.success(),
        text,
    }))
}

fn read_limited<R: Read>(r: R) -> String {
    let mut buf = Vec::new();
    r.take(MAX_OUTPUT).read_to_end(&mut buf).ok();
    String::from_utf8_lossy(&buf).into_owned()
}

/// Fixed install locations first: a PATH can be anything, and this may run as root.
fn find_binary() -> Option<String> {
    if let Ok(p) = std::env::var("TRIAGEX_NGINX_BIN")
        && !p.is_empty()
    {
        return Path::new(&p).is_file().then_some(p);
    }
    BINARY_CANDIDATES
        .iter()
        .find(|p| Path::new(p).is_file())
        .map(|p| p.to_string())
}

/// Counts processes named `nginx` (the master and its workers).
fn count_processes() -> usize {
    let Ok(dir) = fs::read_dir("/proc") else {
        return 0;
    };
    dir.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter(|e| {
            fs::read_to_string(e.path().join("comm"))
                .map(|c| c.trim() == "nginx")
                .unwrap_or(false)
        })
        .count()
}

fn config_test(bin: &str) -> ConfigTest {
    match run_capture(bin, "-t", TEST_TIMEOUT) {
        Ok(Some(c)) => parse_test_output(&c.text, c.ok),
        Ok(None) => ConfigTest {
            state: ConfigState::TimedOut,
            syntax_ok: false,
            errors: vec![format!(
                "nginx -t did not finish within {} s",
                TEST_TIMEOUT.as_secs()
            )],
            warnings: vec![],
        },
        Err(e) => ConfigTest {
            state: ConfigState::Failed,
            syntax_ok: false,
            errors: vec![format!("could not run nginx -t: {e}")],
            warnings: vec![],
        },
    }
}

/// Ok(None): nginx is not on this machine. Err: a reason a check was skipped.
pub fn collect() -> Result<Option<NginxInfo>, String> {
    if std::env::var("TRIAGEX_NGINX").is_ok_and(|v| v.eq_ignore_ascii_case("off")) {
        return Ok(None);
    }
    let binary = find_binary();
    let processes = count_processes();
    if binary.is_none() && processes == 0 {
        return Ok(None);
    }

    let version = binary.as_deref().and_then(|b| {
        run_capture(b, "-v", Duration::from_secs(2))
            .ok()
            .flatten()
            .and_then(|c| parse_version(&c.text))
    });
    let config = match binary.as_deref() {
        Some(b) => config_test(b),
        None => ConfigTest {
            state: ConfigState::NotRun,
            syntax_ok: false,
            errors: vec![],
            warnings: vec![],
        },
    };

    let (status, status_url) = if processes == 0 {
        (None, None)
    } else if let Ok(url) = std::env::var("TRIAGEX_NGINX_STATUS_URL")
        && !url.is_empty()
    {
        match fetch_status(&url) {
            Ok(s) => (Some(s), Some(url)),
            Err(e) => return Err(format!("nginx status page {url}: {e}")),
        }
    } else {
        DEFAULT_STATUS_URLS
            .iter()
            .find_map(|u| fetch_status(u).ok().map(|s| (Some(s), Some(u.to_string()))))
            .unwrap_or((None, None))
    };

    Ok(Some(NginxInfo {
        binary,
        version,
        processes,
        config,
        status,
        status_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn a_passing_test() {
        let t = parse_test_output(
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n",
            true,
        );
        assert_eq!(t.state, ConfigState::Passed);
        assert!(t.syntax_ok && t.errors.is_empty());
    }

    #[test]
    fn a_syntax_error_is_reported_with_its_line() {
        let t = parse_test_output(
            "nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/app:3\nnginx: configuration file /etc/nginx/nginx.conf test failed\n",
            false,
        );
        assert_eq!(t.state, ConfigState::Failed);
        assert!(!t.syntax_ok);
        assert_eq!(
            t.errors,
            vec!["[emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/app:3"]
        );
    }

    #[test]
    fn syntax_can_be_fine_while_the_test_still_fails() {
        // seen on a real machine: IPv6 listen on a host without IPv6
        let t = parse_test_output(
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: [emerg] socket() [::]:80 failed (97: Address family not supported by protocol)\nnginx: configuration file /etc/nginx/nginx.conf test failed\n",
            false,
        );
        assert_eq!(t.state, ConfigState::Failed);
        assert!(t.syntax_ok);
    }

    #[test]
    fn running_without_root_is_inconclusive_not_a_config_error() {
        let t = parse_test_output(
            "nginx: [alert] could not open error log file: open() \"/var/log/nginx/error.log\" failed (13: Permission denied)\nnginx: [emerg] open() \"/run/nginx.pid\" failed (13: Permission denied)\n",
            false,
        );
        assert_eq!(t.state, ConfigState::NeedsRoot);
    }

    #[test]
    fn a_mix_of_permission_and_real_errors_is_still_a_failure() {
        let t = parse_test_output(
            "nginx: [emerg] open() \"/run/nginx.pid\" failed (13: Permission denied)\nnginx: [emerg] unknown directive \"x\" in /etc/nginx/nginx.conf:1\n",
            false,
        );
        assert_eq!(t.state, ConfigState::Failed);
        assert_eq!(t.errors.len(), 2);
    }

    #[test]
    fn warnings_are_kept_and_do_not_fail_a_passing_test() {
        let t = parse_test_output(
            "nginx: [warn] conflicting server name \"example.com\" on 0.0.0.0:80, ignored\nnginx: the configuration file x syntax is ok\nnginx: configuration file x test is successful\n",
            true,
        );
        assert_eq!(t.state, ConfigState::Passed);
        assert_eq!(t.warnings.len(), 1);
    }

    #[test]
    fn unrecognised_output_is_a_failure_that_shows_what_was_printed() {
        let t = parse_test_output("segmentation fault\n", false);
        assert_eq!(t.state, ConfigState::Failed);
        assert_eq!(t.errors, vec!["segmentation fault"]);
        let t = parse_test_output("", false);
        assert_eq!(t.state, ConfigState::Failed);
        assert!(!t.errors.is_empty());
    }

    #[test]
    fn output_with_escape_codes_is_neutralised() {
        let t = parse_test_output("nginx: [emerg] bad \x1b[2J thing\n", false);
        assert!(!t.errors[0].contains('\x1b'));
    }

    #[test]
    fn versions_are_pulled_out_of_nginx_v() {
        assert_eq!(
            parse_version("nginx version: nginx/1.24.0 (Ubuntu)\n").as_deref(),
            Some("1.24.0")
        );
        assert_eq!(parse_version("something else"), None);
    }

    const STATUS: &str = "Active connections: 291 \nserver accepts handled requests\n 16630948 16630946 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n";

    #[test]
    fn parses_stub_status() {
        let s = parse_stub_status(STATUS).unwrap();
        assert_eq!(s.active, 291);
        assert_eq!(
            (s.accepts, s.handled, s.requests),
            (16630948, 16630946, 31070465)
        );
        assert_eq!((s.reading, s.writing, s.waiting), (6, 179, 106));
        assert_eq!(s.dropped(), 2);
    }

    #[test]
    fn other_pages_are_not_stub_status() {
        assert!(parse_stub_status("<html>404</html>").is_none());
        assert!(parse_stub_status("Active connections: x\n").is_none());
        assert!(parse_stub_status("").is_none());
    }

    #[test]
    fn urls_are_parsed_strictly() {
        assert_eq!(
            parse_url("http://127.0.0.1:8080/status"),
            Some(("127.0.0.1".into(), 8080, "/status".into()))
        );
        assert_eq!(
            parse_url("http://localhost"),
            Some(("localhost".into(), 80, "/".into()))
        );
        assert_eq!(
            parse_url("http://[::1]:81/s"),
            Some(("::1".into(), 81, "/s".into()))
        );
        assert_eq!(parse_url("https://127.0.0.1/x"), None);
        assert_eq!(parse_url("http://127.0.0.1/x HTTP/1.1\r\nX: y"), None);
        assert_eq!(parse_url("http://127.0.0.1:notaport/"), None);
    }

    #[test]
    fn remote_hosts_are_refused_without_connecting() {
        let err = fetch_status("http://93.184.216.34/nginx_status").unwrap_err();
        assert!(err.contains("not a loopback address"), "{err}");
    }

    /// A one-shot HTTP server on loopback.
    fn serve(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // read the whole request before answering, like a real server
                let mut req = Vec::new();
                let mut buf = [0u8; 256];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/nginx_status")
    }

    #[test]
    fn reads_stub_status_over_a_real_socket() {
        let url = serve(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nActive connections: 3 \nserver accepts handled requests\n 10 10 25 \nReading: 0 Writing: 1 Waiting: 2 \n",
        );
        let s = fetch_status(&url).unwrap();
        assert_eq!((s.active, s.requests, s.waiting), (3, 25, 2));
    }

    #[test]
    fn a_404_or_a_random_page_is_not_mistaken_for_stub_status() {
        let url = serve("HTTP/1.1 404 Not Found\r\n\r\nnope");
        assert!(fetch_status(&url).unwrap_err().contains("404"));
        let url = serve("HTTP/1.1 200 OK\r\n\r\n<html>my app</html>");
        assert!(
            fetch_status(&url)
                .unwrap_err()
                .contains("not nginx stub_status")
        );
    }

    #[test]
    fn a_closed_port_is_an_error() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(fetch_status(&format!("http://127.0.0.1:{port}/x")).is_err());
    }

    #[test]
    fn a_command_that_hangs_is_killed_at_the_deadline() {
        let started = Instant::now();
        let r = run_capture("/bin/sleep", "30", Duration::from_millis(200)).unwrap();
        assert!(r.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
