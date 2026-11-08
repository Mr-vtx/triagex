//! Read-only Docker visibility over the local Unix socket.
//! Only GET requests are sent. Docker socket access is privileged, so Triagex
//! reports a permission problem instead of trying to work around it.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

const MAX_RESPONSE: u64 = 16 * 1024 * 1024;
const MAX_INSPECT: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    /// running, restarting, exited, paused, created, dead
    pub state: String,
    /// Docker's readable text, e.g. "Up 3 hours (healthy)"
    pub status: String,
    /// healthy, unhealthy or starting; None when the container has no health check
    pub health: Option<String>,
    pub restart_count: u64,
    pub exit_code: Option<i64>,
    pub oom_killed: bool,
}

impl ContainerInfo {
    pub fn is_problem(&self) -> bool {
        self.oom_killed
            || self.state == "restarting"
            || self.state == "dead"
            || (self.state == "exited" && self.exit_code.unwrap_or(0) != 0)
            || self.health.as_deref() == Some("unhealthy")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DockerInfo {
    pub socket: String,
    pub containers: Vec<ContainerInfo>,
}

impl DockerInfo {
    pub fn running(&self) -> usize {
        self.containers
            .iter()
            .filter(|c| c.state == "running")
            .count()
    }

    pub fn stopped(&self) -> usize {
        self.containers
            .iter()
            .filter(|c| c.state == "exited" || c.state == "created" || c.state == "dead")
            .count()
    }

    pub fn problems(&self) -> usize {
        self.containers.iter().filter(|c| c.is_problem()).count()
    }
}

#[derive(Deserialize)]
struct ListItem {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Deserialize)]
struct Inspect {
    #[serde(rename = "RestartCount", default)]
    restart_count: u64,
    #[serde(rename = "State", default)]
    state: InspectState,
}

#[derive(Deserialize, Default)]
struct InspectState {
    #[serde(rename = "ExitCode", default)]
    exit_code: i64,
    #[serde(rename = "OOMKilled", default)]
    oom_killed: bool,
    #[serde(rename = "Health", default)]
    health: Option<Health>,
}

#[derive(Deserialize)]
struct Health {
    #[serde(rename = "Status", default)]
    status: String,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn decode_chunked(mut data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find(data, b"\r\n").ok_or_else(|| bad("truncated chunked body"))?;
        let size_text = std::str::from_utf8(&data[..eol])
            .map_err(|_| bad("bad chunk size"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| bad("bad chunk size"))?;
        data = &data[eol + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return Err(bad("truncated chunk"));
        }
        out.extend_from_slice(&data[..size]);
        data = data[size..]
            .strip_prefix(b"\r\n")
            .ok_or_else(|| bad("missing chunk terminator"))?;
    }
    Ok(out)
}

fn parse_http(raw: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    let split = find(raw, b"\r\n\r\n").ok_or_else(|| bad("incomplete HTTP response"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("non-UTF-8 HTTP headers"))?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("bad HTTP status line"))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = &raw[split + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn get(socket: &Path, path: &str) -> io::Result<(u16, Vec<u8>)> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: triagex\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut raw)?;
    parse_http(&raw)
}

fn describe_io(socket: &Path, e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => format!(
            "docker: permission denied on {} (add your user to the docker group, or run with sudo)",
            socket.display()
        ),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => format!(
            "docker: {} exists but the daemon is not responding",
            socket.display()
        ),
        _ => format!("docker: {}: {e}", socket.display()),
    }
}

fn health_from_status(status: &str) -> Option<String> {
    let s = status.to_ascii_lowercase();
    if s.contains("(unhealthy)") {
        Some("unhealthy".into())
    } else if s.contains("(healthy)") {
        Some("healthy".into())
    } else if s.contains("(health: starting)") {
        Some("starting".into())
    } else {
        None
    }
}

pub fn collect_from(socket: &Path) -> Result<DockerInfo, String> {
    let (status, body) =
        get(socket, "/containers/json?all=1").map_err(|e| describe_io(socket, &e))?;
    if status != 200 {
        return Err(format!(
            "docker: {} answered HTTP {status}",
            socket.display()
        ));
    }
    let items: Vec<ListItem> =
        serde_json::from_slice(&body).map_err(|e| format!("docker: unexpected response: {e}"))?;

    let mut containers = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let name = item
            .names
            .first()
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| item.id.chars().take(12).collect());
        let mut c = ContainerInfo {
            id: item.id.chars().take(12).collect(),
            name,
            image: item.image.clone(),
            state: item.state.clone(),
            status: item.status.clone(),
            health: health_from_status(&item.status),
            restart_count: 0,
            exit_code: None,
            oom_killed: false,
        };

        // Ids come from the daemon; only hex is ever put into a request path.
        let safe_id = !item.id.is_empty() && item.id.chars().all(|ch| ch.is_ascii_hexdigit());
        if i < MAX_INSPECT
            && safe_id
            && let Ok((200, body)) = get(socket, &format!("/containers/{}/json", item.id))
            && let Ok(ins) = serde_json::from_slice::<Inspect>(&body)
        {
            c.restart_count = ins.restart_count;
            c.exit_code = Some(ins.state.exit_code);
            c.oom_killed = ins.state.oom_killed;
            if let Some(h) = ins.state.health
                && !h.status.is_empty()
            {
                c.health = Some(h.status);
            }
        }
        containers.push(c);
    }

    Ok(DockerInfo {
        socket: socket.display().to_string(),
        containers,
    })
}

fn candidate_sockets() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(host) = std::env::var("DOCKER_HOST")
        && let Some(p) = host.strip_prefix("unix://")
    {
        v.push(PathBuf::from(p));
    }
    v.push(PathBuf::from("/var/run/docker.sock"));
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        v.push(PathBuf::from(dir).join("docker.sock"));
    }
    v
}

/// Ok(None) means Docker is not installed or not running here, which is not an error.
pub fn collect() -> Result<Option<DockerInfo>, String> {
    for sock in candidate_sockets() {
        if std::fs::metadata(&sock).is_ok() {
            return collect_from(&sock).map(Some);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        os::unix::net::UnixListener,
        thread,
    };

    fn id(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn list_json() -> String {
        format!(
            r#"[{{"Id":"{}","Names":["/web"],"Image":"nginx:1.27","State":"running","Status":"Up 3 hours (healthy)"}},
               {{"Id":"{}","Names":["/worker"],"Image":"app:latest","State":"restarting","Status":"Restarting (1) 5 seconds ago"}}]"#,
            id('a'),
            id('b')
        )
    }

    #[test]
    fn decodes_chunked_bodies() {
        let body = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"hello world");
        assert!(decode_chunked(b"zz\r\nabc").is_err());
        assert!(decode_chunked(b"5\r\nhe").is_err());
    }

    #[test]
    fn parses_plain_and_chunked_http() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]";
        assert_eq!(parse_http(plain).unwrap(), (200, b"[]".to_vec()));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n";
        assert_eq!(parse_http(chunked).unwrap(), (200, b"[]".to_vec()));
        let err = b"HTTP/1.1 500 Internal Server Error\r\n\r\noops";
        assert_eq!(parse_http(err).unwrap().0, 500);
        assert!(parse_http(b"garbage").is_err());
    }

    #[test]
    fn health_is_read_from_the_status_text() {
        assert_eq!(
            health_from_status("Up 1h (healthy)").as_deref(),
            Some("healthy")
        );
        assert_eq!(
            health_from_status("Up 1h (unhealthy)").as_deref(),
            Some("unhealthy")
        );
        assert_eq!(
            health_from_status("Up 5s (health: starting)").as_deref(),
            Some("starting")
        );
        assert_eq!(health_from_status("Up 1h"), None);
    }

    #[test]
    fn problems_are_recognised() {
        let base = ContainerInfo {
            id: "x".into(),
            name: "x".into(),
            image: "x".into(),
            state: "running".into(),
            status: String::new(),
            health: None,
            restart_count: 0,
            exit_code: None,
            oom_killed: false,
        };
        assert!(!base.is_problem());
        let mut c = base.clone();
        c.state = "exited".into();
        c.exit_code = Some(0);
        assert!(!c.is_problem());
        c.exit_code = Some(1);
        assert!(c.is_problem());
        let mut c = base.clone();
        c.health = Some("unhealthy".into());
        assert!(c.is_problem());
        let mut c = base;
        c.oom_killed = true;
        assert!(c.is_problem());
    }

    /// A tiny fake Docker daemon: one list call, then one inspect call per container.
    #[test]
    fn talks_to_a_docker_socket_end_to_end() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path =
            std::env::temp_dir().join(format!("tx-dock-{}-{nanos}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let (a, b) = (id('a'), id('b'));

        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (mut conn, _) = listener.accept().unwrap();
                let mut request_line = String::new();
                {
                    let mut reader = BufReader::new(&conn);
                    reader.read_line(&mut request_line).unwrap();
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        if h == "\r\n" || h.is_empty() {
                            break;
                        }
                    }
                }
                assert!(request_line.starts_with("GET "), "only GET is allowed");
                let target = request_line.split_whitespace().nth(1).unwrap().to_string();

                let (body, chunked) = if target == "/containers/json?all=1" {
                    (list_json(), true)
                } else if target.contains(&a) {
                    (r#"{"RestartCount":0,"State":{"ExitCode":0,"OOMKilled":false,"Health":{"Status":"healthy"}}}"#.to_string(), false)
                } else if target.contains(&b) {
                    (
                        r#"{"RestartCount":7,"State":{"ExitCode":1,"OOMKilled":false}}"#
                            .to_string(),
                        false,
                    )
                } else {
                    panic!("unexpected request {target}");
                };

                let response = if chunked {
                    let (first, rest) = body.split_at(10);
                    format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{rest}\r\n0\r\n\r\n",
                        first.len(),
                        rest.len()
                    )
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                conn.write_all(response.as_bytes()).unwrap();
            }
        });

        let info = collect_from(&path).unwrap();
        server.join().unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(info.containers.len(), 2);
        let web = &info.containers[0];
        assert_eq!(web.name, "web");
        assert_eq!(web.image, "nginx:1.27");
        assert_eq!(web.health.as_deref(), Some("healthy"));
        assert!(!web.is_problem());
        let worker = &info.containers[1];
        assert_eq!(worker.state, "restarting");
        assert_eq!(worker.restart_count, 7);
        assert_eq!(worker.exit_code, Some(1));
        assert!(worker.is_problem());
        assert_eq!(info.running(), 1);
        assert_eq!(info.problems(), 1);
    }

    #[test]
    fn a_missing_socket_is_a_clear_error() {
        let err = collect_from(Path::new("/definitely/not/a.sock")).unwrap_err();
        assert!(err.starts_with("docker:"));
    }
}
