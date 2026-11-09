//! Redis is read-only with `PING` and `INFO` over a local TCP or Unix socket.
//! No credentials are read or sent. A server that requires a password is reported
//! as such, never bypassed. Set TRIAGEX_REDIS_ADDR (host:port or unix:/path) to
//! point Triagex at a non-default instance.

use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::{Duration, Instant},
};

use serde::Serialize;

const TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_BULK: usize = 8 * 1024 * 1024;
const DEFAULT_TCP: &str = "127.0.0.1:6379";
const DEFAULT_SOCKETS: [&str; 3] = [
    "/var/run/redis/redis-server.sock",
    "/run/redis/redis.sock",
    "/tmp/redis.sock",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RedisInfo {
    pub addr: String,
    pub version: String,
    /// master or slave
    pub role: String,
    pub uptime_secs: u64,
    pub connected_clients: u64,
    pub max_clients: Option<u64>,
    pub used_memory: u64,
    /// 0 means no limit is configured
    pub max_memory: u64,
    pub rss: u64,
    pub fragmentation_ratio: Option<f64>,
    pub evicted_keys: u64,
    pub rejected_connections: u64,
    pub keys: u64,
    /// None when the field is missing from INFO
    pub rdb_save_ok: Option<bool>,
    pub aof_write_ok: Option<bool>,
    pub master_link_up: Option<bool>,
    pub ping_ms: f64,
}

impl RedisInfo {
    /// Share of `maxmemory` in use, when a limit is configured.
    pub fn memory_pct(&self) -> Option<f64> {
        if self.max_memory == 0 {
            None
        } else {
            Some(self.used_memory as f64 / self.max_memory as f64 * 100.0)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Reply {
    Simple(String),
    Error(String),
    Int(i64),
    Bulk(Option<Vec<u8>>),
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn read_reply<R: BufRead>(r: &mut R) -> io::Result<Reply> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed",
        ));
    }
    let line = line.trim_end_matches(['\r', '\n']);
    let (kind, rest) = line.split_at(line.len().min(1));
    match kind {
        "+" => Ok(Reply::Simple(rest.to_string())),
        "-" => Ok(Reply::Error(rest.to_string())),
        ":" => rest
            .parse()
            .map(Reply::Int)
            .map_err(|_| bad("bad integer reply")),
        "$" => {
            let len: i64 = rest.parse().map_err(|_| bad("bad bulk length"))?;
            if len < 0 {
                return Ok(Reply::Bulk(None));
            }
            let len = len as usize;
            if len > MAX_BULK {
                return Err(bad("reply too large"));
            }
            let mut buf = vec![0u8; len + 2];
            r.read_exact(&mut buf)?;
            buf.truncate(len);
            Ok(Reply::Bulk(Some(buf)))
        }
        _ => Err(bad("unexpected reply type (is this Redis?)")),
    }
}

fn send<S: Read + Write>(conn: &mut BufReader<S>, cmd: &str) -> io::Result<Reply> {
    let msg = format!("*1\r\n${}\r\n{cmd}\r\n", cmd.len());
    conn.get_mut().write_all(msg.as_bytes())?;
    conn.get_mut().flush()?;
    read_reply(conn)
}

pub fn parse_info(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn from_info(addr: &str, ping_ms: f64, text: &str) -> Result<RedisInfo, String> {
    let m = parse_info(text);
    let num = |k: &str| m.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let status_ok = |k: &str| m.get(k).map(|v| v == "ok");

    let version = m
        .get("redis_version")
        .cloned()
        .ok_or_else(|| format!("redis: {addr}: INFO had no redis_version (is this Redis?)"))?;

    // "db0:keys=42,expires=1,avg_ttl=0"
    let keys = m
        .iter()
        .filter(|(k, _)| {
            k.len() > 2 && k.starts_with("db") && k[2..].bytes().all(|b| b.is_ascii_digit())
        })
        .filter_map(|(_, v)| {
            v.split(',')
                .find_map(|part| part.strip_prefix("keys="))
                .and_then(|n| n.parse::<u64>().ok())
        })
        .sum();

    Ok(RedisInfo {
        addr: addr.to_string(),
        version,
        role: m.get("role").cloned().unwrap_or_else(|| "unknown".into()),
        uptime_secs: num("uptime_in_seconds"),
        connected_clients: num("connected_clients"),
        max_clients: m.get("maxclients").and_then(|v| v.parse().ok()),
        used_memory: num("used_memory"),
        max_memory: num("maxmemory"),
        rss: num("used_memory_rss"),
        fragmentation_ratio: m
            .get("mem_fragmentation_ratio")
            .and_then(|v| v.parse().ok()),
        evicted_keys: num("evicted_keys"),
        rejected_connections: num("rejected_connections"),
        keys,
        rdb_save_ok: status_ok("rdb_last_bgsave_status"),
        aof_write_ok: status_ok("aof_last_write_status"),
        master_link_up: m.get("master_link_status").map(|v| v == "up"),
        ping_ms,
    })
}

fn probe<S: Read + Write>(stream: S, addr: &str) -> Result<RedisInfo, String> {
    let mut conn = BufReader::new(stream);
    let io_err = |e: io::Error| format!("redis: {addr}: {e}");

    let start = Instant::now();
    let pong = send(&mut conn, "PING").map_err(io_err)?;
    let ping_ms = start.elapsed().as_secs_f64() * 1000.0;
    match pong {
        Reply::Simple(_) => {}
        Reply::Error(e)
            if e.starts_with("NOAUTH") || e.to_ascii_lowercase().contains("authentication") =>
        {
            return Err(format!(
                "redis: {addr} requires a password (Triagex does not send credentials)"
            ));
        }
        other => {
            return Err(format!(
                "redis: {addr} answered PING unexpectedly: {other:?}"
            ));
        }
    }

    match send(&mut conn, "INFO").map_err(io_err)? {
        Reply::Bulk(Some(bytes)) => from_info(addr, ping_ms, &String::from_utf8_lossy(&bytes)),
        Reply::Error(e) => Err(format!("redis: {addr}: INFO refused: {e}")),
        other => Err(format!("redis: {addr}: unexpected INFO reply: {other:?}")),
    }
}

pub fn probe_tcp(addr: SocketAddr) -> Result<RedisInfo, String> {
    let label = addr.to_string();
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("redis: {label}: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    probe(stream, &label)
}

enum Target {
    Tcp(String),
    Unix(PathBuf),
}

fn targets() -> Vec<Target> {
    if let Ok(v) = std::env::var("TRIAGEX_REDIS_ADDR")
        && !v.trim().is_empty()
    {
        return vec![match v.trim().strip_prefix("unix:") {
            Some(path) => Target::Unix(PathBuf::from(path)),
            None => Target::Tcp(v.trim().to_string()),
        }];
    }
    let mut v = vec![Target::Tcp(DEFAULT_TCP.to_string())];
    v.extend(
        DEFAULT_SOCKETS
            .iter()
            .map(|p| Target::Unix(PathBuf::from(p))),
    );
    v
}

fn is_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotFound
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
    )
}

/// Ok(None) means no Redis was found, which is not an error.
pub fn collect() -> Result<Option<RedisInfo>, String> {
    for target in targets() {
        match target {
            Target::Tcp(addr) => {
                let resolved = addr
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut it| it.next())
                    .ok_or_else(|| format!("redis: cannot resolve address {addr}"))?;
                match TcpStream::connect_timeout(&resolved, CONNECT_TIMEOUT) {
                    Ok(stream) => {
                        stream.set_read_timeout(Some(TIMEOUT)).ok();
                        stream.set_write_timeout(Some(TIMEOUT)).ok();
                        return probe(stream, &addr).map(Some);
                    }
                    Err(e) if is_absent(&e) => continue,
                    Err(e) => return Err(format!("redis: {addr}: {e}")),
                }
            }
            Target::Unix(path) => {
                if std::fs::metadata(&path).is_err() {
                    continue;
                }
                let label = path.display().to_string();
                match UnixStream::connect(&path) {
                    Ok(stream) => {
                        stream.set_read_timeout(Some(TIMEOUT)).ok();
                        stream.set_write_timeout(Some(TIMEOUT)).ok();
                        return probe(stream, &label).map(Some);
                    }
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                        return Err(format!(
                            "redis: permission denied on {label} (run with sudo or join the redis group)"
                        ));
                    }
                    Err(e) if is_absent(&e) => continue,
                    Err(e) => return Err(format!("redis: {label}: {e}")),
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    const INFO: &str = "# Server\r\nredis_version:7.2.4\r\nuptime_in_seconds:86400\r\n\r\n# Clients\r\nconnected_clients:12\r\nmaxclients:10000\r\n\r\n# Memory\r\nused_memory:1048576\r\nused_memory_rss:2097152\r\nmaxmemory:0\r\nmem_fragmentation_ratio:2.00\r\n\r\n# Persistence\r\nrdb_last_bgsave_status:ok\r\naof_last_write_status:ok\r\n\r\n# Stats\r\nrejected_connections:3\r\nevicted_keys:5\r\n\r\n# Replication\r\nrole:master\r\n\r\n# Keyspace\r\ndb0:keys=42,expires=1,avg_ttl=0\r\ndb3:keys=8,expires=0,avg_ttl=0\r\n";

    fn reply(bytes: &[u8]) -> io::Result<Reply> {
        read_reply(&mut BufReader::new(bytes))
    }

    #[test]
    fn parses_every_reply_type() {
        assert_eq!(reply(b"+PONG\r\n").unwrap(), Reply::Simple("PONG".into()));
        assert_eq!(
            reply(b"-NOAUTH Authentication required.\r\n").unwrap(),
            Reply::Error("NOAUTH Authentication required.".into())
        );
        assert_eq!(reply(b":42\r\n").unwrap(), Reply::Int(42));
        assert_eq!(
            reply(b"$5\r\nhello\r\n").unwrap(),
            Reply::Bulk(Some(b"hello".to_vec()))
        );
        assert_eq!(reply(b"$-1\r\n").unwrap(), Reply::Bulk(None));
    }

    #[test]
    fn rejects_garbage_and_oversized_replies() {
        assert!(reply(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(reply(b"").is_err());
        assert!(reply(b"$99999999999\r\n").is_err());
        assert!(reply(b"$10\r\nshort\r\n").is_err());
        assert!(reply(b":notanumber\r\n").is_err());
    }

    #[test]
    fn parses_info_into_typed_fields() {
        let info = from_info("test", 0.4, INFO).unwrap();
        assert_eq!(info.version, "7.2.4");
        assert_eq!(info.role, "master");
        assert_eq!(info.uptime_secs, 86400);
        assert_eq!(info.connected_clients, 12);
        assert_eq!(info.max_clients, Some(10000));
        assert_eq!(info.used_memory, 1_048_576);
        assert_eq!(info.max_memory, 0);
        assert_eq!(info.memory_pct(), None);
        assert_eq!(info.fragmentation_ratio, Some(2.0));
        assert_eq!(info.evicted_keys, 5);
        assert_eq!(info.rejected_connections, 3);
        assert_eq!(info.keys, 50);
        assert_eq!(info.rdb_save_ok, Some(true));
        assert_eq!(info.master_link_up, None);
    }

    #[test]
    fn non_redis_info_is_rejected() {
        assert!(from_info("x", 0.0, "hello:world\r\n").is_err());
    }

    #[test]
    fn memory_percentage_needs_a_limit() {
        let mut info = from_info("t", 0.0, INFO).unwrap();
        info.max_memory = 2_097_152;
        assert_eq!(info.memory_pct(), Some(50.0));
    }

    /// A tiny fake Redis: answers PING and INFO for one connection.
    fn fake_redis(require_auth: bool) -> (SocketAddr, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn);
            let mut seen = Vec::new();
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap() == 0 {
                    break;
                }
                let args: usize = header.trim()[1..].parse().unwrap();
                let mut words = Vec::new();
                for _ in 0..args {
                    let mut len = String::new();
                    reader.read_line(&mut len).unwrap();
                    let mut word = String::new();
                    reader.read_line(&mut word).unwrap();
                    words.push(word.trim().to_string());
                }
                let cmd = words.join(" ");
                let out = match (cmd.as_str(), require_auth) {
                    ("PING", true) => "-NOAUTH Authentication required.\r\n".to_string(),
                    ("PING", false) => "+PONG\r\n".to_string(),
                    ("INFO", _) => format!("${}\r\n{INFO}\r\n", INFO.len()),
                    _ => "-ERR unknown command\r\n".to_string(),
                };
                seen.push(cmd);
                reader.get_mut().write_all(out.as_bytes()).unwrap();
            }
            seen
        });
        (addr, handle)
    }

    #[test]
    fn talks_to_a_redis_end_to_end_and_only_sends_read_commands() {
        let (addr, server) = fake_redis(false);
        let info = probe_tcp(addr).unwrap();
        let seen = server.join().unwrap();
        assert_eq!(seen, vec!["PING", "INFO"]);
        assert_eq!(info.version, "7.2.4");
        assert_eq!(info.keys, 50);
        assert!(info.ping_ms >= 0.0);
    }

    #[test]
    fn a_password_protected_redis_is_reported_not_bypassed() {
        let (addr, server) = fake_redis(true);
        let err = probe_tcp(addr).unwrap_err();
        let seen = server.join().unwrap();
        assert!(err.contains("requires a password"), "{err}");
        assert_eq!(seen, vec!["PING"], "must not send anything else");
    }

    #[test]
    fn a_closed_port_is_an_error_for_probe_but_absent_for_collect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(probe_tcp(addr).is_err());
    }
}
