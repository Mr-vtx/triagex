//! nginx error-log support: recognise the format, strip the parts that make every line
//! unique (connection number, client address, request line), and turn the well-known
//! failure messages into findings.
//!
//! The request line is dropped on purpose: it carries query strings, and those carry tokens.
//! The client address is dropped because one scanner would otherwise create a new group
//! per IP. What stays is the level, the message, the `server` block and the upstream's
//! scheme and address, which is what you need to find the broken backend.

use super::{LogGroup, range_text};
use crate::finding::{Finding, Severity};

/// Program label for every nginx error-log line, wherever the file is called.
pub const PROGRAM: &str = "nginx";

const LEVELS: [&str; 8] = [
    "debug", "info", "notice", "warn", "error", "crit", "alert", "emerg",
];

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `field(", server: x, request: ...", "server")` -> `x`. Values end at the next comma.
fn plain_field<'a>(trailer: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(", {key}: ");
    let start = trailer.find(&needle)? + needle.len();
    let rest = &trailer[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    let v = rest[..end].trim();
    (!v.is_empty()).then_some(v)
}

fn quoted_field<'a>(trailer: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(", {key}: \"");
    let start = trailer.find(&needle)? + needle.len();
    let rest = &trailer[start..];
    Some(&rest[..rest.find('"')?])
}

/// `http://10.0.0.5:3000/api/x?token=1` -> `http://10.0.0.5:3000`. Unix sockets are kept whole.
fn origin_of(url: &str) -> &str {
    let Some(i) = url.find("://") else {
        return url.split(['/', '?']).next().unwrap_or(url);
    };
    let (scheme_len, rest) = (i + 3, &url[i + 3..]);
    if rest.starts_with("unix:") {
        return url;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    &url[..scheme_len + end]
}

/// Takes what follows the timestamp of one line. Returns None when it is not an nginx
/// error-log line (`[level] pid#tid: ...`), so other logs are never touched.
pub fn clean_line(rest: &str) -> Option<String> {
    let after_open = rest.trim_start().strip_prefix('[')?;
    let (level, after) = after_open.split_once(']')?;
    if !LEVELS.contains(&level) {
        return None;
    }
    let (ids, body) = after.trim_start().split_once(": ")?;
    let (pid, tid) = ids.split_once('#')?;
    if !all_digits(pid) || !all_digits(tid) {
        return None;
    }

    // "*567 " is the connection number.
    let mut body = body.trim_start();
    if let Some(r) = body.strip_prefix('*')
        && let Some((n, tail)) = r.split_once(' ')
        && all_digits(n)
    {
        body = tail;
    }

    let (head, trailer) = match body.find(", client: ") {
        Some(i) => (&body[..i], Some(&body[i..])),
        None => (body, None),
    };
    let head = head.trim();
    // Missing files are mostly scanners and stale links: every name is different, the folder
    // is what matters. Permission errors keep the full path, since that is what you must fix.
    let head = if head.contains("No such file or directory") {
        collapse_paths(head)
    } else {
        head.to_string()
    };
    let mut msg = format!("[{level}] {head}");
    if let Some(t) = trailer {
        if let Some(server) = plain_field(t, "server") {
            msg.push_str(&format!(", server: {server}"));
        }
        if let Some(up) = quoted_field(t, "upstream") {
            msg.push_str(&format!(", upstream: \"{}\"", origin_of(up)));
        }
    }
    Some(msg)
}

/// `open() "/srv/x/img7.png" failed` -> `open() "/srv/x/<file>" failed`.
fn collapse_paths(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("\"/") {
        out.push_str(&rest[..=start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            out.push_str(after);
            return out;
        };
        let path = &after[..end];
        match path.rfind('/') {
            Some(i) if i + 1 < path.len() => {
                out.push_str(&path[..=i]);
                out.push_str("<file>");
            }
            _ => out.push_str(path),
        }
        out.push('"');
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

struct Rule {
    id: &'static str,
    title: &'static str,
    /// Any one of these sets matches; a set matches when every word is in the pattern.
    any_of: &'static [&'static [&'static str]],
    warn: u64,
    crit: u64,
    next_step: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "log.nginx.worker-connections",
        title: "nginx ran out of worker connections",
        any_of: &[&["worker_connections are not enough"]],
        warn: 1,
        crit: 100,
        next_step: "Raise worker_connections in the events block of nginx.conf (and worker_rlimit_nofile to at least twice that), then: sudo nginx -t && sudo nginx -s reload",
    },
    Rule {
        id: "log.nginx.open-files",
        title: "nginx hit the open-files limit",
        any_of: &[&["too many open files"]],
        warn: 1,
        crit: 100,
        next_step: "Raise worker_rlimit_nofile in nginx.conf and LimitNOFILE in the systemd unit (systemctl edit nginx). See the limit nginx runs with: grep 'open files' /proc/$(pgrep -o nginx)/limits",
    },
    Rule {
        id: "log.nginx.upstream-down",
        title: "nginx cannot reach a backend",
        any_of: &[&["connection refused", "upstream"], &["no live upstreams"]],
        warn: 5,
        crit: 50,
        next_step: "Check that the backend is running and listening on the address shown (ss -ltnp), then read the backend's own logs. If it is a Docker container: docker ps -a",
    },
    Rule {
        id: "log.nginx.upstream-timeout",
        title: "Backend responses are timing out",
        any_of: &[&["timed out", "upstream"]],
        warn: 5,
        crit: 50,
        next_step: "The backend is slow or stuck. Check its logs and its load first; raising proxy_read_timeout only hides the problem.",
    },
    Rule {
        id: "log.nginx.disk-full",
        title: "nginx cannot write: the disk is full",
        any_of: &[&["no space left on device"]],
        warn: 1,
        crit: 1,
        next_step: "Check space and inodes with: df -h; df -i. nginx writes temp files and caches under /var/lib/nginx and /var/cache/nginx: du -xh /var/lib/nginx /var/cache/nginx --max-depth=1 2>/dev/null | sort -h | tail -n 10",
    },
    Rule {
        id: "log.nginx.permission-denied",
        title: "nginx is being denied access",
        any_of: &[&["permission denied"]],
        warn: 1,
        crit: u64::MAX,
        next_step: "Find the path or socket in the example, then check every directory on the way with: namei -l <path>. Workers run as the user set by the `user` directive in nginx.conf.",
    },
];

fn rule_for(g: &LogGroup) -> Option<&'static Rule> {
    if g.program != PROGRAM {
        return None;
    }
    let pattern = g.pattern.to_ascii_lowercase();
    RULES.iter().find(|r| {
        r.any_of
            .iter()
            .any(|set| set.iter().all(|w| pattern.contains(w)))
    })
}

/// True when a specific nginx finding already reports this group, so the generic
/// "repeated N times" finding should not repeat it.
pub fn is_covered(g: &LogGroup) -> bool {
    rule_for(g).is_some()
}

pub fn findings(groups: &[LogGroup]) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in RULES {
        let hits: Vec<&LogGroup> = groups
            .iter()
            .filter(|g| rule_for(g).is_some_and(|r| r.id == rule.id))
            .collect();
        let total: u64 = hits.iter().map(|g| g.count).sum();
        if total < rule.warn {
            continue;
        }
        let severity = if total >= rule.crit {
            Severity::Critical
        } else {
            Severity::Warning
        };
        // Largest group first, so the example is the most common form of the problem.
        let top = hits.iter().max_by_key(|g| g.count).copied();
        let when = top.map(range_text).unwrap_or_default();
        let example = top
            .map(|g| format!(" Example: {}", g.sample))
            .unwrap_or_default();
        out.push(Finding {
            id: rule.id.to_string(),
            severity,
            title: rule.title.to_string(),
            evidence: format!(
                "{total} error-log {} {when}.{example}",
                if total == 1 { "entry" } else { "entries" }
            ),
            next_step: rule.next_step.to_string(),
            source: "nginx error log".to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn group(pattern: &str, count: u64) -> LogGroup {
        LogGroup {
            program: PROGRAM.into(),
            pattern: pattern.into(),
            count,
            first_seen: Some(1_793_000_000),
            last_seen: Some(1_793_000_600),
            sample: format!("[error] sample of {pattern}"),
            minutes: BTreeMap::new(),
        }
    }

    #[test]
    fn strips_ids_client_and_request_but_keeps_server_and_upstream_origin() {
        let line = "[error] 1234#1234: *567 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.9, server: example.com, request: \"GET /api/users?token=SECRET HTTP/1.1\", upstream: \"http://127.0.0.1:3000/api/users?token=SECRET\", host: \"example.com\"";
        let msg = clean_line(line).unwrap();
        assert_eq!(
            msg,
            "[error] connect() failed (111: Connection refused) while connecting to upstream, server: example.com, upstream: \"http://127.0.0.1:3000\""
        );
        assert!(!msg.contains("SECRET"));
        assert!(!msg.contains("203.0.113.9"));
    }

    #[test]
    fn lines_without_a_trailer_or_connection_number_pass_through() {
        assert_eq!(
            clean_line("[emerg] 1#1: bind() to 0.0.0.0:80 failed (98: Address already in use)")
                .unwrap(),
            "[emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)"
        );
        assert_eq!(
            clean_line("[warn] 7#7: *9 upstream server temporarily disabled").unwrap(),
            "[warn] upstream server temporarily disabled"
        );
    }

    #[test]
    fn other_logs_are_not_mistaken_for_nginx() {
        assert!(clean_line("sshd[12]: Failed password").is_none());
        assert!(clean_line("[ERROR] 12#12: shouting").is_none());
        assert!(clean_line("[error] twelve#12: nope").is_none());
        assert!(clean_line("[error] no pid here").is_none());
        assert!(clean_line("").is_none());
    }

    #[test]
    fn missing_files_group_by_folder_but_permission_errors_keep_the_path() {
        let a = clean_line("[error] 1#1: *1 open() \"/srv/www/img1.png\" failed (2: No such file or directory), client: 1.1.1.1, server: a.com, request: \"GET /img1.png HTTP/1.1\", host: \"a.com\"").unwrap();
        let b = clean_line("[error] 1#1: *2 open() \"/srv/www/img2.png\" failed (2: No such file or directory), client: 2.2.2.2, server: a.com, request: \"GET /img2.png HTTP/1.1\", host: \"a.com\"").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a,
            "[error] open() \"/srv/www/<file>\" failed (2: No such file or directory), server: a.com"
        );
        let p = clean_line("[error] 1#1: *3 open() \"/srv/www/secret.txt\" failed (13: Permission denied), client: 1.1.1.1, server: a.com, request: \"GET / HTTP/1.1\", host: \"a.com\"").unwrap();
        assert!(p.contains("/srv/www/secret.txt"));
    }

    #[test]
    fn unix_socket_upstreams_keep_their_path() {
        let line = "[crit] 5#5: *1 connect() to unix:/run/php/php8.3-fpm.sock failed (13: Permission denied) while connecting to upstream, client: 1.2.3.4, server: _, request: \"GET / HTTP/1.1\", upstream: \"fastcgi://unix:/run/php/php8.3-fpm.sock:\", host: \"x\"";
        let msg = clean_line(line).unwrap();
        assert!(msg.contains("upstream: \"fastcgi://unix:/run/php/php8.3-fpm.sock:\""));
        assert!(msg.contains("server: _"));
    }

    #[test]
    fn a_few_refused_connections_warn_and_many_are_critical() {
        let pat = "[error] connect() failed (<n>: Connection refused) while connecting to upstream";
        assert!(findings(&[group(pat, 4)]).is_empty());
        let f = findings(&[group(pat, 5)]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "log.nginx.upstream-down");
        assert_eq!(f[0].severity, Severity::Warning);
        let f = findings(&[group(pat, 50)]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].evidence.starts_with("50 error-log entries"));
        assert!(f[0].evidence.contains("Example:"));
    }

    #[test]
    fn counts_add_up_across_groups_of_the_same_problem() {
        let a = group(
            "[error] connect() failed (<n>: Connection refused) while connecting to upstream, upstream: \"http://<ip>:<n>\"",
            3,
        );
        let b = group(
            "[error] connect() failed (<n>: Connection refused) while connecting to upstream, server: a.com",
            3,
        );
        let f = findings(&[a, b]);
        assert_eq!(f.len(), 1);
        assert!(f[0].evidence.starts_with("6 error-log entries"));
    }

    #[test]
    fn one_worker_connections_message_is_already_a_warning() {
        let f = findings(&[group("[alert] <n> worker_connections are not enough", 1)]);
        assert_eq!(f[0].id, "log.nginx.worker-connections");
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].evidence.starts_with("1 error-log entry"));
    }

    #[test]
    fn a_full_disk_is_critical_straight_away() {
        let f = findings(&[group(
            "[crit] pwrite() \"/var/lib/nginx/tmp/<n>\" failed (<n>: No space left on device)",
            1,
        )]);
        assert_eq!(f[0].id, "log.nginx.disk-full");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn permission_denied_never_goes_critical_by_count_alone() {
        let f = findings(&[group(
            "[error] open() \"/srv/x\" failed (<n>: Permission denied)",
            100_000,
        )]);
        assert_eq!(f[0].severity, Severity::Warning);
    }

    #[test]
    fn only_nginx_groups_trigger_nginx_rules() {
        let mut g = group("[error] Too many open files", 500);
        g.program = "myapp".into();
        assert!(findings(&[g.clone()]).is_empty());
        assert!(!is_covered(&g));
        g.program = PROGRAM.into();
        assert!(is_covered(&g));
    }

    #[test]
    fn harmless_nginx_noise_is_not_covered() {
        let g = group(
            "[error] open() \"/var/www/favicon.ico\" failed (<n>: No such file or directory)",
            900,
        );
        assert!(!is_covered(&g));
    }
}
