//! Triagex read logs and redact secrets, collapse repeated messages into groups,
//! and show when each group happened.

pub mod group;
pub mod normalize;
pub mod parse;
pub mod redact;
pub mod source;

use std::{io, path::PathBuf};

use serde::Serialize;

use crate::{
    finding::{Finding, Severity},
    time::{format_rfc3339, format_utc, local_utc_offset_secs, now_epoch},
};
use group::{Grouper, LogGroup, timeline};
use parse::{ParseContext, parse_line};

pub const TIMELINE_BUCKETS: usize = 24;
const DEFAULT_FILES: &[&str] = &["/var/log/auth.log"];

#[derive(Debug, Clone)]
pub struct LogOptions {
    pub files: Vec<PathBuf>,
    pub journal: bool,
    /// No explicit source given: try the journal and well-known files, skip quietly if absent.
    pub use_defaults: bool,
    pub since_secs: Option<i64>,
    /// Include every line instead of only lines that look like problems (files only).
    pub all_lines: bool,
    pub top: usize,
}

impl Default for LogOptions {
    fn default() -> Self {
        LogOptions {
            files: Vec::new(),
            journal: false,
            use_defaults: true,
            since_secs: Some(86400),
            all_lines: false,
            top: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupView {
    pub program: String,
    pub pattern: String,
    pub count: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub sample: String,
    pub timeline: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub hostname: String,
    pub since: Option<String>,
    pub sources: Vec<String>,
    pub lines_scanned: u64,
    pub lines_matched: u64,
    pub groups_total: usize,
    pub groups: Vec<GroupView>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<String>,
}

impl LogReport {
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

const PROBLEM_WORDS: &[&str] = &[
    "error",
    "fail",
    "denied",
    "refused",
    "invalid",
    "timeout",
    "timed out",
    "critical",
    "fatal",
    "panic",
    "oom",
    "out of memory",
    "segfault",
    "killed",
    "unreachable",
    "exception",
    "warn",
    "corrupt",
    "unauthorized",
    "forbidden",
    "no space",
    "cannot",
    "can't",
    "unable",
];

pub fn looks_like_problem(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    PROBLEM_WORDS.iter().any(|w| lower.contains(w))
}

struct Ingest<'a> {
    grouper: &'a mut Grouper,
    ctx: ParseContext,
    cutoff: Option<i64>,
    filter_problems: bool,
    scanned: u64,
    matched: u64,
}

impl Ingest<'_> {
    fn line(&mut self, raw: &str, default_program: &str) {
        self.scanned += 1;
        if raw.trim().is_empty() || raw.starts_with("-- ") || raw.starts_with([' ', '\t']) {
            return;
        }
        let parsed = parse_line(raw, &self.ctx, default_program);
        if let (Some(cutoff), Some(t)) = (self.cutoff, parsed.timestamp)
            && t < cutoff
        {
            return;
        }
        if self.filter_problems && !looks_like_problem(&parsed.message) {
            return;
        }
        let message = redact::redact(&parsed.message);
        self.matched += 1;
        self.grouper
            .add(&parsed.program, &message, parsed.timestamp);
    }
}

fn file_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "log".to_string())
}

fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", h as u32)
}

fn range_text(g: &LogGroup) -> String {
    match (g.first_seen, g.last_seen) {
        (Some(a), Some(b)) => format!("between {} and {} UTC", format_utc(a), format_utc(b)),
        _ => "at unknown times".to_string(),
    }
}

pub fn findings_from_groups(groups: &[LogGroup]) -> Vec<Finding> {
    let mut out = Vec::new();

    // SSH password guessing: every "Failed password" group is one attempt per line.
    let ssh: Vec<&LogGroup> = groups
        .iter()
        .filter(|g| g.pattern.starts_with("Failed password"))
        .collect();
    let attempts: u64 = ssh.iter().map(|g| g.count).sum();
    if attempts >= 20 {
        let first = ssh.iter().filter_map(|g| g.first_seen).min();
        let last = ssh.iter().filter_map(|g| g.last_seen).max();
        let range = match (first, last) {
            (Some(a), Some(b)) => {
                format!("between {} and {} UTC", format_utc(a), format_utc(b))
            }
            _ => "at unknown times".to_string(),
        };
        out.push(Finding {
            id: "log.ssh.failed-passwords".into(),
            severity: if attempts >= 200 {
                Severity::Critical
            } else {
                Severity::Warning
            },
            title: "Many failed SSH password attempts".into(),
            evidence: format!("{attempts} failed password attempts {range}."),
            next_step: "Prefer key-only SSH (PasswordAuthentication no in /etc/ssh/sshd_config) and consider fail2ban or firewall rate limiting.".into(),
            source: "auth log".into(),
        });
    }

    for g in groups {
        if g.pattern.starts_with("Failed password") || g.count < 100 {
            continue;
        }
        out.push(Finding {
            id: format!("log.repeat:{}:{}", g.program, short_hash(&g.pattern)),
            severity: if g.count >= 1000 {
                Severity::Critical
            } else {
                Severity::Warning
            },
            title: format!("{} repeated {} times", g.program, g.count),
            evidence: format!("\"{}\" {}.", g.pattern, range_text(g)),
            next_step: format!(
                "Inspect recent entries with: journalctl -t {} --since \"-1h\" --no-pager | tail -n 50",
                g.program
            ),
            source: "logs".into(),
        });
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

pub fn analyze(opts: &LogOptions) -> LogReport {
    let now = now_epoch();
    let ctx = ParseContext {
        now,
        utc_offset: local_utc_offset_secs(now),
    };
    let cutoff = opts.since_secs.map(|s| now - s);

    let mut grouper = Grouper::new();
    let mut scanned = 0u64;
    let mut matched = 0u64;
    let mut sources: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    // Journal: already filtered to warnings and worse by journalctl.
    if opts.journal || opts.use_defaults {
        let mut ing = Ingest {
            grouper: &mut grouper,
            ctx,
            cutoff,
            filter_problems: false,
            scanned: 0,
            matched: 0,
        };
        match source::read_journal(opts.since_secs, |l| ing.line(l, "journal")) {
            Ok(()) => {
                sources.push("journalctl".into());
                scanned += ing.scanned;
                matched += ing.matched;
            }
            Err(e) => skipped.push(e),
        }
    }

    let mut files: Vec<(PathBuf, bool)> = opts.files.iter().map(|p| (p.clone(), true)).collect();
    if opts.use_defaults {
        files.extend(DEFAULT_FILES.iter().map(|p| (PathBuf::from(p), false)));
    }

    for (path, explicit) in files {
        let label = file_label(&path);
        let mut ing = Ingest {
            grouper: &mut grouper,
            ctx,
            cutoff,
            filter_problems: !opts.all_lines,
            scanned: 0,
            matched: 0,
        };
        match source::read_file(&path, |l| ing.line(l, &label)) {
            Ok(()) => {
                sources.push(path.display().to_string());
                scanned += ing.scanned;
                matched += ing.matched;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && !explicit => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                skipped.push(format!(
                    "{}: permission denied (try sudo or add your user to the adm group)",
                    path.display()
                ));
            }
            Err(e) => skipped.push(format!("{}: {e}", path.display())),
        }
    }

    if sources.is_empty() && skipped.is_empty() {
        skipped.push("no log sources found; pass --file <path> or --journal".into());
    }

    let groups = grouper.into_sorted();
    let findings = findings_from_groups(&groups);

    let gmin = groups
        .iter()
        .filter_map(|g| g.minutes.keys().next().copied())
        .min();
    let gmax = groups
        .iter()
        .filter_map(|g| g.minutes.keys().next_back().copied())
        .max();

    let groups_total = groups.len();
    let views = groups
        .iter()
        .take(opts.top)
        .map(|g| GroupView {
            program: g.program.clone(),
            pattern: g.pattern.clone(),
            count: g.count,
            first_seen: g.first_seen.map(format_rfc3339),
            last_seen: g.last_seen.map(format_rfc3339),
            sample: g.sample.clone(),
            timeline: match (gmin, gmax) {
                (Some(lo), Some(hi)) => timeline(&g.minutes, lo, hi, TIMELINE_BUCKETS),
                _ => vec![0; TIMELINE_BUCKETS],
            },
        })
        .collect();

    LogReport {
        tool: "triagex",
        version: env!("CARGO_PKG_VERSION"),
        hostname: crate::hostname(),
        since: opts.since_secs.map(format_since),
        sources,
        lines_scanned: scanned,
        lines_matched: matched,
        groups_total,
        groups: views,
        findings,
        skipped,
    }
}

fn format_since(secs: i64) -> String {
    if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_log(contents: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path =
            std::env::temp_dir().join(format!("triagex-test-{}-{nanos}.log", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        path
    }

    fn file_only(path: PathBuf) -> LogOptions {
        LogOptions {
            files: vec![path],
            journal: false,
            use_defaults: false,
            since_secs: None,
            all_lines: false,
            top: 10,
        }
    }

    #[test]
    fn groups_ssh_failures_from_a_file() {
        let mut text = String::new();
        for i in 0..30 {
            text.push_str(&format!(
                "Oct 26 03:{:02}:11 vps sshd[{}]: Failed password for invalid user u{} from 45.1.2.{} port {} ssh2\n",
                i,
                1000 + i,
                i,
                i + 1,
                40000 + i
            ));
        }
        text.push_str(
            "Oct 26 04:00:00 vps sshd[9]: Accepted publickey for vans from 10.0.0.2 port 22 ssh2\n",
        );
        text.push_str("Oct 26 04:01:00 vps cron[5]: (root) error: something broke\n");
        let path = temp_log(&text);

        let report = analyze(&file_only(path.clone()));
        std::fs::remove_file(path).ok();

        assert_eq!(report.lines_scanned, 32);
        assert_eq!(report.lines_matched, 31); // a successful login is not a problem line
        assert_eq!(report.groups_total, 2);
        assert_eq!(report.groups[0].count, 30);
        assert_eq!(
            report.groups[0].pattern,
            "Failed password for invalid user <user> from <ip> port <n> ssh2"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "log.ssh.failed-passwords")
        );
    }

    #[test]
    fn all_lines_flag_includes_everything() {
        let path = temp_log(
            "Oct 26 04:00:00 vps sshd[9]: Accepted publickey for vans from 10.0.0.2 port 22 ssh2\n",
        );
        let mut opts = file_only(path.clone());
        opts.all_lines = true;
        let report = analyze(&opts);
        std::fs::remove_file(path).ok();
        assert_eq!(report.lines_matched, 1);
    }

    #[test]
    fn secrets_never_reach_the_report() {
        let path =
            temp_log("Oct 26 04:00:00 vps app[1]: error connecting password=hunter2 to db\n");
        let report = analyze(&file_only(path.clone()));
        std::fs::remove_file(path).ok();
        let json = format!("{:?}", report.groups[0]);
        assert!(!json.contains("hunter2"));
        assert!(json.contains("<redacted>"));
    }

    #[test]
    fn since_filters_old_lines() {
        let path = temp_log("Jan  1 00:00:00 vps app[1]: error long ago\n");
        let mut opts = file_only(path.clone());
        opts.since_secs = Some(3600);
        let report = analyze(&opts);
        std::fs::remove_file(path).ok();
        assert_eq!(report.lines_matched, 0);
        assert!(report.groups.is_empty());
    }

    #[test]
    fn missing_explicit_file_is_reported_not_hidden() {
        let report = analyze(&file_only(PathBuf::from("/definitely/not/here.log")));
        assert!(report.skipped.iter().any(|s| s.contains("not/here.log")));
    }

    #[test]
    fn heavy_repeats_raise_a_finding() {
        let mut text = String::new();
        for i in 0..150 {
            text.push_str(&format!(
                "Oct 26 05:{:02}:{:02} vps api[1]: error upstream timed out after {} ms\n",
                i / 60,
                i % 60,
                1000 + i
            ));
        }
        let path = temp_log(&text);
        let report = analyze(&file_only(path.clone()));
        std::fs::remove_file(path).ok();
        let f = report
            .findings
            .iter()
            .find(|f| f.id.starts_with("log.repeat:api:"))
            .expect("repeat finding");
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn since_is_formatted_compactly() {
        assert_eq!(format_since(86400), "1d");
        assert_eq!(format_since(7200), "2h");
        assert_eq!(format_since(1800), "30m");
        assert_eq!(format_since(45), "45s");
    }
}
