//! Process view: the biggest CPU and memory consumers, read from `/proc`. Read-only.
//!
//! Only the process *name* is collected, never the command line: arguments often hold
//! passwords and tokens (`mysql -pSECRET`, `--api-key=...`), and Triagex output ends up in
//! screenshots, bug reports and CI logs.
//!
//! CPU% needs two readings, so collection is split in two: `Sampler::start()` takes the first
//! reading, the other collectors run, then `Sampler::finish()` takes the second. The wait is
//! hidden inside work that had to happen anyway. CPU% follows `top`: 100% is one full core,
//! so a busy 4-core machine can add up to 400%.

use std::{
    collections::HashMap,
    fs, io,
    os::unix::fs::MetadataExt,
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

/// How many processes are kept in each top list.
pub const TOP_N: usize = 5;
/// The two readings are at least this far apart, or CPU% would be mostly noise.
const MIN_SAMPLE: Duration = Duration::from_millis(250);
/// Processes using less CPU than this over the sample are not worth listing.
const MIN_CPU_PCT: f64 = 0.05;
/// Longest process name shown. The kernel already cuts `comm` at 15 characters.
const MAX_NAME: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub user: String,
    /// Kernel state letter: R running, S sleeping, D uninterruptible, Z zombie, T stopped.
    pub state: char,
    /// Percent of one core over the sample window (can exceed 100).
    pub cpu_pct: f64,
    pub rss_bytes: u64,
    /// Resident memory as a share of total RAM.
    pub mem_pct: f64,
    pub threads: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ProcessInfo {
    pub total: usize,
    pub running: usize,
    pub sleeping: usize,
    pub zombies: usize,
    /// Processes in state D (usually waiting on disk or network storage) at *both* readings.
    pub stuck: Vec<ProcessEntry>,
    /// How far apart the two readings were.
    pub sample_ms: u64,
    /// `/proc` is mounted with hidepid, so this is only your own processes.
    pub partial_view: bool,
    pub top_cpu: Vec<ProcessEntry>,
    pub top_mem: Vec<ProcessEntry>,
}

/// One process at one moment, straight from `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq)]
pub struct RawStat {
    pub name: String,
    pub state: char,
    pub ticks: u64,
    pub threads: u32,
    pub start_ticks: u64,
    pub rss_pages: u64,
}

/// `comm` is untrusted: any process can name itself anything, including terminal escape
/// sequences. Strip control characters so a hostile name cannot repaint the screen.
pub fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if cleaned.chars().count() > MAX_NAME {
        let mut cut: String = cleaned.chars().take(MAX_NAME - 1).collect();
        cut.push('~');
        cut
    } else {
        cleaned
    }
}

/// Parses one `/proc/<pid>/stat` line. The name sits between the first `(` and the LAST `)`
/// because it may itself contain spaces and parentheses.
pub fn parse_stat(s: &str) -> Option<(u32, RawStat)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close < open {
        return None;
    }
    let pid: u32 = s[..open].trim().parse().ok()?;
    let name = sanitize(&s[open + 1..close]);
    let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
    // Field numbers below are from proc(5); `rest[0]` is field 3 (state).
    let state = rest.first()?.chars().next()?;
    let utime: u64 = rest.get(11)?.parse().ok()?; // field 14
    let stime: u64 = rest.get(12)?.parse().ok()?; // field 15
    let threads: u32 = rest.get(17)?.parse().ok()?; // field 20
    let start_ticks: u64 = rest.get(19)?.parse().ok()?; // field 22
    let rss_pages: u64 = rest.get(21)?.parse().ok()?; // field 24
    Some((
        pid,
        RawStat {
            name,
            state,
            ticks: utime + stime,
            threads,
            start_ticks,
            rss_pages,
        },
    ))
}

/// `/etc/passwd` lines to a uid -> name map. Bad lines are skipped.
pub fn parse_passwd(s: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in s.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            map.entry(uid).or_insert_with(|| sanitize(name));
        }
    }
    map
}

/// True when the `proc` line of /proc/mounts hides other users' processes.
pub fn hidepid_enabled(mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let mut f = line.split_whitespace();
        let (_, Some(mount), Some(fstype), Some(opts)) = (f.next(), f.next(), f.next(), f.next())
        else {
            return false;
        };
        mount == "/proc"
            && fstype == "proc"
            && opts.split(',').any(|o| {
                matches!(
                    o,
                    "hidepid=1" | "hidepid=2" | "hidepid=invisible" | "hidepid=noaccess"
                )
            })
    })
}

fn read_all() -> io::Result<HashMap<u32, RawStat>> {
    let mut out = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        // A process can exit between listing and reading. That is normal, not an error.
        let Ok(text) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some((parsed_pid, raw)) = parse_stat(&text)
            && parsed_pid == pid
        {
            out.insert(pid, raw);
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no readable processes in /proc",
        ));
    }
    Ok(out)
}

fn sysconf(name: libc::c_int, fallback: u64) -> u64 {
    // SAFETY: sysconf only reads a system constant and has no preconditions.
    let v = unsafe { libc::sysconf(name) };
    if v > 0 { v as u64 } else { fallback }
}

pub struct Sampler {
    first: HashMap<u32, RawStat>,
    at: Instant,
}

impl Sampler {
    pub fn start() -> io::Result<Self> {
        let first = read_all()?;
        Ok(Sampler {
            first,
            at: Instant::now(),
        })
    }

    /// Takes the second reading (waiting if the first was too recent) and builds the view.
    /// `total_mem_bytes` is used for the memory share; None leaves `mem_pct` at 0.
    pub fn finish(self, total_mem_bytes: Option<u64>) -> io::Result<ProcessInfo> {
        let elapsed = self.at.elapsed();
        if elapsed < MIN_SAMPLE {
            thread::sleep(MIN_SAMPLE - elapsed);
        }
        let second = read_all()?;
        let window = self.at.elapsed();

        let users = fs::read_to_string("/etc/passwd")
            .map(|s| parse_passwd(&s))
            .unwrap_or_default();
        let partial_view = fs::read_to_string("/proc/mounts")
            .map(|m| hidepid_enabled(&m))
            .unwrap_or(false)
            // SAFETY: geteuid has no preconditions and cannot fail.
            && unsafe { libc::geteuid() } != 0;

        Ok(build(
            &self.first,
            &second,
            window,
            sysconf(libc::_SC_CLK_TCK, 100),
            sysconf(libc::_SC_PAGESIZE, 4096),
            total_mem_bytes,
            partial_view,
            &|pid| {
                fs::metadata(format!("/proc/{pid}"))
                    .ok()
                    .map(|m| m.uid())
                    .map(|uid| users.get(&uid).cloned().unwrap_or_else(|| uid.to_string()))
                    .unwrap_or_else(|| "?".to_string())
            },
        ))
    }
}

/// Pure part of the work, kept separate so it can be tested with made-up readings.
#[allow(clippy::too_many_arguments)]
pub fn build(
    first: &HashMap<u32, RawStat>,
    second: &HashMap<u32, RawStat>,
    window: Duration,
    clk_tck: u64,
    page_size: u64,
    total_mem_bytes: Option<u64>,
    partial_view: bool,
    user_of: &dyn Fn(u32) -> String,
) -> ProcessInfo {
    let secs = window.as_secs_f64().max(0.001);
    let ticks_per_sec = clk_tck.max(1) as f64;

    let entry = |pid: u32, p: &RawStat| {
        // A pid that was reused between the readings is a different process: no CPU figure.
        let cpu_pct = match first.get(&pid) {
            Some(before) if before.start_ticks == p.start_ticks => {
                p.ticks.saturating_sub(before.ticks) as f64 / ticks_per_sec / secs * 100.0
            }
            _ => 0.0,
        };
        let rss_bytes = p.rss_pages.saturating_mul(page_size);
        let mem_pct = match total_mem_bytes {
            Some(total) if total > 0 => rss_bytes as f64 / total as f64 * 100.0,
            _ => 0.0,
        };
        ProcessEntry {
            pid,
            name: p.name.clone(),
            user: user_of(pid),
            state: p.state,
            cpu_pct,
            rss_bytes,
            mem_pct,
            threads: p.threads,
        }
    };

    let mut info = ProcessInfo {
        total: second.len(),
        sample_ms: window.as_millis() as u64,
        partial_view,
        ..ProcessInfo::default()
    };

    let mut cpu_rank: Vec<(u32, f64)> = Vec::new();
    let mut mem_rank: Vec<(u32, u64)> = Vec::new();
    let mut stuck_pids: Vec<u32> = Vec::new();

    for (&pid, p) in second {
        match p.state {
            'R' => info.running += 1,
            'S' | 'I' => info.sleeping += 1,
            'Z' => info.zombies += 1,
            _ => {}
        }
        if p.state == 'D'
            && first
                .get(&pid)
                .is_some_and(|b| b.state == 'D' && b.start_ticks == p.start_ticks)
        {
            stuck_pids.push(pid);
        }
        if let Some(before) = first.get(&pid)
            && before.start_ticks == p.start_ticks
        {
            let pct = p.ticks.saturating_sub(before.ticks) as f64 / ticks_per_sec / secs * 100.0;
            if pct >= MIN_CPU_PCT {
                cpu_rank.push((pid, pct));
            }
        }
        if p.rss_pages > 0 {
            mem_rank.push((pid, p.rss_pages));
        }
    }

    // Ties break on pid so the output is stable from run to run.
    cpu_rank.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    mem_rank.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    stuck_pids.sort_unstable();

    info.top_cpu = cpu_rank
        .iter()
        .take(TOP_N)
        .map(|(pid, _)| entry(*pid, &second[pid]))
        .collect();
    info.top_mem = mem_rank
        .iter()
        .take(TOP_N)
        .map(|(pid, _)| entry(*pid, &second[pid]))
        .collect();
    info.stuck = stuck_pids
        .iter()
        .take(TOP_N)
        .map(|pid| entry(*pid, &second[pid]))
        .collect();
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-looking line: 52 fields, name with spaces and parentheses.
    fn line(
        pid: u32,
        name: &str,
        state: char,
        utime: u64,
        stime: u64,
        start: u64,
        rss: u64,
    ) -> String {
        format!(
            "{pid} ({name}) {state} 1 {pid} {pid} 0 -1 4194560 100 0 0 0 {utime} {stime} 0 0 20 0 3 0 {start} 123456789 {rss} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"
        )
    }

    fn raw(name: &str, state: char, ticks: u64, start: u64, rss: u64) -> RawStat {
        RawStat {
            name: name.into(),
            state,
            ticks,
            threads: 1,
            start_ticks: start,
            rss_pages: rss,
        }
    }

    #[test]
    fn parses_a_stat_line() {
        let (pid, s) = parse_stat(&line(42, "nginx", 'S', 70, 30, 9000, 2500)).unwrap();
        assert_eq!(pid, 42);
        assert_eq!(s.name, "nginx");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ticks, 100);
        assert_eq!(s.threads, 3);
        assert_eq!(s.start_ticks, 9000);
        assert_eq!(s.rss_pages, 2500);
    }

    #[test]
    fn names_with_spaces_and_parentheses_do_not_shift_the_fields() {
        let (_, s) = parse_stat(&line(7, "Web Content) (x", 'R', 5, 5, 1, 10)).unwrap();
        assert_eq!(s.name, "Web Content) (x");
        assert_eq!(s.state, 'R');
        assert_eq!(s.ticks, 10);
        assert_eq!(s.rss_pages, 10);
    }

    #[test]
    fn garbage_and_short_lines_are_rejected() {
        assert!(parse_stat("").is_none());
        assert!(parse_stat("nope").is_none());
        assert!(parse_stat("12 (x) S 1 2 3").is_none());
        assert!(parse_stat(") 12 (").is_none());
    }

    #[test]
    fn hostile_names_cannot_inject_terminal_escapes() {
        let name = sanitize("a\x1b[2Jb\nc");
        assert!(!name.contains('\x1b'));
        assert!(!name.contains('\n'));
        assert_eq!(name, "a?[2Jb?c");
        let long = sanitize(&"x".repeat(100));
        assert_eq!(long.chars().count(), MAX_NAME);
        assert!(long.ends_with('~'));
    }

    #[test]
    fn passwd_maps_uids_and_skips_bad_lines() {
        let m = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nbroken\nvans:x:1000:1000::/home/vans:/bin/zsh\nx:x:notanumber:0\n",
        );
        assert_eq!(m.get(&0).map(String::as_str), Some("root"));
        assert_eq!(m.get(&1000).map(String::as_str), Some("vans"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn hidepid_is_detected_only_on_the_proc_mount() {
        let on = "sysfs /sys sysfs rw 0 0\nproc /proc proc rw,nosuid,hidepid=2 0 0\n";
        let off = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n";
        let other = "proc /tmp/x proc rw,hidepid=2 0 0\n";
        assert!(hidepid_enabled(on));
        assert!(!hidepid_enabled(off));
        assert!(!hidepid_enabled(other));
    }

    fn view(
        first: &[(u32, RawStat)],
        second: &[(u32, RawStat)],
        total_mem: Option<u64>,
    ) -> ProcessInfo {
        let f: HashMap<_, _> = first.iter().cloned().collect();
        let s: HashMap<_, _> = second.iter().cloned().collect();
        build(
            &f,
            &s,
            Duration::from_millis(500),
            100,
            4096,
            total_mem,
            false,
            &|pid| format!("u{pid}"),
        )
    }

    #[test]
    fn cpu_percent_is_a_share_of_one_core_over_the_window() {
        // 100 ticks/s * 0.5 s = 50 ticks would be 100% of a core.
        let info = view(
            &[
                (1, raw("busy", 'R', 1000, 1, 10)),
                (2, raw("calm", 'S', 1000, 1, 10)),
            ],
            &[
                (1, raw("busy", 'R', 1050, 1, 10)),
                (2, raw("calm", 'S', 1005, 1, 10)),
            ],
            None,
        );
        assert_eq!(info.top_cpu[0].name, "busy");
        assert!((info.top_cpu[0].cpu_pct - 100.0).abs() < 1e-9);
        assert!((info.top_cpu[1].cpu_pct - 10.0).abs() < 1e-9);
    }

    #[test]
    fn multi_threaded_work_can_exceed_one_hundred_percent() {
        let info = view(
            &[(1, raw("render", 'R', 0, 1, 10))],
            &[(1, raw("render", 'R', 150, 1, 10))],
            None,
        );
        assert!((info.top_cpu[0].cpu_pct - 300.0).abs() < 1e-9);
    }

    #[test]
    fn idle_processes_are_not_listed_and_a_reused_pid_gets_no_cpu() {
        let info = view(
            &[
                (1, raw("idle", 'S', 500, 1, 10)),
                (2, raw("old", 'S', 0, 1, 10)),
            ],
            // pid 2 was reused by a new process (different start time) with 900 ticks
            &[
                (1, raw("idle", 'S', 500, 1, 10)),
                (2, raw("new", 'R', 900, 2, 10)),
            ],
            None,
        );
        assert!(info.top_cpu.is_empty());
    }

    #[test]
    fn memory_ranks_by_resident_size_and_reports_a_share_of_ram() {
        let info = view(
            &[],
            &[
                (1, raw("small", 'S', 0, 1, 100)),
                (2, raw("big", 'S', 0, 1, 25_000)),
                (3, raw("kthread", 'S', 0, 1, 0)),
            ],
            Some(100_000 * 4096),
        );
        assert_eq!(info.top_mem.len(), 2);
        assert_eq!(info.top_mem[0].name, "big");
        assert_eq!(info.top_mem[0].rss_bytes, 25_000 * 4096);
        assert!((info.top_mem[0].mem_pct - 25.0).abs() < 1e-9);
        assert_eq!(info.top_mem[0].user, "u2");
    }

    #[test]
    fn lists_are_capped_and_ties_are_stable() {
        let second: Vec<_> = (1..=12).map(|p| (p, raw("w", 'S', 0, 1, 50))).collect();
        let info = view(&[], &second, None);
        assert_eq!(info.top_mem.len(), TOP_N);
        let pids: Vec<u32> = info.top_mem.iter().map(|e| e.pid).collect();
        assert_eq!(pids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn counts_states_and_only_flags_processes_stuck_at_both_readings() {
        let first = [
            (1, raw("a", 'R', 0, 1, 1)),
            (2, raw("rsync", 'D', 0, 1, 1)),
            (3, raw("blip", 'D', 0, 1, 1)),
        ];
        let second = [
            (1, raw("a", 'S', 0, 1, 1)),
            (2, raw("rsync", 'D', 0, 1, 1)),
            (3, raw("blip", 'S', 0, 1, 1)),
            (4, raw("ghost", 'Z', 0, 1, 0)),
            (5, raw("job", 'R', 0, 1, 1)),
        ];
        let info = view(&first, &second, None);
        assert_eq!(info.total, 5);
        assert_eq!(info.running, 1);
        assert_eq!(info.sleeping, 2);
        assert_eq!(info.zombies, 1);
        assert_eq!(info.stuck.len(), 1);
        assert_eq!(info.stuck[0].name, "rsync");
    }

    #[test]
    fn a_live_sample_of_this_machine_works() {
        let sampler = Sampler::start().expect("/proc should be readable");
        let info = sampler.finish(Some(1 << 30)).expect("second reading");
        assert!(info.total > 0);
        assert!(info.sample_ms >= MIN_SAMPLE.as_millis() as u64);
        assert!(info.top_mem.len() <= TOP_N);
        assert!(info.top_mem.iter().all(|e| !e.name.is_empty()));
    }
}
