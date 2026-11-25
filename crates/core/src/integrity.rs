//! File integrity is used to record a baseline of selected paths, to be later compared against.
//!
//! Scan-based, not real-time. Read-only on the system being inspected; the only thing
//! written is the baseline file itself, in Triagex's own data directory (mode 0600).
//! Symlinks are never followed, special files are skipped, and anything unreadable is
//! reported instead of being silently ignored.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    finding::{Finding, Severity},
    guard,
    time::{format_rfc3339, now_epoch},
};

pub const DEFAULT_MAX_FILES: usize = 200_000;
pub const DEFAULT_MAX_HASH_MB: u64 = 256;
const FORMAT_VERSION: u32 = 1;
const LIST_PREVIEW: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub kind: EntryKind,
    pub size: u64,
    /// Permission bits including setuid/setgid/sticky (0o7777)
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    /// BLAKE3 of the content; None for directories, symlinks and files too large to hash
    pub hash: Option<String>,
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created_at: String,
    pub hostname: String,
    pub roots: Vec<String>,
    pub excludes: Vec<String>,
    pub max_files: usize,
    pub max_hash_bytes: u64,
    pub entries: BTreeMap<String, Entry>,
    pub skipped: Vec<Skipped>,
    /// BLAKE3 over everything above that matters; detects a baseline edited after the fact.
    pub digest: String,
}

impl Baseline {
    /// Why the scan that produced this baseline did not finish, if it did not. Such a baseline
    /// is partial and must not be saved: verify would report everything it missed as deleted.
    pub fn aborted_reason(&self) -> Option<&str> {
        self.skipped
            .iter()
            .find(|s| s.path == ABORTED_PATH)
            .map(|s| s.reason.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub excludes: Vec<String>,
    pub max_files: usize,
    pub max_hash_bytes: u64,
}

impl ScanOptions {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        ScanOptions {
            roots,
            excludes: Vec::new(),
            max_files: DEFAULT_MAX_FILES,
            max_hash_bytes: DEFAULT_MAX_HASH_MB * 1024 * 1024,
        }
    }
}

#[derive(Debug, Default)]
pub struct Scan {
    pub entries: BTreeMap<String, Entry>,
    pub skipped: Vec<Skipped>,
    /// Why the scan was cut short (a hung mount, the run deadline), or None if it finished.
    /// The entries are then only what was reached before that.
    pub aborted: Option<String>,
}

/// The `Skipped::path` that marks a scan which did not finish. A baseline carries it in its
/// skipped list, so a partial baseline can be recognised (and refused) later.
pub const ABORTED_PATH: &str = "(scan aborted)";

/// A walk that makes no progress for this long is stuck on dead storage. Override with
/// TRIAGEX_STALL_SECS (a slow but alive disk may need more).
const STALL_LIMIT: Duration = Duration::from_secs(15);

fn stall_limit() -> Duration {
    std::env::var("TRIAGEX_STALL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(STALL_LIMIT)
}

fn skip(path: impl AsRef<str>, reason: impl Into<String>) -> Skipped {
    Skipped {
        path: path.as_ref().to_string(),
        reason: reason.into(),
    }
}

fn describe(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        io::ErrorKind::NotFound => "disappeared while scanning".to_string(),
        _ => e.to_string(),
    }
}

/// Minimal glob: `*` matches any run of characters, `?` matches one.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_excluded(path: &str, excludes: &[String]) -> bool {
    excludes.iter().any(|pat| {
        glob_match(pat, path)
            || path
                .strip_prefix(pat.trim_end_matches('/'))
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

#[cfg(test)]
fn hash_file(path: &Path) -> io::Result<String> {
    hash_file_with(path, || {})
}

/// `tick` runs after every chunk, so a long hash of a big file still counts as progress.
fn hash_file_with(path: &Path, tick: impl Fn()) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        tick();
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// What the walking thread and the thread watching it share.
struct Shared {
    scan: Mutex<Scan>,
    /// The path being worked on, for the message if it never finishes.
    current: Mutex<String>,
    started: Instant,
    /// Milliseconds since `started` at the last sign of life.
    last_progress_ms: AtomicU64,
    done: AtomicBool,
    /// Set by the watcher when it gives up; a late-waking walker must then do nothing.
    abandoned: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn new() -> Self {
        Shared {
            scan: Mutex::new(Scan::default()),
            current: Mutex::new(String::new()),
            started: Instant::now(),
            last_progress_ms: AtomicU64::new(0),
            done: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_progress_ms.store(ms, Ordering::Relaxed);
    }

    fn at(&self, path: &str) {
        *lock(&self.current) = path.to_string();
        self.touch();
    }

    fn idle(&self) -> Duration {
        let last = Duration::from_millis(self.last_progress_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    fn is_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Relaxed)
    }

    fn skip(&self, path: impl AsRef<str>, reason: impl Into<String>) {
        lock(&self.scan).skipped.push(skip(path, reason));
    }

    fn count(&self) -> usize {
        lock(&self.scan).entries.len()
    }

    fn insert(&self, path: String, entry: Entry) {
        lock(&self.scan).entries.insert(path, entry);
    }
}

/// Runs `work` on its own thread and watches it. If the thread makes no progress for `stall`,
/// or the run deadline passes, the watcher stops waiting and returns what was gathered so far,
/// marked as aborted. The stuck thread is abandoned: it is blocked in the kernel on dead
/// storage and cannot be cancelled, and it will notice `abandoned` if it ever wakes up.
fn run_guarded(stall: Duration, work: impl FnOnce(&Shared) + Send + 'static) -> Scan {
    let shared = Arc::new(Shared::new());
    let worker = Arc::clone(&shared);
    let handle = thread::Builder::new()
        .name("triagex-scan".into())
        .spawn(move || {
            work(&worker);
            worker.done.store(true, Ordering::Release);
        });
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            let reason = format!("could not start the scan thread: {e}");
            return Scan {
                skipped: vec![skip(ABORTED_PATH, reason.clone())],
                aborted: Some(reason),
                ..Scan::default()
            };
        }
    };

    let reason = loop {
        if shared.done.load(Ordering::Acquire) || handle.is_finished() {
            break None;
        }
        if guard::expired() {
            break Some("the run deadline passed".to_string());
        }
        let idle = shared.idle();
        if idle >= stall {
            break Some(format!(
                "no progress for {} s (a hung or unreachable mount?)",
                idle.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };

    shared.abandoned.store(reason.is_some(), Ordering::Release);
    let mut scan = std::mem::take(&mut *lock(&shared.scan));
    if let Some(reason) = reason {
        let at = lock(&shared.current).clone();
        if !at.is_empty() {
            scan.skipped.push(skip(
                &at,
                format!("scan stopped here: {reason}; this path or one below it did not answer"),
            ));
        }
        scan.skipped.push(skip(
            ABORTED_PATH,
            format!("scan stopped early: {reason}; the results are incomplete"),
        ));
        scan.aborted = Some(reason);
    }
    scan
}

pub fn scan(opts: &ScanOptions) -> Scan {
    let opts = opts.clone();
    run_guarded(stall_limit(), move |sh| scan_roots(&opts, sh))
}

fn scan_roots(opts: &ScanOptions, sh: &Shared) {
    // Network and automounted filesystems are never entered: stat() on a stale NFS mount
    // point is itself the call that hangs, so they are skipped by name, before any stat.
    let hang_prone = guard::hang_prone_mounts();
    for root in &opts.roots {
        if sh.is_abandoned() {
            return;
        }
        let shown = root.display().to_string();
        sh.at(&shown);
        let root = match fs::canonicalize(root) {
            Ok(p) => p,
            Err(e) => {
                sh.skip(shown, describe(&e));
                continue;
            }
        };
        let root_dev = fs::metadata(&root).map(|m| m.dev()).ok();
        walk(&root, root_dev, opts, &hang_prone, sh);
    }
}

fn walk(
    start: &Path,
    root_dev: Option<u64>,
    opts: &ScanOptions,
    hang_prone: &HashMap<PathBuf, String>,
    sh: &Shared,
) {
    let mut stack = vec![start.to_path_buf()];
    while let Some(path) = stack.pop() {
        if sh.is_abandoned() {
            return;
        }
        let shown = path.to_string_lossy().into_owned();
        if is_excluded(&shown, &opts.excludes) {
            continue;
        }
        // A root named on the command line is scanned even if it is itself a network mount
        // (the stall watchdog covers that); anything found *below* a root is not.
        if path != start
            && let Some(fstype) = hang_prone.get(&path)
        {
            sh.skip(
                &shown,
                format!(
                    "{fstype} mount point (can hang when the server is unreachable), not scanned"
                ),
            );
            continue;
        }
        if sh.count() >= opts.max_files {
            sh.skip(
                &shown,
                format!(
                    "file limit ({}) reached; the scan is incomplete",
                    opts.max_files
                ),
            );
            break;
        }
        sh.at(&shown);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                sh.skip(&shown, describe(&e));
                continue;
            }
        };
        let ft = meta.file_type();
        let mut entry = Entry {
            kind: EntryKind::File,
            size: meta.len(),
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: meta.mtime(),
            hash: None,
            target: None,
        };

        if ft.is_symlink() {
            entry.kind = EntryKind::Symlink;
            entry.target = fs::read_link(&path)
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
        } else if ft.is_dir() {
            entry.kind = EntryKind::Dir;
            if Some(meta.dev()) != root_dev {
                sh.skip(&shown, "different filesystem (mount point), not scanned");
            } else {
                match fs::read_dir(&path) {
                    Ok(rd) => stack.extend(rd.flatten().map(|c| c.path())),
                    Err(e) => sh.skip(&shown, describe(&e)),
                }
            }
        } else if ft.is_file() {
            if meta.len() > opts.max_hash_bytes {
                sh.skip(
                    &shown,
                    format!(
                        "too large to hash ({} bytes); size and mode are still tracked",
                        meta.len()
                    ),
                );
            } else {
                match hash_file_with(&path, || sh.touch()) {
                    Ok(h) => entry.hash = Some(h),
                    Err(e) => {
                        sh.skip(&shown, describe(&e));
                        continue;
                    }
                }
            }
        } else {
            sh.skip(&shown, "special file (socket, device or pipe), skipped");
            continue;
        }
        if sh.is_abandoned() {
            return;
        }
        sh.insert(shown, entry);
    }
}

fn compute_digest(
    roots: &[String],
    excludes: &[String],
    entries: &BTreeMap<String, Entry>,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"triagex-baseline-v1\n");
    for part in [
        serde_json::to_vec(roots),
        serde_json::to_vec(excludes),
        serde_json::to_vec(entries),
    ] {
        h.update(&part.unwrap_or_default());
        h.update(b"\n");
    }
    h.finalize().to_hex().to_string()
}

pub fn create_baseline(opts: &ScanOptions) -> Baseline {
    let Scan {
        entries, skipped, ..
    } = scan(opts);
    let roots: Vec<String> = opts
        .roots
        .iter()
        .map(|r| {
            fs::canonicalize(r)
                .unwrap_or_else(|_| r.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let digest = compute_digest(&roots, &opts.excludes, &entries);
    Baseline {
        version: FORMAT_VERSION,
        created_at: format_rfc3339(now_epoch()),
        hostname: crate::hostname(),
        roots,
        excludes: opts.excludes.clone(),
        max_files: opts.max_files,
        max_hash_bytes: opts.max_hash_bytes,
        entries,
        skipped,
        digest,
    }
}

// -------------------------- storage --------------------------

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.')
}

/// Root keeps baselines in /var/lib/triagex; other users in their own data directory.
pub fn data_dir_for(is_root: bool, xdg_data_home: Option<&str>, home: Option<&str>) -> PathBuf {
    if is_root {
        return PathBuf::from("/var/lib/triagex");
    }
    match (
        xdg_data_home.filter(|v| !v.is_empty()),
        home.filter(|v| !v.is_empty()),
    ) {
        (Some(x), _) => PathBuf::from(x).join("triagex"),
        (None, Some(h)) => PathBuf::from(h).join(".local/share/triagex"),
        _ => PathBuf::from("/tmp/triagex-data"),
    }
}

pub fn data_dir() -> PathBuf {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let is_root = unsafe { libc::geteuid() } == 0;
    data_dir_for(
        is_root,
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

pub fn baseline_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid baseline name \"{name}\" (use letters, digits, - _ . and at most 64 characters)"
        ));
    }
    Ok(dir.join("baselines").join(format!("{name}.json")))
}

pub fn save_baseline(path: &Path, baseline: &Baseline, force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "a baseline already exists at {} (use --force to replace it)",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or("baseline path has no parent directory")?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| format!("could not create {}: {e}", parent.display()))?;

    let json = serde_json::to_vec_pretty(baseline).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    let write = || -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        fs::remove_file(&tmp).ok();
        format!("could not write {}: {e}", path.display())
    })
}

pub fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!(
                "no baseline at {} (create one with: triagex baseline <paths>)",
                path.display()
            )
        } else {
            format!("could not read {}: {e}", path.display())
        }
    })?;
    let b: Baseline = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not a valid baseline: {e}", path.display()))?;
    if b.version != FORMAT_VERSION {
        return Err(format!(
            "{} uses baseline format {} but this Triagex reads format {FORMAT_VERSION}",
            path.display(),
            b.version
        ));
    }
    Ok(b)
}

/// What `triagex baseline` reports back (the full baseline can be huge, so this is the summary).
#[derive(Debug, Clone, Serialize)]
pub struct BaselineSummary {
    pub name: String,
    pub path: String,
    pub created_at: String,
    pub roots: Vec<String>,
    pub files: usize,
    pub dirs: usize,
    pub symlinks: usize,
    pub hashed: usize,
    pub skipped_total: usize,
    /// The first few skipped paths, enough to explain what is missing
    pub skipped: Vec<Skipped>,
    pub digest: String,
}

pub fn summarize(name: &str, path: &Path, b: &Baseline) -> BaselineSummary {
    let count = |kind| b.entries.values().filter(|e| e.kind == kind).count();
    BaselineSummary {
        name: name.to_string(),
        path: path.display().to_string(),
        created_at: b.created_at.clone(),
        roots: b.roots.clone(),
        files: count(EntryKind::File),
        dirs: count(EntryKind::Dir),
        symlinks: count(EntryKind::Symlink),
        hashed: b.entries.values().filter(|e| e.hash.is_some()).count(),
        skipped_total: b.skipped.len(),
        skipped: b.skipped.iter().take(20).cloned().collect(),
        digest: b.digest.clone(),
    }
}

// -------------------------- comparison --------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PermChange {
    pub path: String,
    pub old_mode: u32,
    pub new_mode: u32,
    pub old_owner: (u32, u32),
    pub new_owner: (u32, u32),
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub name: String,
    pub created_at: String,
    pub hostname: String,
    pub roots: Vec<String>,
    pub baseline_entries: usize,
    pub checked: usize,
    /// false means the stored baseline no longer matches its own digest
    pub digest_ok: bool,
    pub digest: String,
    /// Some(true/false) when --expect-digest was given
    pub expected_digest_ok: Option<bool>,
    pub added: Vec<String>,
    pub deleted: Vec<String>,
    pub modified: Vec<String>,
    pub permissions: Vec<PermChange>,
    pub type_changed: Vec<String>,
    pub unreadable: Vec<Skipped>,
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    pub fn changes(&self) -> usize {
        self.added.len()
            + self.deleted.len()
            + self.modified.len()
            + self.permissions.len()
            + self.type_changed.len()
    }
}

fn content_changed(old: &Entry, new: &Entry) -> bool {
    match (&old.hash, &new.hash) {
        (Some(a), Some(b)) => a != b,
        // not hashed (too large): fall back to size
        _ => old.size != new.size,
    }
}

pub fn verify(
    name: &str,
    baseline: &Baseline,
    expect_digest: Option<&str>,
    current: &Scan,
) -> VerifyReport {
    let recomputed = compute_digest(&baseline.roots, &baseline.excludes, &baseline.entries);
    let digest_ok = recomputed == baseline.digest;

    let mut report = VerifyReport {
        name: name.to_string(),
        created_at: baseline.created_at.clone(),
        hostname: baseline.hostname.clone(),
        roots: baseline.roots.clone(),
        baseline_entries: baseline.entries.len(),
        checked: current.entries.len(),
        digest_ok,
        digest: baseline.digest.clone(),
        expected_digest_ok: expect_digest.map(|d| d.eq_ignore_ascii_case(&baseline.digest)),
        added: Vec::new(),
        deleted: Vec::new(),
        modified: Vec::new(),
        permissions: Vec::new(),
        type_changed: Vec::new(),
        unreadable: Vec::new(),
        findings: Vec::new(),
    };

    for (path, old) in &baseline.entries {
        let Some(new) = current.entries.get(path) else {
            // After an aborted scan, "not found" only means "not reached".
            if current.aborted.is_none() {
                report.deleted.push(path.clone());
            }
            continue;
        };
        if old.kind != new.kind {
            report.type_changed.push(path.clone());
            continue;
        }
        let changed = match old.kind {
            EntryKind::File => content_changed(old, new),
            EntryKind::Symlink => old.target != new.target,
            EntryKind::Dir => false,
        };
        if changed {
            report.modified.push(path.clone());
        }
        if old.mode != new.mode || old.uid != new.uid || old.gid != new.gid {
            report.permissions.push(PermChange {
                path: path.clone(),
                old_mode: old.mode,
                new_mode: new.mode,
                old_owner: (old.uid, old.gid),
                new_owner: (new.uid, new.gid),
            });
        }
    }
    report.added = current
        .entries
        .keys()
        .filter(|p| !baseline.entries.contains_key(*p))
        .cloned()
        .collect();

    // Things the baseline could read but this scan could not (or vice versa) are worth knowing.
    let known_unreadable: Vec<&str> = baseline.skipped.iter().map(|s| s.path.as_str()).collect();
    report.unreadable = current
        .skipped
        .iter()
        .filter(|s| !known_unreadable.contains(&s.path.as_str()))
        .cloned()
        .collect();

    report.findings = findings(&report, &current.entries);
    if let Some(reason) = &current.aborted {
        report.findings.push(Finding {
            id: "integrity.scan-incomplete".to_string(),
            severity: Severity::Warning,
            title: "The file scan did not finish, so this comparison is incomplete".to_string(),
            evidence: format!(
                "{reason}. {} of {} baseline paths were reached before it stopped; deleted-file detection is off for this run.",
                current.entries.len(),
                baseline.entries.len()
            ),
            next_step: "Find the path the scan stopped at (see the unreadable list) and check its storage: mount, df, dmesg. If the disk is only slow, raise --deadline or set TRIAGEX_STALL_SECS, then verify again.".to_string(),
            source: SOURCE.to_string(),
        });
        report
            .findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    }
    report
}

/// Re-scan exactly what the baseline covered, then compare.
pub fn verify_baseline(
    name: &str,
    baseline: &Baseline,
    expect_digest: Option<&str>,
) -> VerifyReport {
    let current = scan(&ScanOptions {
        roots: baseline.roots.iter().map(PathBuf::from).collect(),
        excludes: baseline.excludes.clone(),
        max_files: baseline.max_files,
        max_hash_bytes: baseline.max_hash_bytes,
    });
    verify(name, baseline, expect_digest, &current)
}

// -------------------------- findings --------------------------

/// Paths where an unexpected change deserves a louder warning. This is a heuristic about
/// where changes matter most, not a verdict that anything is wrong.
pub fn is_sensitive(path: &str) -> bool {
    const EXACT: [&str; 7] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/ld.so.preload",
    ];
    const PREFIXES: [&str; 5] = [
        "/etc/sudoers.d/",
        "/etc/cron.d/",
        "/etc/pam.d/",
        "/etc/ssh/",
        "/root/.ssh/",
    ];
    EXACT.contains(&path)
        || PREFIXES.iter().any(|p| path.starts_with(p))
        || path.ends_with("/.ssh/authorized_keys")
}

fn preview(paths: &[String]) -> String {
    let shown: Vec<&str> = paths
        .iter()
        .take(LIST_PREVIEW)
        .map(String::as_str)
        .collect();
    let mut text = shown.join(", ");
    if paths.len() > LIST_PREVIEW {
        text.push_str(&format!(" (+{} more)", paths.len() - LIST_PREVIEW));
    }
    text
}

const SOURCE: &str = "baseline comparison";
const REBASELINE: &str =
    "If a change was intended, record a new baseline with: triagex baseline <paths> --force";

fn gained_dangerous_bits(old: u32, new: u32) -> bool {
    let gained = new & !old;
    gained & 0o6000 != 0 || gained & 0o002 != 0
}

pub fn findings(report: &VerifyReport, current: &BTreeMap<String, Entry>) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |id: &str, sev, title: String, evidence: String, next: &str| Finding {
        id: id.to_string(),
        severity: sev,
        title,
        evidence,
        next_step: next.to_string(),
        source: SOURCE.to_string(),
    };

    if !report.digest_ok {
        out.push(f(
            "integrity.baseline-tampered",
            Severity::Critical,
            "The baseline file does not match its own digest".to_string(),
            format!(
                "The stored entries hash to something other than the recorded digest {}. The baseline was edited or damaged after it was created.",
                &report.digest[..report.digest.len().min(16)]
            ),
            "Do not trust this comparison. Restore the baseline from a trusted copy, or recreate it from a known-good state.",
        ));
    }
    if report.expected_digest_ok == Some(false) {
        out.push(f(
            "integrity.digest-mismatch",
            Severity::Critical,
            "The baseline digest is not the one you expected".to_string(),
            format!(
                "The baseline's digest is {}, which differs from the digest you passed.",
                report.digest
            ),
            "This baseline is not the one you recorded. Restore your trusted copy before relying on it.",
        ));
    }

    let sensitive: Vec<String> = report
        .modified
        .iter()
        .chain(&report.added)
        .chain(&report.deleted)
        .chain(&report.type_changed)
        .filter(|p| is_sensitive(p))
        .cloned()
        .collect();
    if !sensitive.is_empty() {
        out.push(f(
            "integrity.sensitive",
            Severity::Critical,
            format!("{} sensitive file(s) changed since the baseline", sensitive.len()),
            preview(&sensitive),
            "Check these first: who changed them, and when? (ls -l --time-style=full-iso, last, journalctl). Then restore or re-baseline.",
        ));
    }

    let lists: [(&str, &str, &Vec<String>); 4] = [
        ("integrity.modified", "modified", &report.modified),
        ("integrity.added", "added", &report.added),
        ("integrity.deleted", "deleted", &report.deleted),
        (
            "integrity.type",
            "changed type (file, directory or symlink)",
            &report.type_changed,
        ),
    ];
    for (id, word, list) in lists {
        if list.is_empty() {
            continue;
        }
        out.push(f(
            id,
            Severity::Warning,
            format!("{} file(s) {word} since the baseline", list.len()),
            preview(list),
            REBASELINE,
        ));
    }

    if !report.permissions.is_empty() {
        let risky: Vec<&PermChange> = report
            .permissions
            .iter()
            .filter(|c| {
                current
                    .get(&c.path)
                    .is_some_and(|e| e.kind != EntryKind::Dir)
                    && gained_dangerous_bits(c.old_mode, c.new_mode)
            })
            .collect();
        let describe = |c: &PermChange| {
            let owner = if c.old_owner != c.new_owner {
                format!(
                    ", owner {}:{} -> {}:{}",
                    c.old_owner.0, c.old_owner.1, c.new_owner.0, c.new_owner.1
                )
            } else {
                String::new()
            };
            format!(
                "{} ({:04o} -> {:04o}{owner})",
                c.path, c.old_mode, c.new_mode
            )
        };
        if !risky.is_empty() {
            let text: Vec<String> = risky.iter().map(|c| describe(c)).collect();
            out.push(f(
                "integrity.permissions.risky",
                Severity::Critical,
                format!("{} file(s) gained setuid, setgid or world-write", risky.len()),
                preview(&text),
                "Check whether this was intended: ls -l on each path. Remove the bit if not: chmod u-s,g-s,o-w <path>",
            ));
        }
        let text: Vec<String> = report.permissions.iter().map(describe).collect();
        out.push(f(
            "integrity.permissions",
            Severity::Warning,
            format!(
                "{} permission or ownership change(s) since the baseline",
                report.permissions.len()
            ),
            preview(&text),
            REBASELINE,
        ));
    }

    // A new file that is setuid is worth its own line even if it is "just" an addition.
    let new_suid: Vec<String> = report
        .added
        .iter()
        .filter(|p| {
            current
                .get(*p)
                .is_some_and(|e| e.kind == EntryKind::File && e.mode & 0o6000 != 0)
        })
        .cloned()
        .collect();
    if !new_suid.is_empty() {
        out.push(f(
            "integrity.new-setuid",
            Severity::Critical,
            format!("{} new setuid or setgid file(s)", new_suid.len()),
            preview(&new_suid),
            "A new privileged binary appeared. Identify it: ls -l, file, and your package manager's file ownership query.",
        ));
    }

    if !report.unreadable.is_empty() {
        let text: Vec<String> = report
            .unreadable
            .iter()
            .map(|s| format!("{} ({})", s.path, s.reason))
            .collect();
        out.push(f(
            "integrity.unreadable",
            Severity::Info,
            format!("{} path(s) could not be checked", report.unreadable.len()),
            preview(&text),
            "Run with enough privileges to read them (sudo), or exclude them with --exclude when creating the baseline.",
        ));
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let dir =
                std::env::temp_dir().join(format!("tx-int-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Tmp(dir)
        }
        fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
        fn write(&self, rel: &str, content: &str) {
            let p = self.path(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, content).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).ok();
        }
    }

    fn opts(t: &Tmp) -> ScanOptions {
        ScanOptions::new(vec![t.0.clone()])
    }

    fn key(t: &Tmp, rel: &str) -> String {
        fs::canonicalize(t.path(rel))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn blake3_of_empty_input_is_the_published_value() {
        let t = Tmp::new("hash");
        t.write("empty", "");
        let h = hash_file(&t.path("empty")).unwrap();
        assert_eq!(
            h,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("/etc/*.conf", "/etc/app.conf"));
        assert!(glob_match("/var/log/*", "/var/log/syslog"));
        assert!(glob_match("*.tmp", "/a/b/c.tmp"));
        assert!(glob_match("/a/?/c", "/a/b/c"));
        assert!(!glob_match("/etc/*.conf", "/etc/app.txt"));
        assert!(!glob_match("/a/?", "/a/bc"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn excludes_match_globs_and_whole_directories() {
        let ex = vec!["/data/cache".to_string(), "*.log".to_string()];
        assert!(is_excluded("/data/cache", &ex));
        assert!(is_excluded("/data/cache/x/y", &ex));
        assert!(is_excluded("/data/app.log", &ex));
        assert!(!is_excluded("/data/cachefile", &ex));
        assert!(!is_excluded("/data/app.txt", &ex));
    }

    #[test]
    fn an_unchanged_tree_verifies_clean() {
        let t = Tmp::new("clean");
        t.write("a.conf", "one");
        t.write("sub/b.conf", "two");
        let base = create_baseline(&opts(&t));
        let report = verify_baseline("t", &base, None);
        assert_eq!(report.changes(), 0, "{report:?}");
        assert!(report.digest_ok);
        assert!(report.findings.is_empty());
        assert!(report.checked >= 4); // root, sub, two files
    }

    #[test]
    fn modified_added_and_deleted_files_are_found() {
        let t = Tmp::new("diff");
        t.write("keep", "same");
        t.write("change", "before");
        t.write("remove", "bye");
        let base = create_baseline(&opts(&t));

        t.write("change", "after");
        t.write("new", "hello");
        fs::remove_file(t.path("remove")).unwrap();

        let r = verify_baseline("t", &base, None);
        assert_eq!(r.modified, vec![key(&t, "change")]);
        assert_eq!(r.added, vec![key(&t, "new")]);
        assert_eq!(r.deleted, vec![key_missing(&t, "remove")]);
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"integrity.modified"));
        assert!(ids.contains(&"integrity.added"));
        assert!(ids.contains(&"integrity.deleted"));
    }

    fn key_missing(t: &Tmp, rel: &str) -> String {
        fs::canonicalize(&t.0)
            .unwrap()
            .join(rel)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn a_touched_file_with_the_same_content_is_not_a_change() {
        let t = Tmp::new("touch");
        t.write("f", "content");
        let base = create_baseline(&opts(&t));
        // rewrite identical bytes: mtime moves, content does not
        std::thread::sleep(std::time::Duration::from_millis(20));
        t.write("f", "content");
        assert_eq!(verify_baseline("t", &base, None).changes(), 0);
    }

    #[test]
    fn permission_changes_are_reported_and_dangerous_ones_are_critical() {
        let t = Tmp::new("perm");
        t.write("tool", "#!/bin/sh");
        fs::set_permissions(t.path("tool"), fs::Permissions::from_mode(0o755)).unwrap();
        let base = create_baseline(&opts(&t));

        fs::set_permissions(t.path("tool"), fs::Permissions::from_mode(0o4755)).unwrap();
        let r = verify_baseline("t", &base, None);
        assert_eq!(r.permissions.len(), 1);
        assert_eq!(r.permissions[0].old_mode, 0o755);
        assert_eq!(r.permissions[0].new_mode, 0o4755);
        let risky = r
            .findings
            .iter()
            .find(|f| f.id == "integrity.permissions.risky")
            .unwrap();
        assert_eq!(risky.severity, Severity::Critical);

        fs::set_permissions(t.path("tool"), fs::Permissions::from_mode(0o700)).unwrap();
        let r = verify_baseline("t", &base, None);
        assert_eq!(r.permissions.len(), 1);
        assert!(
            r.findings
                .iter()
                .all(|f| f.id != "integrity.permissions.risky")
        );
        assert!(r.findings.iter().any(|f| f.id == "integrity.permissions"));
    }

    #[test]
    fn world_writable_is_dangerous() {
        assert!(gained_dangerous_bits(0o644, 0o666));
        assert!(gained_dangerous_bits(0o755, 0o2755));
        assert!(!gained_dangerous_bits(0o644, 0o600));
        assert!(!gained_dangerous_bits(0o666, 0o666));
    }

    #[test]
    fn symlinks_are_recorded_not_followed() {
        let t = Tmp::new("link");
        t.write("real", "data");
        symlink("real", t.path("ln")).unwrap();
        symlink("/etc", t.path("to-etc")).unwrap();
        let base = create_baseline(&opts(&t));

        let ln = &base.entries[&key_missing(&t, "ln")];
        assert_eq!(ln.kind, EntryKind::Symlink);
        assert_eq!(ln.target.as_deref(), Some("real"));
        // the target of a symlink pointing outside the tree is not scanned
        assert!(!base.entries.keys().any(|k| k.starts_with("/etc/")));

        fs::remove_file(t.path("ln")).unwrap();
        symlink("elsewhere", t.path("ln")).unwrap();
        let r = verify_baseline("t", &base, None);
        assert_eq!(r.modified, vec![key_missing(&t, "ln")]);
    }

    #[test]
    fn a_file_replaced_by_a_symlink_is_a_type_change() {
        let t = Tmp::new("type");
        t.write("f", "x");
        let base = create_baseline(&opts(&t));
        fs::remove_file(t.path("f")).unwrap();
        symlink("/etc/passwd", t.path("f")).unwrap();
        let r = verify_baseline("t", &base, None);
        assert_eq!(r.type_changed, vec![key_missing(&t, "f")]);
    }

    #[test]
    fn special_files_are_skipped_and_reported() {
        let t = Tmp::new("fifo");
        t.write("f", "x");
        let fifo = std::ffi::CString::new(t.path("pipe").to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
        let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        let base = create_baseline(&opts(&t));
        assert!(!base.entries.contains_key(&key_missing(&t, "pipe")));
        assert!(
            base.skipped
                .iter()
                .any(|s| s.path.ends_with("/pipe") && s.reason.contains("special"))
        );
    }

    #[test]
    fn excluded_paths_are_ignored_even_when_they_change() {
        let t = Tmp::new("excl");
        t.write("keep", "a");
        t.write("noise/log", "1");
        let mut o = opts(&t);
        o.excludes = vec![key_missing(&t, "noise")];
        let base = create_baseline(&o);
        assert!(!base.entries.keys().any(|k| k.contains("/noise")));
        t.write("noise/log", "changed");
        t.write("noise/another", "new");
        assert_eq!(verify_baseline("t", &base, None).changes(), 0);
    }

    #[test]
    fn large_files_are_tracked_by_size_when_not_hashed() {
        let t = Tmp::new("big");
        t.write("big", "0123456789");
        let mut o = opts(&t);
        o.max_hash_bytes = 4;
        let base = create_baseline(&o);
        let e = &base.entries[&key_missing(&t, "big")];
        assert!(e.hash.is_none());
        assert!(base.skipped.iter().any(|s| s.reason.contains("too large")));
        t.write("big", "0123456789ABCDEF");
        assert_eq!(verify_baseline("t", &base, None).modified.len(), 1);
    }

    #[test]
    fn the_file_limit_stops_the_scan_and_says_so() {
        let t = Tmp::new("limit");
        for i in 0..10 {
            t.write(&format!("f{i}"), "x");
        }
        let mut o = opts(&t);
        o.max_files = 4;
        let base = create_baseline(&o);
        assert_eq!(base.entries.len(), 4);
        assert!(base.skipped.iter().any(|s| s.reason.contains("file limit")));
    }

    #[test]
    fn a_tampered_baseline_is_detected() {
        let t = Tmp::new("tamper");
        t.write("f", "x");
        let mut base = create_baseline(&opts(&t));
        assert!(verify_baseline("t", &base, None).digest_ok);
        // an attacker edits the recorded hash to hide a change
        base.entries.values_mut().for_each(|e| {
            if e.hash.is_some() {
                e.hash = Some("0".repeat(64));
            }
        });
        let r = verify_baseline("t", &base, None);
        assert!(!r.digest_ok);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "integrity.baseline-tampered")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn an_expected_digest_is_checked() {
        let t = Tmp::new("expect");
        t.write("f", "x");
        let base = create_baseline(&opts(&t));
        let ok = verify_baseline("t", &base, Some(&base.digest));
        assert_eq!(ok.expected_digest_ok, Some(true));
        let bad = verify_baseline("t", &base, Some("deadbeef"));
        assert_eq!(bad.expected_digest_ok, Some(false));
        assert!(
            bad.findings
                .iter()
                .any(|f| f.id == "integrity.digest-mismatch")
        );
    }

    #[test]
    fn sensitive_paths_are_recognised() {
        for p in [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/home/u/.ssh/authorized_keys",
            "/etc/cron.d/job",
            "/etc/sudoers.d/x",
        ] {
            assert!(is_sensitive(p), "{p}");
        }
        for p in ["/etc/hostname", "/var/www/index.html", "/etc/ssh2"] {
            assert!(!is_sensitive(p), "{p}");
        }
    }

    #[test]
    fn changes_to_sensitive_files_get_their_own_critical_finding() {
        let mut cur = BTreeMap::new();
        cur.insert(
            "/etc/passwd".to_string(),
            Entry {
                kind: EntryKind::File,
                size: 1,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                hash: None,
                target: None,
            },
        );
        let report = VerifyReport {
            name: "t".into(),
            created_at: String::new(),
            hostname: String::new(),
            roots: vec![],
            baseline_entries: 1,
            checked: 1,
            digest_ok: true,
            digest: "d".repeat(64),
            expected_digest_ok: None,
            added: vec![],
            deleted: vec![],
            modified: vec!["/etc/passwd".into(), "/etc/other".into()],
            permissions: vec![],
            type_changed: vec![],
            unreadable: vec![],
            findings: vec![],
        };
        let f = findings(&report, &cur);
        assert_eq!(f[0].id, "integrity.sensitive");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].evidence.contains("/etc/passwd"));
        assert!(!f[0].evidence.contains("/etc/other"));
        assert!(f.iter().any(|x| x.id == "integrity.modified"));
    }

    #[test]
    fn long_change_lists_are_previewed() {
        let paths: Vec<String> = (0..20).map(|i| format!("/f{i}")).collect();
        let text = preview(&paths);
        assert!(text.contains("/f0"));
        assert!(text.contains("(+12 more)"));
    }

    #[test]
    fn baselines_roundtrip_with_private_permissions() {
        let t = Tmp::new("store");
        t.write("f", "x");
        let base = create_baseline(&opts(&t));
        let dir = Tmp::new("data");
        let path = baseline_path(&dir.0, "web").unwrap();
        save_baseline(&path, &base, false).unwrap();

        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "baseline file must be private");
        let dir_mode = fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "baseline directory must be private");

        let loaded = load_baseline(&path).unwrap();
        assert_eq!(loaded.digest, base.digest);
        assert_eq!(loaded.entries, base.entries);
        assert!(verify_baseline("web", &loaded, None).digest_ok);

        // never silently overwrite
        assert!(
            save_baseline(&path, &base, false)
                .unwrap_err()
                .contains("--force")
        );
        save_baseline(&path, &base, true).unwrap();
    }

    #[test]
    fn loading_problems_are_explained() {
        assert!(
            load_baseline(Path::new("/definitely/not/here.json"))
                .unwrap_err()
                .contains("triagex baseline")
        );
        let t = Tmp::new("junk");
        t.write("b.json", "not json");
        assert!(
            load_baseline(&t.path("b.json"))
                .unwrap_err()
                .contains("not a valid baseline")
        );
    }

    #[test]
    fn summaries_count_each_kind() {
        let t = Tmp::new("sum");
        t.write("a", "1");
        t.write("d/b", "2");
        symlink("a", t.path("ln")).unwrap();
        let base = create_baseline(&opts(&t));
        let s = summarize("x", Path::new("/p/x.json"), &base);
        assert_eq!((s.files, s.dirs, s.symlinks), (2, 2, 1));
        assert_eq!(s.hashed, 2);
        assert_eq!(s.digest, base.digest);
        assert_eq!(s.skipped_total, 0);
    }

    #[test]
    fn baseline_names_and_data_dirs() {
        assert!(valid_name("web-1.prod"));
        assert!(!valid_name(""));
        assert!(!valid_name("../evil"));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("a/b"));
        assert!(baseline_path(Path::new("/x"), "../evil").is_err());
        assert_eq!(
            data_dir_for(true, Some("/x"), Some("/h")),
            PathBuf::from("/var/lib/triagex")
        );
        assert_eq!(
            data_dir_for(false, Some("/x"), Some("/h")),
            PathBuf::from("/x/triagex")
        );
        assert_eq!(
            data_dir_for(false, None, Some("/h")),
            PathBuf::from("/h/.local/share/triagex")
        );
        assert_eq!(
            data_dir_for(false, Some(""), Some("/h")),
            PathBuf::from("/h/.local/share/triagex")
        );
    }

    // ---------- hang protection ----------

    fn entry_stub() -> Entry {
        Entry {
            kind: EntryKind::File,
            size: 1,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            hash: None,
            target: None,
        }
    }

    #[test]
    fn a_finished_scan_is_not_marked_aborted() {
        let t = Tmp::new("fin");
        t.write("a", "1");
        let s = scan(&opts(&t));
        assert!(s.aborted.is_none());
        assert!(s.skipped.iter().all(|k| k.path != ABORTED_PATH));
    }

    #[test]
    fn a_stuck_scan_gives_up_and_returns_what_it_had() {
        let started = Instant::now();
        let s = run_guarded(Duration::from_millis(200), |sh| {
            sh.at("/data/ok");
            sh.insert("/data/ok".into(), entry_stub());
            sh.at("/mnt/dead-nfs/file");
            // Stands in for a stat() on a stale NFS mount.
            thread::sleep(Duration::from_secs(30));
        });
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(s.entries.len(), 1);
        assert!(s.aborted.as_deref().unwrap().contains("no progress"));
        let at = s
            .skipped
            .iter()
            .find(|k| k.path == "/mnt/dead-nfs/file")
            .expect("the path it was stuck at is named");
        assert!(at.reason.contains("did not answer"));
        assert!(s.skipped.iter().any(|k| k.path == ABORTED_PATH));
    }

    #[test]
    fn steady_progress_is_not_mistaken_for_a_hang() {
        // Takes longer overall than the stall limit, but never goes quiet for that long.
        let s = run_guarded(Duration::from_millis(300), |sh| {
            for i in 0..12 {
                sh.at("/slow");
                sh.insert(format!("/slow/{i}"), entry_stub());
                thread::sleep(Duration::from_millis(60));
            }
        });
        assert!(s.aborted.is_none());
        assert_eq!(s.entries.len(), 12);
    }

    #[test]
    fn a_walker_that_wakes_late_changes_nothing() {
        let s = run_guarded(Duration::from_millis(100), |sh| {
            thread::sleep(Duration::from_millis(600));
            if !sh.is_abandoned() {
                sh.insert("/late".into(), entry_stub());
            }
        });
        assert!(s.aborted.is_some());
        thread::sleep(Duration::from_millis(800));
        assert!(s.entries.is_empty());
    }

    #[test]
    fn network_mounts_below_a_root_are_skipped_without_being_touched() {
        let t = Tmp::new("nfs");
        t.write("keep/a", "1");
        t.write("mnt/inside", "2");
        let root = fs::canonicalize(&t.0).unwrap();
        let mut hp = HashMap::new();
        hp.insert(root.join("mnt"), "nfs4".to_string());

        let sh = Shared::new();
        let o = opts(&t);
        let dev = fs::metadata(&root).map(|m| m.dev()).ok();
        walk(&root, dev, &o, &hp, &sh);
        let s = lock(&sh.scan);

        assert!(s.entries.contains_key(&key(&t, "keep/a")));
        assert!(
            !s.entries.contains_key(&key(&t, "mnt")),
            "mount point was stat'ed"
        );
        assert!(!s.entries.contains_key(&key(&t, "mnt/inside")));
        let why = s.skipped.iter().find(|k| k.path.ends_with("/mnt")).unwrap();
        assert!(why.reason.contains("nfs4 mount point"));
    }

    #[test]
    fn a_root_that_is_itself_a_network_mount_is_still_scanned() {
        let t = Tmp::new("nfsroot");
        t.write("a", "1");
        let root = fs::canonicalize(&t.0).unwrap();
        let mut hp = HashMap::new();
        hp.insert(root.clone(), "nfs4".to_string());

        let sh = Shared::new();
        let dev = fs::metadata(&root).map(|m| m.dev()).ok();
        walk(&root, dev, &opts(&t), &hp, &sh);
        assert!(lock(&sh.scan).entries.contains_key(&key(&t, "a")));
    }

    #[test]
    fn an_incomplete_scan_does_not_report_unreached_files_as_deleted() {
        let t = Tmp::new("partial");
        t.write("a", "1");
        t.write("b", "2");
        let base = create_baseline(&opts(&t));
        assert_eq!(base.aborted_reason(), None);

        let cut_short = Scan {
            aborted: Some("no progress for 15 s".into()),
            skipped: vec![skip(ABORTED_PATH, "scan stopped early")],
            ..Scan::default()
        };
        let r = verify("t", &base, None, &cut_short);
        assert!(r.deleted.is_empty());
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "integrity.scan-incomplete")
            .expect("says the comparison is incomplete");
        assert_eq!(f.severity, Severity::Warning);
        assert!(!r.findings.iter().any(|f| f.id == "integrity.deleted"));
    }

    #[test]
    fn a_complete_scan_still_reports_deleted_files() {
        let t = Tmp::new("deleted-still");
        t.write("a", "1");
        t.write("b", "2");
        let base = create_baseline(&opts(&t));
        fs::remove_file(t.path("b")).unwrap();
        let r = verify_baseline("t", &base, None);
        assert_eq!(r.deleted, vec![key_of_removed(&t, "b")]);
        assert!(
            !r.findings
                .iter()
                .any(|f| f.id == "integrity.scan-incomplete")
        );
    }

    fn key_of_removed(t: &Tmp, rel: &str) -> String {
        fs::canonicalize(&t.0)
            .unwrap()
            .join(rel)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn a_baseline_from_an_aborted_scan_is_recognised() {
        let t = Tmp::new("abase");
        t.write("a", "1");
        let mut base = create_baseline(&opts(&t));
        assert_eq!(base.aborted_reason(), None);
        base.skipped.push(skip(
            ABORTED_PATH,
            "scan stopped early: no progress for 15 s",
        ));
        assert!(base.aborted_reason().unwrap().contains("no progress"));
    }
}
