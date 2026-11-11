mod about;
mod render;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use triagex_core::{
    Snapshot,
    finding::{Finding, Severity},
    integrity::{self, DEFAULT_MAX_FILES, DEFAULT_MAX_HASH_MB, ScanOptions},
    investigation::{Investigation, investigate},
    logs::{LogOptions, analyze},
    markdown, rules,
    time::parse_duration,
};
use ui::{ColorMode, Theme, Ui};

#[derive(Parser)]
#[command(
    name = "triagex",
    version,
    about = "Linux server diagnostics. Read-only, single binary, no outbound network.",
    after_help = "Run with no command for a quick overview of this server."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Overview only: look at logs from the last N (30m, 2h, 1d, 1w, or "all")
    #[arg(long, default_value = "24h")]
    since: String,

    /// Overview only: print JSON instead of text
    #[arg(long)]
    json: bool,

    /// When to use colors
    #[arg(long, value_enum, global = true, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Color theme (or set TRIAGEX_THEME)
    #[arg(long, value_enum, global = true)]
    theme: Option<Theme>,

    /// Hide the logo banner
    #[arg(long, global = true)]
    no_banner: bool,

    /// Tighter layout: no padding inside panels, no gaps between them
    #[arg(long, global = true)]
    compact: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    #[value(alias = "md")]
    Markdown,
}

#[derive(Subcommand)]
enum Commands {
    /// Detailed investigation: system findings, log groups and evidence
    Report {
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Write the report to this file instead of printing it (json or markdown)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Log file to include (repeatable). Default: the journal plus /var/log/auth.log
        #[arg(short, long = "file")]
        files: Vec<PathBuf>,
        /// Only look at logs from the last N: 30m, 2h, 1d, 1w, or "all"
        #[arg(long, default_value = "24h")]
        since: String,
        /// How many log groups to include
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Also compare against a file-integrity baseline (default name: "default")
        #[arg(long, num_args = 0..=1, default_missing_value = "default", value_name = "NAME")]
        verify: Option<String>,
    },
    /// Record hashes, permissions and owners of files, to compare against later
    Baseline {
        /// Files or directories to watch
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Name for this baseline
        #[arg(long, default_value = "default")]
        name: String,
        /// Skip paths matching this glob or directory (repeatable)
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Files larger than this are tracked by size only
        #[arg(long, default_value_t = DEFAULT_MAX_HASH_MB)]
        max_hash_mb: u64,
        /// Stop after recording this many paths
        #[arg(long, default_value_t = DEFAULT_MAX_FILES)]
        max_files: usize,
        /// Replace an existing baseline of the same name
        #[arg(long)]
        force: bool,
        /// Print a JSON summary
        #[arg(long)]
        json: bool,
    },
    /// Compare files against a baseline (exit code: 0 ok, 1 warnings, 2 critical)
    Verify {
        /// Which baseline to compare against
        #[arg(long, default_value = "default")]
        name: String,
        /// The digest you recorded when you created the baseline
        #[arg(long)]
        expect_digest: Option<String>,
        /// Print the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Run only the system checks (exit code: 0 ok, 1 warnings, 2 critical)
    Check {
        /// Print the findings as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Group repeated log errors and show when they happened
    Logs {
        /// Log file to read (repeatable). Default: the journal plus /var/log/auth.log
        #[arg(short, long = "file")]
        files: Vec<PathBuf>,
        /// Read warnings and worse from the systemd journal
        #[arg(long)]
        journal: bool,
        /// Only look at the last N: 30m, 2h, 1d, 1w, or "all"
        #[arg(long, default_value = "24h")]
        since: String,
        /// How many groups to show
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Include every line from files, not just lines that look like problems
        #[arg(long)]
        all: bool,
        /// Print the report as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Show version, codename, author and source
    About,
}

fn main() -> ExitCode {
    // Behave like a normal Unix tool when piped (`triagex logs | head`): exit quietly on a
    // closed pipe instead of panicking. Rust ignores SIGPIPE by default.
    // SAFETY: restoring the default disposition of SIGPIPE is sound and happens before any threads start.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    let ui = Ui::detect(cli.color, ui::resolve_theme(cli.theme), cli.compact);
    // The big logo only appears when colors are on (a real terminal), never in pipes or logs.
    let banner = ui.color && !cli.no_banner;

    match cli.command {
        None => overview(&ui, &cli.since, cli.json, banner),
        Some(Commands::Report {
            format,
            output,
            files,
            since,
            top,
            verify,
        }) => report(&ui, format, output, files, &since, top, verify),
        Some(Commands::Baseline {
            paths,
            name,
            excludes,
            max_hash_mb,
            max_files,
            force,
            json,
        }) => baseline(
            &ui,
            paths,
            &name,
            excludes,
            max_hash_mb,
            max_files,
            force,
            json,
        ),
        Some(Commands::Verify {
            name,
            expect_digest,
            json,
        }) => verify_cmd(&ui, &name, expect_digest.as_deref(), json),
        Some(Commands::Check { json }) => system_check(&ui, json),
        Some(Commands::Logs {
            files,
            journal,
            since,
            top,
            all,
            json,
        }) => logs(&ui, files, journal, &since, top, all, json),
        Some(Commands::About) => {
            print!("{}", render::about_screen(&ui));
            ExitCode::SUCCESS
        }
    }
}

fn exit_for(worst: Option<Severity>) -> ExitCode {
    match worst {
        Some(Severity::Critical) => ExitCode::from(2),
        Some(Severity::Warning) => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), ExitCode> {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            println!("{s}");
            Ok(())
        }
        Err(e) => {
            eprintln!("triagex: failed to serialize output: {e}");
            Err(ExitCode::from(3))
        }
    }
}

fn parse_since(since: &str) -> Result<Option<i64>, ExitCode> {
    if since.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    match parse_duration(since) {
        Some(s) => Ok(Some(s)),
        None => {
            eprintln!(
                "triagex: invalid --since value \"{since}\" (use e.g. 30m, 2h, 1d, 1w or all)"
            );
            Err(ExitCode::from(3))
        }
    }
}

fn worst(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

fn overview(ui: &Ui, since: &str, json: bool, banner: bool) -> ExitCode {
    let since_secs = match parse_since(since) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let inv = investigate(&LogOptions {
        since_secs,
        top: 3,
        ..LogOptions::default()
    });

    if json {
        if let Err(code) = print_json(&inv) {
            return code;
        }
    } else {
        print!("{}", render::overview(ui, &inv, Some(5), banner, true));
    }
    exit_for(inv.worst())
}

fn report(
    ui: &Ui,
    format: Format,
    output: Option<PathBuf>,
    files: Vec<PathBuf>,
    since: &str,
    top: usize,
    verify: Option<String>,
) -> ExitCode {
    let since_secs = match parse_since(since) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if output.is_some() && matches!(format, Format::Text) {
        eprintln!("triagex: --output needs --format json or --format markdown");
        return ExitCode::from(3);
    }

    let mut inv = investigate(&LogOptions {
        use_defaults: files.is_empty(),
        files,
        journal: false,
        since_secs,
        all_lines: false,
        top,
    });
    if let Some(name) = verify {
        attach_integrity(&mut inv, &name);
    }

    let rendered = match format {
        Format::Text => {
            print!("{}", render::overview(ui, &inv, None, false, false));
            return exit_for(inv.worst());
        }
        Format::Json => match serde_json::to_string_pretty(&inv) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("triagex: failed to serialize report: {e}");
                return ExitCode::from(3);
            }
        },
        Format::Markdown => markdown::render(&inv),
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, rendered) {
                eprintln!("triagex: could not write {}: {e}", path.display());
                return ExitCode::from(3);
            }
            println!("Wrote report to {}", path.display());
        }
        None => println!("{rendered}"),
    }
    exit_for(inv.worst())
}

/// Compare against a baseline and fold the result into the report. A missing baseline is
/// noted in the report instead of failing it.
fn attach_integrity(inv: &mut Investigation, name: &str) {
    let result = integrity::baseline_path(&integrity::data_dir(), name)
        .and_then(|path| integrity::load_baseline(&path));
    match result {
        Ok(base) => {
            let r = integrity::verify_baseline(name, &base, None);
            inv.findings.extend(r.findings.clone());
            inv.findings
                .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
            inv.integrity = Some(r);
        }
        Err(e) => inv.skipped.push(format!("integrity: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn baseline(
    ui: &Ui,
    paths: Vec<PathBuf>,
    name: &str,
    mut excludes: Vec<String>,
    max_hash_mb: u64,
    max_files: usize,
    force: bool,
    json: bool,
) -> ExitCode {
    let data_dir = integrity::data_dir();
    let path = match integrity::baseline_path(&data_dir, name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("triagex: {e}");
            return ExitCode::from(3);
        }
    };
    if path.exists() && !force {
        eprintln!(
            "triagex: a baseline named \"{name}\" already exists at {} (use --force to replace it)",
            path.display()
        );
        return ExitCode::from(3);
    }
    // Never baseline the baselines themselves.
    excludes.push(data_dir.to_string_lossy().into_owned());

    let mut opts = ScanOptions::new(paths);
    opts.excludes = excludes;
    opts.max_files = max_files;
    opts.max_hash_bytes = max_hash_mb.saturating_mul(1024 * 1024);

    let base = integrity::create_baseline(&opts);
    if base.entries.is_empty() {
        eprintln!("triagex: nothing was recorded (are the paths correct and readable?)");
        for s in base.skipped.iter().take(5) {
            eprintln!("  {} ({})", s.path, s.reason);
        }
        return ExitCode::from(3);
    }
    if let Err(e) = integrity::save_baseline(&path, &base, force) {
        eprintln!("triagex: {e}");
        return ExitCode::from(3);
    }

    let summary = integrity::summarize(name, &path, &base);
    if json {
        if let Err(code) = print_json(&summary) {
            return code;
        }
    } else {
        print!("{}", render::baseline_screen(ui, &summary));
    }
    ExitCode::SUCCESS
}

fn verify_cmd(ui: &Ui, name: &str, expect_digest: Option<&str>, json: bool) -> ExitCode {
    let loaded = integrity::baseline_path(&integrity::data_dir(), name)
        .and_then(|path| integrity::load_baseline(&path));
    let base = match loaded {
        Ok(b) => b,
        Err(e) => {
            eprintln!("triagex: {e}");
            return ExitCode::from(3);
        }
    };
    let report = integrity::verify_baseline(name, &base, expect_digest);
    if json {
        if let Err(code) = print_json(&report) {
            return code;
        }
    } else {
        print!("{}", render::verify_screen(ui, &report));
    }
    exit_for(worst(&report.findings))
}

fn system_check(ui: &Ui, json: bool) -> ExitCode {
    let snap = Snapshot::collect();
    let findings = rules::evaluate(&snap);

    if json {
        if let Err(code) = print_json(&findings) {
            return code;
        }
    } else {
        print!(
            "{}",
            render::check(
                ui,
                &triagex_core::host::collect(),
                &snap.meters(),
                &snap.failed_units,
                &snap.docker,
                &snap.redis,
                &findings,
                &snap.skipped
            )
        );
    }
    exit_for(worst(&findings))
}

fn logs(
    ui: &Ui,
    files: Vec<PathBuf>,
    journal: bool,
    since: &str,
    top: usize,
    all: bool,
    json: bool,
) -> ExitCode {
    let since_secs = match parse_since(since) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let opts = LogOptions {
        use_defaults: files.is_empty() && !journal,
        files,
        journal,
        since_secs,
        all_lines: all,
        top,
    };
    let report = analyze(&opts);

    if json {
        if let Err(code) = print_json(&report) {
            return code;
        }
    } else {
        print!("{}", render::logs(ui, &report));
    }
    exit_for(report.worst())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_durations_and_all() {
        assert_eq!(parse_since("2h").ok(), Some(Some(7200)));
        assert_eq!(parse_since("all").ok(), Some(None));
        assert!(parse_since("banana").is_err());
    }
}
