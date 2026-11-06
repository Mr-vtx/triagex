use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use triagex_core::{
    Snapshot,
    finding::{Finding, Severity},
    host::format_uptime,
    investigation::{Investigation, investigate},
    logs::{GroupView, LogOptions, LogReport, analyze},
    markdown, rules,
    time::parse_duration,
};

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

    /// print JSON instead of text
    #[arg(long)]
    json: bool,
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
}

fn main() -> ExitCode {
    // Behave like a normal Unix tool when piped (`triagex logs | head`): exit quietly on a
    // closed pipe instead of panicking. Rust ignores SIGPIPE by default.
    // SAFETY: restoring the default disposition of SIGPIPE is sound and happens before any threads start.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match cli.command {
        None => overview(&cli.since, cli.json),
        Some(Commands::Report {
            format,
            output,
            files,
            since,
            top,
        }) => report(format, output, files, &since, top),
        Some(Commands::Check { json }) => system_check(json),
        Some(Commands::Logs {
            files,
            journal,
            since,
            top,
            all,
            json,
        }) => logs(files, journal, &since, top, all, json),
    }
}

fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
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

fn overview(since: &str, json: bool) -> ExitCode {
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
        print_investigation(&inv, Some(5));
        println!(
            "Run `triagex report` for the full investigation, or `triagex logs` for log triage."
        );
    }
    exit_for(inv.worst())
}

fn report(
    format: Format,
    output: Option<PathBuf>,
    files: Vec<PathBuf>,
    since: &str,
    top: usize,
) -> ExitCode {
    let since_secs = match parse_since(since) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if output.is_some() && matches!(format, Format::Text) {
        eprintln!("triagex: --output needs --format json or --format markdown");
        return ExitCode::from(3);
    }

    let inv = investigate(&LogOptions {
        use_defaults: files.is_empty(),
        files,
        journal: false,
        since_secs,
        all_lines: false,
        top,
    });

    let rendered = match format {
        Format::Text => {
            print_investigation(&inv, None);
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

fn system_check(json: bool) -> ExitCode {
    let snap = Snapshot::collect();
    let findings = rules::evaluate(&snap);

    if json {
        if let Err(code) = print_json(&findings) {
            return code;
        }
        return exit_for(worst(&findings));
    }

    let color = use_color();
    println!(
        "{}\n",
        paint(&format!("triagex | host: {}", snap.hostname), "1", color)
    );

    println!("Checked:");
    for reading in snap.readings() {
        println!("  {reading}");
    }
    println!();

    if findings.is_empty() {
        println!("{}", paint("No issues found.", "32", color));
        println!();
    }
    print_findings(&findings, color);
    print_skipped(&snap.skipped);
    exit_for(worst(&findings))
}

fn logs(
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
        print_logs(&report);
    }
    exit_for(report.worst())
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn print_findings(findings: &[Finding], color: bool) {
    for f in findings {
        let tag = match f.severity {
            Severity::Critical => paint("[CRIT]", "1;31", color),
            Severity::Warning => paint("[WARN]", "1;33", color),
            Severity::Info => paint("[INFO]", "36", color),
        };
        println!("{tag} {}", f.title);
        println!("       evidence: {}", f.evidence);
        println!("       next:     {}", f.next_step);
        println!();
    }
}

fn print_skipped(skipped: &[String]) {
    if !skipped.is_empty() {
        println!("Skipped:");
        for s in skipped {
            println!("  - {s}");
        }
        println!();
    }
}

/// Draws a group's timeline: scaled to that group's busiest bucket, "·" for no activity.
fn sparkline(values: &[u32]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = values.iter().copied().max().unwrap_or(0);
    values
        .iter()
        .map(|&v| {
            if v == 0 || max == 0 {
                '·'
            } else {
                let idx = ((v as u64 * (BARS.len() as u64 - 1)) / max as u64) as usize;
                BARS[idx]
            }
        })
        .collect()
}

fn short_time(rfc3339: &str) -> String {
    rfc3339.replace('T', " ").trim_end_matches('Z').to_string()
}

fn print_group(rank: usize, g: &GroupView, color: bool) {
    println!(
        "{} {} {}  {}",
        paint(&format!("#{rank}"), "1", color),
        paint(&format!("x{}", g.count), "1;33", color),
        paint(&g.program, "36", color),
        sparkline(&g.timeline)
    );
    println!("    {}", g.pattern);
    if let (Some(a), Some(b)) = (&g.first_seen, &g.last_seen) {
        println!(
            "    first {}   last {}  (UTC)",
            short_time(a),
            short_time(b)
        );
    }
    println!("    e.g. {}", g.sample);
    println!();
}

fn print_logs(report: &LogReport) {
    let color = use_color();
    let window = report
        .since
        .as_deref()
        .map(|s| format!("last {s}"))
        .unwrap_or_else(|| "all time".to_string());
    println!(
        "{}",
        paint(
            &format!(
                "triagex logs {} | host: {} | {}",
                report.version, report.hostname, window
            ),
            "1",
            color
        )
    );
    if !report.sources.is_empty() {
        println!("sources: {}", report.sources.join(", "));
    }
    println!(
        "{} lines scanned, {} kept, {} groups",
        report.lines_scanned, report.lines_matched, report.groups_total
    );
    println!();

    if report.groups.is_empty() && report.skipped.is_empty() {
        println!("{}", paint("No matching log lines.", "32", color));
        println!();
    }

    for (i, g) in report.groups.iter().enumerate() {
        print_group(i + 1, g, color);
    }
    if report.groups_total > report.groups.len() {
        println!(
            "... and {} more groups (use --top {})",
            report.groups_total - report.groups.len(),
            report.groups_total
        );
        println!();
    }

    if !report.findings.is_empty() {
        println!("{}", paint("Findings", "1", color));
        println!();
        print_findings(&report.findings, color);
    }
    print_skipped(&report.skipped);
}

fn host_line(inv: &Investigation) -> String {
    let h = &inv.host;
    let mut parts = vec![format!("triagex {}", inv.version), h.hostname.clone()];
    if let Some(os) = &h.os {
        parts.push(os.clone());
    }
    if let Some(k) = &h.kernel {
        parts.push(format!("kernel {k}"));
    }
    if let Some(u) = h.uptime_secs {
        parts.push(format!("up {}", format_uptime(u)));
    }
    parts.push(format!("{} cores", h.cpu_cores));
    parts.join(" | ")
}

/// Shared by the overview (limited findings) and the report (everything).
fn print_investigation(inv: &Investigation, max_findings: Option<usize>) {
    let color = use_color();
    println!("{}", paint(&host_line(inv), "1", color));
    println!();

    if !inv.readings.is_empty() {
        println!("Checked:");
        for r in &inv.readings {
            println!("  {r}");
        }
        println!();
    }

    if inv.findings.is_empty() {
        println!("{}", paint("No issues found.", "32", color));
        println!();
    } else {
        let shown = max_findings.unwrap_or(inv.findings.len());
        print_findings(&inv.findings[..shown.min(inv.findings.len())], color);
        if inv.findings.len() > shown {
            println!(
                "... and {} more findings (see `triagex report`)",
                inv.findings.len() - shown
            );
            println!();
        }
    }

    if !inv.log_groups.is_empty() {
        let window = inv
            .since
            .as_deref()
            .map(|s| format!("last {s}"))
            .unwrap_or_else(|| "all time".to_string());
        println!(
            "{}",
            paint(
                &format!(
                    "Log highlights ({window}, {} lines scanned, {} groups)",
                    inv.log_lines_scanned, inv.log_groups_total
                ),
                "1",
                color
            )
        );
        println!();
        for (i, g) in inv.log_groups.iter().enumerate() {
            print_group(i + 1, g, color);
        }
    }

    print_skipped(&inv.skipped);

    println!(
        "{} critical, {} warning, {} info",
        inv.count(Severity::Critical),
        inv.count(Severity::Warning),
        inv.count(Severity::Info)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_scales_to_the_busiest_bucket() {
        assert_eq!(sparkline(&[0, 1, 8]), "·▁█");
        assert_eq!(sparkline(&[0, 0]), "··");
    }

    #[test]
    fn short_time_drops_t_and_z() {
        assert_eq!(short_time("2026-10-26T09:47:01Z"), "2026-10-26 09:47:01");
    }

    #[test]
    fn since_accepts_durations_and_all() {
        assert_eq!(parse_since("2h").ok(), Some(Some(7200)));
        assert_eq!(parse_since("all").ok(), Some(None));
        assert!(parse_since("banana").is_err());
    }
}
