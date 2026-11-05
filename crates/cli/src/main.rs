use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use triagex_core::{
    Snapshot,
    finding::{Finding, Severity},
    logs::{GroupView, LogOptions, LogReport, analyze},
    rules,
    time::parse_duration,
};

#[derive(Parser)]
#[command(
    name = "triagex",
    version,
    about = "Linux server diagnostics. Read-only, single binary, no outbound network.",
    after_help = "Run with no command to check this machine's health."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Group repeated log errors and show when they happened
    Logs {
        #[arg(short, long = "file")]
        files: Vec<PathBuf>,
        #[arg(long)]
        journal: bool,
        /// Only look at the last N: 30m, 2h, 1d, 1w, or "all"
        #[arg(long, default_value = "24h")]
        since: String,
        #[arg(long, default_value_t = 10)]
        top: usize,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match cli.command {
        None => system_check(cli.json),
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
