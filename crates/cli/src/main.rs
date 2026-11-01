use std::process::ExitCode;

use triagex_core::{Snapshot, finding::Severity, rules};

fn main() -> ExitCode {
    let json = std::env::args().any(|a| a == "--json");

    let snap = Snapshot::collect();
    let findings = rules::evaluate(&snap);

    if json {
        match serde_json::to_string_pretty(&findings) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("triagex: failed to serialize findings: {e}");
                return ExitCode::from(3);
            }
        }
    } else {
        println!("triagex | host: {}\n", snap.hostname);

        println!("Checked:");
        for reading in snap.readings() {
            println!(" {reading}");
        }
        println!();
        if findings.is_empty() {
            println!("No issues found.");
        }
        for f in &findings {
            let tag = match f.severity {
                Severity::Critical => "[CRIT]",
                Severity::Warning => "[WARN]",
                Severity::Info => "[INFO]",
            };
            println!("{tag} {}", f.title);
            println!("  evidence: {}", f.evidence);
            println!("  next:   {}", f.next_step);
            println!();
        }
        if !snap.skipped.is_empty() {
            println!("Skipped:");
            for s in snap.skipped {
                println!("  -   {s}");
            }
        }
    }

    match findings.iter().map(|f| f.severity).max() {
        Some(Severity::Critical) => ExitCode::from(2),
        Some(Severity::Warning) => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}
