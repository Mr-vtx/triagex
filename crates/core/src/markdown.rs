//! Renders an Investigation as a Markdown report.

use crate::{finding::Severity, host::format_uptime, investigation::Investigation};

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn when(rfc3339: &Option<String>) -> String {
    rfc3339
        .as_deref()
        .map(|s| s.replace('T', " ").trim_end_matches('Z').to_string())
        .unwrap_or_else(|| "-".to_string())
}

pub fn render(inv: &Investigation) -> String {
    let mut md = String::new();
    let window = inv
        .since
        .as_deref()
        .map(|s| format!("last {s}"))
        .unwrap_or_else(|| "all time".to_string());

    md.push_str(&format!("# Triagex report: {}\n\n", inv.host.hostname));
    md.push_str(&format!(
        "Generated {} UTC by triagex {}. Log window: {}.\n\n",
        inv.generated_at.replace('T', " ").trim_end_matches('Z'),
        inv.version,
        window
    ));

    md.push_str("## Host\n\n| | |\n|---|---|\n");
    md.push_str(&format!("| Hostname | {} |\n", cell(&inv.host.hostname)));
    if let Some(os) = &inv.host.os {
        md.push_str(&format!("| OS | {} |\n", cell(os)));
    }
    if let Some(k) = &inv.host.kernel {
        md.push_str(&format!("| Kernel | {} |\n", cell(k)));
    }
    if let Some(u) = inv.host.uptime_secs {
        md.push_str(&format!("| Uptime | {} |\n", format_uptime(u)));
    }
    md.push_str(&format!("| CPU cores | {} |\n\n", inv.host.cpu_cores));

    if !inv.readings.is_empty() {
        md.push_str("## Checked\n\n");
        for r in &inv.readings {
            md.push_str(&format!("- {r}\n"));
        }
        md.push('\n');
    }

    md.push_str("## Summary\n\n");
    md.push_str(&format!(
        "{} critical, {} warning, {} info.\n\n",
        inv.count(Severity::Critical),
        inv.count(Severity::Warning),
        inv.count(Severity::Info)
    ));

    md.push_str("## Findings\n\n");
    if inv.findings.is_empty() {
        md.push_str("No issues found.\n\n");
    }
    for f in &inv.findings {
        md.push_str(&format!(
            "### [{}] {}\n\n",
            f.severity.as_str().to_uppercase(),
            f.title
        ));
        md.push_str(&format!("- **Evidence:** {}\n", f.evidence));
        md.push_str(&format!("- **Next step:** {}\n", f.next_step));
        md.push_str(&format!("- **Source:** {} (`{}`)\n\n", f.source, f.id));
    }

    md.push_str("## Log groups\n\n");
    if inv.log_groups.is_empty() {
        md.push_str("No matching log lines.\n\n");
    } else {
        md.push_str(&format!(
            "{} lines scanned from {}; showing the top {} of {} groups.\n\n",
            inv.log_lines_scanned,
            if inv.log_sources.is_empty() {
                "no sources".to_string()
            } else {
                inv.log_sources.join(", ")
            },
            inv.log_groups.len(),
            inv.log_groups_total
        ));
        md.push_str(
            "| # | ID | Count | Program | Pattern | First seen (UTC) | Last seen (UTC) |\n",
        );
        md.push_str("|---|---|---|---|---|---|---|\n");
        for (i, g) in inv.log_groups.iter().enumerate() {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | `{}` | {} | {} |\n",
                i + 1,
                cell(&g.id),
                g.count,
                cell(&g.program),
                cell(&g.pattern).replace('`', "'"),
                when(&g.first_seen),
                when(&g.last_seen)
            ));
        }
        md.push('\n');
    }

    if !inv.skipped.is_empty() {
        md.push_str("## Skipped checks\n\n");
        for s in &inv.skipped {
            md.push_str(&format!("- {s}\n"));
        }
        md.push('\n');
    }

    md.push_str("---\n\nTriagex only reads system state. Findings are evidence to investigate, not root-cause conclusions.\n");
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{finding::Finding, host::HostInfo, logs::GroupView};

    fn sample() -> Investigation {
        Investigation {
            tool: "triagex",
            version: "0.1.0",
            generated_at: "2026-10-29T10:00:00Z".into(),
            host: HostInfo {
                hostname: "myvps".into(),
                os: Some("Debian 12".into()),
                kernel: Some("6.1.0".into()),
                uptime_secs: Some(90000),
                cpu_cores: 2,
            },
            since: Some("24h".into()),
            readings: vec!["load: 0.40 / 0.30 / 0.20 (1/5/15 min) on 2 cores".into()],
            meters: vec![],
            failed_units: Some(vec![]),
            docker: None,
            redis: None,
            findings: vec![Finding {
                id: "disk.usage:/".into(),
                severity: Severity::Critical,
                title: "Disk space is running low on /".into(),
                evidence: "95.0% used".into(),
                next_step: "du -xh /".into(),
                source: "statvfs".into(),
            }],
            log_sources: vec!["journalctl".into()],
            log_lines_scanned: 10,
            log_groups_total: 1,
            log_groups: vec![GroupView {
                id: "api:1a2b3c4d".into(),
                program: "api".into(),
                pattern: "error a | b".into(),
                count: 3,
                first_seen: Some("2026-10-29T09:00:00Z".into()),
                last_seen: None,
                sample: "x".into(),
                timeline: vec![],
            }],
            skipped: vec!["systemd: not available".into()],
        }
    }

    #[test]
    fn renders_all_sections() {
        let md = render(&sample());
        assert!(md.starts_with("# Triagex report: myvps"));
        assert!(md.contains("| Uptime | 1d 1h |"));
        assert!(md.contains("## Checked"));
        assert!(md.contains("- load: 0.40 / 0.30 / 0.20 (1/5/15 min) on 2 cores"));
        assert!(md.contains("1 critical, 0 warning, 0 info."));
        assert!(md.contains("### [CRITICAL] Disk space is running low on /"));
        assert!(md.contains("- **Evidence:** 95.0% used"));
        assert!(md.contains("## Skipped checks"));
        assert!(md.contains("not root-cause conclusions"));
    }

    #[test]
    fn pipes_in_patterns_do_not_break_tables() {
        let md = render(&sample());
        assert!(md.contains("error a \\| b"));
        assert!(md.contains("| 2026-10-29 09:00:00 | - |"));
        assert!(md.contains("`api:1a2b3c4d`"));
    }
}
