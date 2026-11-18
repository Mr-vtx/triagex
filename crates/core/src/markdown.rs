//! Renders an Investigation as a Markdown report.

use crate::{
    finding::Severity, host::format_uptime, investigation::Investigation, util::human_bytes,
};

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

    if let Some(n) = &inv.nginx {
        use crate::collectors::nginx::ConfigState;
        md.push_str("## Nginx\n\n");
        let config = match n.config.state {
            ConfigState::Passed => "passed",
            ConfigState::Failed => "FAILED",
            ConfigState::NeedsRoot => "not tested (needs root)",
            ConfigState::TimedOut => "timed out",
            ConfigState::NotRun => "not tested (no nginx binary on this host)",
        };
        md.push_str(&format!(
            "- Version: {}\n- Processes: {}\n- Config test (`nginx -t`): {config}\n",
            n.version.as_deref().unwrap_or("unknown"),
            n.processes
        ));
        for e in &n.config.errors {
            md.push_str(&format!("  - error: `{}`\n", e.replace('`', "'")));
        }
        for w in &n.config.warnings {
            md.push_str(&format!("  - warning: `{}`\n", w.replace('`', "'")));
        }
        match &n.status {
            Some(s) => md.push_str(&format!(
                "- Connections: {} active ({} reading, {} writing, {} waiting)\n- Since start: {} requests, {} accepted, {} dropped\n",
                s.active, s.reading, s.writing, s.waiting, s.requests, s.accepts, s.dropped()
            )),
            None => md.push_str("- Status page: not found (stub_status is not enabled or not on a known path)\n"),
        }
        md.push('\n');
    }

    if let Some(p) = &inv.processes {
        md.push_str("## Processes\n\n");
        md.push_str(&format!(
            "{} total, {} running, {} zombie. CPU% is per core over a {} ms sample.{}\n\n",
            p.total,
            p.running,
            p.zombies,
            p.sample_ms,
            if p.partial_view {
                " `/proc` hides other users' processes (hidepid), so this is a partial view."
            } else {
                ""
            }
        ));
        for (title, list) in [("Top CPU", &p.top_cpu), ("Top memory", &p.top_mem)] {
            md.push_str(&format!("**{title}**\n\n"));
            if list.is_empty() {
                md.push_str("Nothing above the reporting threshold.\n\n");
                continue;
            }
            md.push_str(
                "| PID | Name | User | CPU% | Memory | RAM% |\n|---|---|---|---|---|---|\n",
            );
            for e in list {
                md.push_str(&format!(
                    "| {} | {} | {} | {:.1} | {} | {:.1} |\n",
                    e.pid,
                    cell(&e.name),
                    cell(&e.user),
                    e.cpu_pct,
                    human_bytes(e.rss_bytes),
                    e.mem_pct
                ));
            }
            md.push('\n');
        }
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

    if let Some(r) = &inv.integrity {
        md.push_str("## File integrity\n\n");
        md.push_str(&format!(
            "Baseline `{}` created {} on {}; watching {}. {} paths checked.\n\n",
            r.name,
            r.created_at.replace('T', " ").trim_end_matches('Z'),
            r.hostname,
            r.roots.join(", "),
            r.checked
        ));
        md.push_str(&format!(
            "Baseline digest `{}`: {}.\n\n",
            r.digest,
            if r.digest_ok {
                "matches"
            } else {
                "DOES NOT MATCH, the baseline may have been edited"
            }
        ));
        let lists: [(&str, &Vec<String>); 4] = [
            ("Modified", &r.modified),
            ("Added", &r.added),
            ("Deleted", &r.deleted),
            ("Changed type", &r.type_changed),
        ];
        for (title, list) in lists {
            if list.is_empty() {
                continue;
            }
            md.push_str(&format!("**{title} ({})**\n\n", list.len()));
            for p in list.iter().take(50) {
                md.push_str(&format!("- `{}`\n", cell(p)));
            }
            if list.len() > 50 {
                md.push_str(&format!("- ... and {} more\n", list.len() - 50));
            }
            md.push('\n');
        }
        if !r.permissions.is_empty() {
            md.push_str(&format!(
                "**Permissions or ownership ({})**\n\n",
                r.permissions.len()
            ));
            for c in r.permissions.iter().take(50) {
                md.push_str(&format!(
                    "- `{}`: {:04o} to {:04o}, owner {}:{} to {}:{}\n",
                    cell(&c.path),
                    c.old_mode,
                    c.new_mode,
                    c.old_owner.0,
                    c.old_owner.1,
                    c.new_owner.0,
                    c.new_owner.1
                ));
            }
            md.push('\n');
        }
        if r.changes() == 0 {
            md.push_str("No changes since the baseline.\n\n");
        }
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
            nginx: None,
            processes: None,
            integrity: None,
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
    fn the_nginx_section_shows_config_and_status() {
        use crate::collectors::nginx::{ConfigState, ConfigTest, NginxInfo, StubStatus};
        assert!(!render(&sample()).contains("## Nginx"));
        let mut inv = sample();
        inv.nginx = Some(NginxInfo {
            binary: Some("/usr/sbin/nginx".into()),
            version: Some("1.24.0".into()),
            processes: 3,
            config: ConfigTest {
                state: ConfigState::Failed,
                syntax_ok: false,
                errors: vec!["[emerg] unknown `directive`".into()],
                warnings: vec![],
            },
            status: Some(StubStatus {
                active: 5,
                accepts: 10,
                handled: 9,
                requests: 40,
                reading: 0,
                writing: 1,
                waiting: 4,
            }),
            status_url: None,
        });
        let md = render(&inv);
        assert!(md.contains("## Nginx"));
        assert!(md.contains("Config test (`nginx -t`): FAILED"));
        assert!(md.contains("error: `[emerg] unknown 'directive'`"));
        assert!(md.contains("5 active (0 reading, 1 writing, 4 waiting)"));
        assert!(md.contains("1 dropped"));
    }

    #[test]
    fn the_processes_section_appears_only_with_data_and_escapes_names() {
        use crate::collectors::process::{ProcessEntry, ProcessInfo};
        let md = render(&sample());
        assert!(!md.contains("## Processes"));

        let mut inv = sample();
        inv.processes = Some(ProcessInfo {
            total: 120,
            running: 1,
            zombies: 2,
            sample_ms: 270,
            partial_view: true,
            top_cpu: vec![ProcessEntry {
                pid: 7,
                name: "a|b".into(),
                user: "app".into(),
                state: 'R',
                cpu_pct: 142.26,
                rss_bytes: 3 * 1024 * 1024,
                mem_pct: 0.5,
                threads: 2,
            }],
            ..ProcessInfo::default()
        });
        let md = render(&inv);
        assert!(md.contains("## Processes"));
        assert!(md.contains("120 total, 1 running, 2 zombie"));
        assert!(md.contains("270 ms sample"));
        assert!(md.contains("partial view"));
        assert!(md.contains("| 7 | a\\|b | app | 142.3 | 3.0 MiB | 0.5 |"));
        assert!(md.contains("Nothing above the reporting threshold."));
    }

    #[test]
    fn pipes_in_patterns_do_not_break_tables() {
        let md = render(&sample());
        assert!(md.contains("error a \\| b"));
        assert!(md.contains("| 2026-10-29 09:00:00 | - |"));
        assert!(md.contains("`api:1a2b3c4d`"));
    }
}
