//! One investigation = system checks + log triage, merged into a single result.
//! The overview, the report, and later the watcher and dashboard all consume this.

use serde::Serialize;

use crate::{
    Meter, Snapshot,
    collectors::docker::DockerInfo,
    finding::{Finding, Severity},
    host::{self, HostInfo},
    logs::{GroupView, LogOptions, analyze},
    rules,
    time::{format_rfc3339, now_epoch},
};

#[derive(Debug, Clone, Serialize)]
pub struct Investigation {
    pub tool: &'static str,
    pub version: &'static str,
    pub generated_at: String,
    pub host: HostInfo,
    pub since: Option<String>,
    /// What was measured, so "no issues" still shows what was checked.
    pub readings: Vec<String>,
    /// The same measurements as gauges, for the terminal UI.
    pub meters: Vec<Meter>,
    /// None means systemd could not be queried (see `skipped`).
    pub failed_units: Option<Vec<String>>,
    /// None means Docker is not installed here (or could not be queried).
    pub docker: Option<DockerInfo>,
    pub findings: Vec<Finding>,
    pub log_sources: Vec<String>,
    pub log_lines_scanned: u64,
    pub log_groups_total: usize,
    pub log_groups: Vec<GroupView>,
    pub skipped: Vec<String>,
}

impl Investigation {
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

pub fn investigate(opts: &LogOptions) -> Investigation {
    let snap = Snapshot::collect();
    let readings = snap.readings();
    let meters = snap.meters();
    let failed_units = snap.failed_units.clone();
    let docker = snap.docker.clone();
    let mut findings = rules::evaluate(&snap);
    let mut skipped = snap.skipped;

    let logs = analyze(opts);
    findings.extend(logs.findings);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    skipped.extend(logs.skipped);

    Investigation {
        tool: "triagex",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: format_rfc3339(now_epoch()),
        host: host::collect(),
        since: logs.since,
        readings,
        meters,
        failed_units,
        docker,
        findings,
        log_sources: logs.sources,
        log_lines_scanned: logs.lines_scanned,
        log_groups_total: logs.groups_total,
        log_groups: logs.groups,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, path::PathBuf};

    #[test]
    fn merges_system_readings_and_log_findings() {
        let mut text = String::new();
        for i in 0..25 {
            text.push_str(&format!(
                "2026-10-26T03:{i:02}:11+0000 vps sshd[1]: Failed password for root from 45.1.2.{} port 22 ssh2\n",
                i + 1
            ));
        }
        let path: PathBuf = std::env::temp_dir().join(format!(
            "triagex-inv-{}-{}.log",
            std::process::id(),
            now_epoch()
        ));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();

        let inv = investigate(&LogOptions {
            files: vec![path.clone()],
            journal: false,
            use_defaults: false,
            since_secs: None,
            all_lines: false,
            top: 5,
        });
        std::fs::remove_file(path).ok();

        assert!(!inv.host.hostname.is_empty());
        assert!(!inv.readings.is_empty());
        assert!(
            inv.findings
                .iter()
                .any(|f| f.id == "log.ssh.failed-passwords")
        );
        assert_eq!(inv.log_groups_total, 1);
        // findings stay sorted worst-first
        let sev: Vec<_> = inv.findings.iter().map(|f| f.severity).collect();
        assert!(sev.windows(2).all(|w| w[0] >= w[1]));
    }
}
