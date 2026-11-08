//! Triagex core collects system facts, apply transparent rules and emit findings.
//! It is Read-only, the crate never modifies the system it inspects

pub mod collectors;
pub mod finding;
pub mod host;
pub mod investigation;
pub mod logs;
pub mod markdown;
pub mod rules;
pub mod time;
pub mod util;

use collectors::{cpu::LoadInfo, disk::DiskInfo, docker::DockerInfo, memory::MemInfo};
use finding::{Report, Severity};
use serde::Serialize;
use util::human_bytes;

/// One gauge for display: a label, how full it is, and how worried to be about it.
#[derive(Debug, Clone, Serialize)]
pub struct Meter {
    pub label: String,
    /// 0-100, for drawing a bar.
    pub percent: f64,
    /// Short text shown next to the bar, e.g. "41.2%" or "0.11/core".
    pub value: String,
    pub detail: String,
    /// None means healthy.
    pub severity: Option<Severity>,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub hostname: String,
    pub load: Option<LoadInfo>,
    pub memory: Option<MemInfo>,
    pub disks: Vec<DiskInfo>,
    /// None means the check could not run (see `skipped`).
    pub failed_units: Option<Vec<String>>,
    /// None means Docker is not installed here, or could not be queried (see `skipped`).
    pub docker: Option<DockerInfo>,
    /// Checks that could not run, with the reason. Never silently dropped.
    pub skipped: Vec<String>,
}

impl Snapshot {
    pub fn collect() -> Self {
        let mut skipped = Vec::new();

        let load = match collectors::cpu::collect() {
            Ok(v) => Some(v),
            Err(e) => {
                skipped.push(format!("cpu/load: {e}"));
                None
            }
        };
        let memory = match collectors::memory::collect() {
            Ok(v) => Some(v),
            Err(e) => {
                skipped.push(format!("memory: {e}"));
                None
            }
        };
        let disks = match collectors::disk::collect() {
            Ok(v) => v,
            Err(e) => {
                skipped.push(format!("disk: {e}"));
                Vec::new()
            }
        };

        let failed_units = match collectors::systemd::collect() {
            Ok(v) => Some(v),
            Err(e) => {
                skipped.push(format!("systemd: {e}"));
                None
            }
        };

        let docker = match collectors::docker::collect() {
            Ok(v) => v,
            Err(e) => {
                skipped.push(e);
                None
            }
        };

        Snapshot {
            hostname: hostname(),
            load,
            memory,
            disks,
            failed_units,
            docker,
            skipped,
        }
    }

    /// Gauges for the terminal UI. Severity uses the same thresholds as the rules.
    pub fn meters(&self) -> Vec<Meter> {
        let mut out = Vec::new();

        if let Some(l) = &self.load {
            let per_core = l.per_core_5m();
            out.push(Meter {
                label: "LOAD".to_string(),
                percent: (per_core * 100.0).clamp(0.0, 100.0),
                value: format!("{per_core:.2}/core"),
                detail: format!("load {:.2} {:.2} {:.2}", l.load1, l.load5, l.load15),
                severity: rules::high(per_core, rules::LOAD_WARN, rules::LOAD_CRIT),
            });
        }

        if let Some(m) = &self.memory {
            let avail = m.available_pct();
            let used = 100.0 - avail;
            let severity = if avail < rules::MEM_AVAILABLE_CRIT_PCT {
                Some(Severity::Critical)
            } else if avail < rules::MEM_AVAILABLE_WARN_PCT {
                Some(Severity::Warning)
            } else {
                None
            };
            out.push(Meter {
                label: "MEMORY".to_string(),
                percent: used.clamp(0.0, 100.0),
                value: format!("{used:.1}%"),
                detail: format!(
                    "{} free of {}",
                    human_bytes(m.available_kb * 1024),
                    human_bytes(m.total_kb * 1024)
                ),
                severity,
            });
            out.push(match m.swap_used_pct() {
                Some(p) => Meter {
                    label: "SWAP".to_string(),
                    percent: p.clamp(0.0, 100.0),
                    value: format!("{p:.1}%"),
                    detail: format!(
                        "{} of {} in use",
                        human_bytes(m.swap_total_kb.saturating_sub(m.swap_free_kb) * 1024),
                        human_bytes(m.swap_total_kb * 1024)
                    ),
                    severity: rules::high(p, rules::SWAP_WARN_PCT, rules::SWAP_CRIT_PCT),
                },
                None => Meter {
                    label: "SWAP".to_string(),
                    percent: 0.0,
                    value: "none".to_string(),
                    detail: "no swap configured".to_string(),
                    severity: None,
                },
            });
        }

        for d in &self.disks {
            let used = d.used_pct();
            let inode = d.inode_used_pct();
            let severity =
                rules::high(used, rules::DISK_WARN_PCT, rules::DISK_CRIT_PCT)
                    .max(inode.and_then(|p| {
                        rules::high(p, rules::INODE_WARN_PCT, rules::INODE_CRIT_PCT)
                    }));
            let inodes = inode
                .map(|p| format!(", inodes {p:.1}%"))
                .unwrap_or_default();
            out.push(Meter {
                label: format!("DISK {}", d.mount),
                percent: used.clamp(0.0, 100.0),
                value: format!("{used:.1}%"),
                detail: format!(
                    "{} free of {}{}",
                    human_bytes(d.avail_bytes),
                    human_bytes(d.total_bytes),
                    inodes
                ),
                severity,
            });
        }
        out
    }

    /// Plain-language readings, so "no issues" still shows what was checked.
    pub fn readings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(l) = &self.load {
            out.push(format!(
                "load: {:.2} / {:.2} / {:.2} (1/5/15 min) on {} cores",
                l.load1, l.load5, l.load15, l.cores
            ));
        }
        if let Some(m) = &self.memory {
            out.push(format!(
                "memory: {:.1}% available ({} of {})",
                m.available_pct(),
                human_bytes(m.available_kb * 1024),
                human_bytes(m.total_kb * 1024)
            ));
            match m.swap_used_pct() {
                Some(p) => out.push(format!("swap: {p:.1}% used")),
                None => out.push("swap: none".to_string()),
            }
        }
        for d in &self.disks {
            let inodes = d
                .inode_used_pct()
                .map(|p| format!(", inodes {p:.1}% used"))
                .unwrap_or_default();
            out.push(format!(
                "disk {}: {:.1}% used ({} free of {}){}",
                d.mount,
                d.used_pct(),
                human_bytes(d.avail_bytes),
                human_bytes(d.total_bytes),
                inodes
            ));
        }
        match &self.failed_units {
            Some(units) if units.is_empty() => out.push("systemd: no failed units".to_string()),
            Some(units) => out.push(format!("systemd: {} failed unit(s)", units.len())),
            None => {}
        }
        if let Some(d) = &self.docker {
            out.push(format!(
                "docker: {} containers ({} running, {} stopped, {} with problems)",
                d.containers.len(),
                d.running(),
                d.stopped(),
                d.problems()
            ));
        }
        out
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn run_check() -> Report {
    let snap = Snapshot::collect();
    let findings = rules::evaluate(&snap);
    Report {
        tool: "triagex",
        version: env!("CARGO_PKG_VERSION"),
        hostname: snap.hostname,
        findings,
        skipped: snap.skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot {
            hostname: "t".into(),
            load: Some(LoadInfo {
                load1: 0.4,
                load5: 0.4,
                load15: 0.4,
                cores: 4,
            }),
            memory: Some(MemInfo {
                total_kb: 1_000_000,
                available_kb: 100_000,
                swap_total_kb: 0,
                swap_free_kb: 0,
            }),
            disks: vec![DiskInfo {
                mount: "/".into(),
                fstype: "ext4".into(),
                total_bytes: 100_000,
                used_bytes: 50_000,
                avail_bytes: 50_000,
                inodes_total: 1000,
                inodes_used: 950,
            }],
            failed_units: Some(vec![]),
            docker: None,
            skipped: vec![],
        }
    }

    #[test]
    fn memory_meter_reports_used_and_severity() {
        let m = snap().meters();
        let mem = m.iter().find(|x| x.label == "MEMORY").unwrap();
        assert_eq!(mem.value, "90.0%");
        assert_eq!(mem.severity, Some(Severity::Warning));
    }

    #[test]
    fn no_swap_is_an_empty_healthy_meter() {
        let m = snap().meters();
        let swap = m.iter().find(|x| x.label == "SWAP").unwrap();
        assert_eq!(swap.value, "none");
        assert_eq!(swap.percent, 0.0);
        assert_eq!(swap.severity, None);
    }

    #[test]
    fn disk_meter_takes_the_worse_of_space_and_inodes() {
        let m = snap().meters();
        let disk = m.iter().find(|x| x.label == "DISK /").unwrap();
        // space is 50% (fine) but inodes are 95% (critical)
        assert_eq!(disk.severity, Some(Severity::Critical));
        assert!(disk.detail.contains("inodes 95.0%"));
    }
}
