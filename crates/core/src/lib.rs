//! Triagex core collects system facts, apply transparent rules and emit findings.
//! It is Read-only, the crate never modifies the system it inspects

pub mod collectors;
pub mod finding;
pub mod rules;
pub mod util;

use collectors::{cpu::LoadInfo, disk::DiskInfo, memory::MemInfo};
use finding::Report;
use util::human_bytes;

#[derive(Debug, Default)]
pub struct Snapshot {
    pub hostname: String,
    pub load: Option<LoadInfo>,
    pub memory: Option<MemInfo>,
    pub disks: Vec<DiskInfo>,
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

        Snapshot {
            hostname: hostname(),
            load,
            memory,
            disks,
            skipped,
        }
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
