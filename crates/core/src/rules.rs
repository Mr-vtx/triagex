use crate::{
    Snapshot,
    finding::{Finding, Severity},
    util::human_bytes,
};

pub const LOAD_WARN: f64 = 1.0;
pub const LOAD_CRIT: f64 = 2.0;
pub const MEM_AVAILABLE_WARN_PCT: f64 = 15.0;
pub const MEM_AVAILABLE_CRIT_PCT: f64 = 5.0;
pub const SWAP_WARN_PCT: f64 = 50.0;
pub const SWAP_CRIT_PCT: f64 = 80.0;

fn high(value: f64, warn: f64, crit: f64) -> Option<Severity> {
    if value >= crit {
        Some(Severity::Critical)
    } else if value >= warn {
        Some(Severity::Warning)
    } else {
        None
    }
}

fn finding(
    id: &str,
    severity: Severity,
    title: &str,
    evidence: String,
    next_step: &str,
    source: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        severity,
        title: title.to_string(),
        evidence,
        next_step: next_step.to_string(),
        source: source.to_string(),
    }
}

pub fn evaluate(snap: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(load) = &snap.load {
        let per_core = load.per_core_5m();
        if let Some(sev) = high(per_core, LOAD_WARN, LOAD_CRIT) {
            out.push(finding(
                "cpu.load",
                sev,
                "CPU load is high",
                format!(
                    "Load average {:.2} / {:.2} / {:.2} (1/5/15 min) on {} core(s); 5-min load per core is {:.2}.",
                    load.load1, load.load5, load.load15, load.cores, per_core
                ),
                "Find the busiest processes with: ps aux --sort=-%cpu | head -n 10",
                "/proc/loadavg",
            ));
        }
    }

    if let Some(mem) = &snap.memory {
        let avail = mem.available_pct();
        let sev = if avail < MEM_AVAILABLE_CRIT_PCT {
            Some(Severity::Critical)
        } else if avail < MEM_AVAILABLE_WARN_PCT {
            Some(Severity::Warning)
        } else {
            None
        };
        if let Some(sev) = sev {
            out.push(finding(
                "mem.available",
                sev,
                "Available memory is low",
                format!(
                    "{:.1}% of RAM available ({} of {}).",
                    avail,
                    human_bytes(mem.available_kb * 1024),
                    human_bytes(mem.total_kb * 1024)
                ),
                "Find the biggest consumers with: ps aux --sort=-%mem | head -n 10",
                "/proc/meminfo",
            ));
        }

        if let Some(swap) = mem.swap_used_pct()
            && let Some(sev) = high(swap, SWAP_WARN_PCT, SWAP_CRIT_PCT)
        {
            out.push(finding(
                    "mem.swap",
                    sev,
                    "Swap usage is high",
                    format!(
                        "{:.1}% of swap in use ({} of {}).",
                        swap,
                        human_bytes(mem.swap_total_kb.saturating_sub(mem.swap_free_kb) * 1024),
                        human_bytes(mem.swap_total_kb * 1024)
                    ),
                    "Heavy swapping slows everything down. Check memory consumers with: ps aux --sort=-%mem | head -n 10",
                    "/proc/meminfo",
                ));
        }
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{cpu::LoadInfo, memory::MemInfo};

    fn healthy() -> Snapshot {
        Snapshot {
            hostname: "test".into(),
            load: Some(LoadInfo {
                load1: 0.2,
                load5: 0.2,
                load15: 0.2,
                cores: 4,
            }),
            memory: Some(MemInfo {
                total_kb: 1_000_000,
                available_kb: 600_000,
                swap_total_kb: 1_000_000,
                swap_free_kb: 1_000_000,
            }),
            skipped: vec![],
        }
    }

    #[test]
    fn healthy_system_has_no_findings() {
        assert!(evaluate(&healthy()).is_empty());
    }

    #[test]
    fn high_load_is_critical() {
        let mut s = healthy();
        s.load = Some(LoadInfo {
            load1: 9.0,
            load5: 8.0,
            load15: 7.0,
            cores: 4,
        });
        let f = evaluate(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "cpu.load");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn low_memory_warns_then_goes_critical() {
        let mut s = healthy();
        s.memory.as_mut().unwrap().available_kb = 100_000;
        assert_eq!(evaluate(&s)[0].severity, Severity::Warning);
        s.memory.as_mut().unwrap().available_kb = 20_000;
        assert_eq!(evaluate(&s)[0].severity, Severity::Critical);
    }

    #[test]
    fn heavy_swap_is_flagged() {
        let mut s = healthy();
        s.memory.as_mut().unwrap().swap_free_kb = 100_000;
        let f = evaluate(&s);
        assert_eq!(f[0].id, "mem.swap");
        assert_eq!(f[0].severity, Severity::Critical);
    }
}
