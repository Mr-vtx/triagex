use crate::{
    Snapshot,
    collectors::docker::ContainerInfo,
    finding::{Finding, Severity},
    util::human_bytes,
};

// Thresholds live here so the rules stay transparent and easy to audit.
pub const LOAD_WARN: f64 = 1.0;
pub const LOAD_CRIT: f64 = 2.0;
pub const MEM_AVAILABLE_WARN_PCT: f64 = 15.0;
pub const MEM_AVAILABLE_CRIT_PCT: f64 = 5.0;
pub const SWAP_WARN_PCT: f64 = 50.0;
pub const SWAP_CRIT_PCT: f64 = 80.0;
pub const DISK_WARN_PCT: f64 = 80.0;
pub const DISK_CRIT_PCT: f64 = 90.0;
pub const INODE_WARN_PCT: f64 = 80.0;
pub const INODE_CRIT_PCT: f64 = 90.0;

/// Severity for "higher is worse" readings.
pub fn high(value: f64, warn: f64, crit: f64) -> Option<Severity> {
    if value >= crit {
        Some(Severity::Critical)
    } else if value >= warn {
        Some(Severity::Warning)
    } else {
        None
    }
}

/// Like `high`, but for an optional reading; returns the value alongside the severity.
fn level(value: Option<f64>, warn: f64, crit: f64) -> Option<(f64, Severity)> {
    let v = value?;
    high(v, warn, crit).map(|sev| (v, sev))
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

        if let Some((swap, sev)) = level(mem.swap_used_pct(), SWAP_WARN_PCT, SWAP_CRIT_PCT) {
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

    for disk in &snap.disks {
        if let Some((used, sev)) = level(Some(disk.used_pct()), DISK_WARN_PCT, DISK_CRIT_PCT) {
            out.push(finding(
                &format!("disk.usage:{}", disk.mount),
                sev,
                &format!("Disk space is running low on {}", disk.mount),
                format!(
                    "{:.1}% used; {} free of {} ({}).",
                    used,
                    human_bytes(disk.avail_bytes),
                    human_bytes(disk.total_bytes),
                    disk.fstype
                ),
                &format!(
                    "See what is taking space with: du -xh {} --max-depth=1 2>/dev/null | sort -h | tail -n 10. If df reports much more used than du explains, a deleted file may still be held open by a process: check with `sudo lsof +L1`.",
                    disk.mount
                ),
                "statvfs",
            ));
        }

        if let Some((inodes, sev)) = level(disk.inode_used_pct(), INODE_WARN_PCT, INODE_CRIT_PCT) {
            out.push(finding(
                &format!("disk.inodes:{}", disk.mount),
                sev,
                &format!("Inodes are running low on {}", disk.mount),
                format!(
                    "{:.1}% of inodes used ({} of {}).",
                    inodes, disk.inodes_used, disk.inodes_total
                ),
                &format!(
                    "Many tiny files are the usual cause. Find the heavy directories with: find {} -xdev -type f | cut -d/ -f1-4 | sort | uniq -c | sort -n | tail -n 10",
                    disk.mount
                ),
                "statvfs",
            ));
        }
    }

    if let Some(units) = &snap.failed_units {
        for unit in units {
            out.push(finding(
                &format!("systemd.failed:{unit}"),
                Severity::Warning,
                &format!("systemd unit failed: {unit}"),
                format!("`systemctl --failed` lists {unit} in a failed state."),
                &format!(
                    "Inspect it with: systemctl status {unit} && journalctl -u {unit} -n 50 --no-pager"
                ),
                "systemctl",
            ));
        }
    }

    if let Some(docker) = &snap.docker {
        for c in &docker.containers {
            docker_findings(c, &mut out);
        }
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

fn docker_findings(c: &ContainerInfo, out: &mut Vec<Finding>) {
    let name = &c.name;
    let logs = format!("docker logs --tail 50 {name}");
    let code = c.exit_code.map_or("unknown".to_string(), |v| v.to_string());

    if c.oom_killed {
        out.push(finding(
            &format!("docker.oom:{name}"),
            Severity::Critical,
            &format!("Container {name} was killed for running out of memory"),
            format!(
                "Docker recorded an out-of-memory kill (state {}, exit code {code}).",
                c.state
            ),
            &format!(
                "Check its limit and usage with: docker stats --no-stream {name}. Then look for a leak: {logs}"
            ),
            "docker",
        ));
    } else if c.state == "restarting" {
        out.push(finding(
            &format!("docker.restarting:{name}"),
            Severity::Warning,
            &format!("Container {name} keeps restarting"),
            format!("State is restarting; restart count {}.", c.restart_count),
            &format!("See why it exits: {logs}"),
            "docker",
        ));
    } else if (c.state == "exited" || c.state == "dead") && c.exit_code.unwrap_or(0) != 0 {
        out.push(finding(
            &format!("docker.exited:{name}"),
            Severity::Warning,
            &format!("Container {name} exited with an error"),
            format!("State {}, exit code {code}.", c.state),
            &format!("See the last output: {logs}"),
            "docker",
        ));
    }

    if c.health.as_deref() == Some("unhealthy") {
        out.push(finding(
            &format!("docker.health:{name}"),
            Severity::Warning,
            &format!("Container {name} is failing its health check"),
            format!("Health status is unhealthy (status text: {}).", c.status),
            &format!("See the recent health results: docker inspect --format '{{{{json .State.Health}}}}' {name}"),
            "docker",
        ));
    }

    if c.state == "running" && c.restart_count >= 3 {
        out.push(finding(
            &format!("docker.restarts:{name}"),
            Severity::Warning,
            &format!("Container {name} has restarted {} times", c.restart_count),
            format!(
                "It is running now, but Docker restarted it {} times.",
                c.restart_count
            ),
            &format!("Find out what keeps stopping it: {logs}"),
            "docker",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{cpu::LoadInfo, disk::DiskInfo, memory::MemInfo};

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
            disks: vec![DiskInfo {
                mount: "/".into(),
                fstype: "ext4".into(),
                total_bytes: 100_000,
                used_bytes: 20_000,
                avail_bytes: 80_000,
                inodes_total: 1000,
                inodes_used: 100,
            }],
            failed_units: Some(vec![]),
            docker: None,
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

    #[test]
    fn full_disk_is_critical_and_names_the_mount() {
        let mut s = healthy();
        s.disks[0].used_bytes = 95_000;
        s.disks[0].avail_bytes = 5_000;
        let f = evaluate(&s);
        assert_eq!(f[0].id, "disk.usage:/");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].next_step.contains("du -xh /"));
    }

    #[test]
    fn disk_next_step_mentions_deleted_files_held_open() {
        let mut s = healthy();
        s.disks[0].used_bytes = 95_000;
        s.disks[0].avail_bytes = 5_000;
        let f = evaluate(&s);
        assert!(f[0].next_step.contains("lsof +L1"));
        assert!(f[0].next_step.contains("du -xh /"));
    }

    #[test]
    fn disk_warns_between_80_and_90_percent() {
        let mut s = healthy();
        s.disks[0].used_bytes = 85_000;
        s.disks[0].avail_bytes = 15_000;
        assert_eq!(evaluate(&s)[0].severity, Severity::Warning);
    }

    #[test]
    fn inode_exhaustion_is_detected() {
        let mut s = healthy();
        s.disks[0].inodes_used = 950;
        let f = evaluate(&s);
        assert_eq!(f[0].id, "disk.inodes:/");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn filesystems_without_inode_counts_are_not_flagged() {
        let mut s = healthy();
        s.disks[0].inodes_total = 0;
        s.disks[0].inodes_used = 0;
        assert!(evaluate(&s).is_empty());
    }

    #[test]
    fn failed_unit_becomes_a_warning_with_a_next_step() {
        let mut s = healthy();
        s.failed_units = Some(vec!["nginx.service".into()]);
        let f = evaluate(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "systemd.failed:nginx.service");
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].next_step.contains("journalctl -u nginx.service"));
    }

    #[test]
    fn unavailable_systemd_is_not_a_finding() {
        let mut s = healthy();
        s.failed_units = None;
        assert!(evaluate(&s).is_empty());
    }

    fn container(name: &str, state: &str) -> ContainerInfo {
        ContainerInfo {
            id: "abc".into(),
            name: name.into(),
            image: "img".into(),
            state: state.into(),
            status: String::new(),
            health: None,
            restart_count: 0,
            exit_code: None,
            oom_killed: false,
        }
    }

    fn with_containers(list: Vec<ContainerInfo>) -> Snapshot {
        let mut s = healthy();
        s.docker = Some(crate::collectors::docker::DockerInfo {
            socket: "/var/run/docker.sock".into(),
            containers: list,
        });
        s
    }

    #[test]
    fn healthy_containers_produce_no_findings() {
        let mut ok = container("web", "running");
        ok.health = Some("healthy".into());
        let mut stopped = container("job", "exited");
        stopped.exit_code = Some(0);
        assert!(evaluate(&with_containers(vec![ok, stopped])).is_empty());
    }

    #[test]
    fn restarting_container_is_flagged_with_logs_command() {
        let mut c = container("worker", "restarting");
        c.restart_count = 9;
        let f = evaluate(&with_containers(vec![c]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "docker.restarting:worker");
        assert!(f[0].next_step.contains("docker logs --tail 50 worker"));
    }

    #[test]
    fn crashed_container_reports_the_exit_code() {
        let mut c = container("db", "exited");
        c.exit_code = Some(137);
        let f = evaluate(&with_containers(vec![c]));
        assert_eq!(f[0].id, "docker.exited:db");
        assert!(f[0].evidence.contains("137"));
    }

    #[test]
    fn oom_kill_is_critical_and_not_double_reported() {
        let mut c = container("api", "exited");
        c.exit_code = Some(137);
        c.oom_killed = true;
        let f = evaluate(&with_containers(vec![c]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "docker.oom:api");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn unhealthy_and_flapping_containers_are_flagged() {
        let mut c = container("web", "running");
        c.health = Some("unhealthy".into());
        c.restart_count = 4;
        let ids: Vec<String> = evaluate(&with_containers(vec![c]))
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert!(ids.contains(&"docker.health:web".to_string()));
        assert!(ids.contains(&"docker.restarts:web".to_string()));
    }

    #[test]
    fn findings_are_sorted_worst_first() {
        let mut s = healthy();
        s.disks[0].used_bytes = 85_000;
        s.disks[0].avail_bytes = 15_000;
        s.load = Some(LoadInfo {
            load1: 9.0,
            load5: 8.0,
            load15: 7.0,
            cores: 4,
        });
        let f = evaluate(&s);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f.last().unwrap().severity, Severity::Warning);
    }
}
