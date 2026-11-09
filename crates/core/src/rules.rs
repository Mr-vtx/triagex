use crate::{
    Snapshot,
    collectors::{docker::ContainerInfo, redis::RedisInfo},
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
pub const REDIS_MEM_WARN_PCT: f64 = 85.0;
pub const REDIS_MEM_CRIT_PCT: f64 = 95.0;
pub const REDIS_FRAGMENTATION_WARN: f64 = 1.5;
pub const REDIS_CLIENTS_WARN_PCT: f64 = 90.0;
pub const REDIS_PING_WARN_MS: f64 = 100.0;
/// Fragmentation ratios are noisy on tiny datasets, so only judge Redis above this size.
const REDIS_FRAGMENTATION_MIN_BYTES: u64 = 100 * 1024 * 1024;

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

    if let Some(redis) = &snap.redis {
        redis_findings(redis, &mut out);
    }

    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    out
}

fn redis_findings(r: &RedisInfo, out: &mut Vec<Finding>) {
    let source = "redis INFO";

    if let Some((pct, sev)) = level(r.memory_pct(), REDIS_MEM_WARN_PCT, REDIS_MEM_CRIT_PCT) {
        out.push(finding(
            "redis.memory",
            sev,
            "Redis is close to its memory limit",
            format!(
                "{pct:.1}% of maxmemory in use ({} of {}).",
                human_bytes(r.used_memory),
                human_bytes(r.max_memory)
            ),
            "Check the eviction policy and biggest keys: redis-cli config get maxmemory-policy; redis-cli --bigkeys",
            source,
        ));
    }

    if r.evicted_keys > 0 {
        out.push(finding(
            "redis.evictions",
            Severity::Warning,
            "Redis has been evicting keys",
            format!(
                "{} keys evicted since the server started (maxmemory is {}).",
                r.evicted_keys,
                if r.max_memory == 0 {
                    "not set".to_string()
                } else {
                    human_bytes(r.max_memory)
                }
            ),
            "Data is being dropped to stay under the memory limit. Raise maxmemory or review the policy: redis-cli config get maxmemory-policy",
            source,
        ));
    }

    match r.fragmentation_ratio {
        Some(ratio)
            if r.rss >= REDIS_FRAGMENTATION_MIN_BYTES && ratio >= REDIS_FRAGMENTATION_WARN =>
        {
            out.push(finding(
                "redis.fragmentation",
                Severity::Warning,
                "Redis memory is heavily fragmented",
                format!(
                    "Fragmentation ratio {ratio:.2}: the process uses {} of RAM for {} of data.",
                    human_bytes(r.rss),
                    human_bytes(r.used_memory)
                ),
                "Consider active defragmentation (redis-cli config set activedefrag yes) or a restart in a quiet window.",
                source,
            ));
        }
        Some(ratio) if r.used_memory >= REDIS_FRAGMENTATION_MIN_BYTES && ratio < 1.0 => {
            out.push(finding(
                "redis.swapping",
                Severity::Warning,
                "Redis may be swapping to disk",
                format!(
                    "Fragmentation ratio {ratio:.2} is below 1.0, which usually means part of Redis's memory is in swap."
                ),
                "Check swap use with: free -h. Redis latency suffers badly when it swaps.",
                source,
            ));
        }
        _ => {}
    }

    if r.rejected_connections > 0 {
        out.push(finding(
            "redis.rejected",
            Severity::Warning,
            "Redis has rejected connections",
            format!(
                "{} connections were refused since the server started (maxclients {}).",
                r.rejected_connections,
                r.max_clients.map_or("unknown".to_string(), |m| m.to_string())
            ),
            "Clients hit the connection limit. Look for leaks: redis-cli client list | wc -l, or raise maxclients.",
            source,
        ));
    }

    if let Some(max) = r.max_clients.filter(|m| *m > 0) {
        let pct = r.connected_clients as f64 / max as f64 * 100.0;
        if pct >= REDIS_CLIENTS_WARN_PCT {
            out.push(finding(
                "redis.clients",
                Severity::Warning,
                "Redis is nearly out of client slots",
                format!(
                    "{} of {max} client connections in use ({pct:.0}%).",
                    r.connected_clients
                ),
                "Find who is connected: redis-cli client list",
                source,
            ));
        }
    }

    if r.rdb_save_ok == Some(false) {
        out.push(finding(
            "redis.persistence.rdb",
            Severity::Critical,
            "Redis's last background save failed",
            "rdb_last_bgsave_status is err, so a restart could lose recent data.".to_string(),
            "Check disk space and permissions (df -h) and the Redis log, then retry: redis-cli bgsave",
            source,
        ));
    }
    if r.aof_write_ok == Some(false) {
        out.push(finding(
            "redis.persistence.aof",
            Severity::Critical,
            "Redis cannot write its append-only file",
            "aof_last_write_status is err.".to_string(),
            "Check disk space and permissions (df -h) and the Redis log: redis-cli info persistence",
            source,
        ));
    }

    if r.role == "slave" && r.master_link_up == Some(false) {
        out.push(finding(
            "redis.replication",
            Severity::Warning,
            "Redis replica has lost its master",
            "master_link_status is down.".to_string(),
            "See the replication details: redis-cli info replication",
            source,
        ));
    }

    if r.ping_ms >= REDIS_PING_WARN_MS {
        out.push(finding(
            "redis.latency",
            Severity::Warning,
            "Redis is slow to answer",
            format!(
                "PING took {:.0} ms; on a local server it should take well under 1 ms.",
                r.ping_ms
            ),
            "Look for slow commands: redis-cli slowlog get 10, and check CPU load.",
            source,
        ));
    }
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
            redis: None,
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

    fn redis() -> RedisInfo {
        RedisInfo {
            addr: "127.0.0.1:6379".into(),
            version: "7.2.4".into(),
            role: "master".into(),
            uptime_secs: 1000,
            connected_clients: 10,
            max_clients: Some(10_000),
            used_memory: 50 * 1024 * 1024,
            max_memory: 0,
            rss: 60 * 1024 * 1024,
            fragmentation_ratio: Some(1.2),
            evicted_keys: 0,
            rejected_connections: 0,
            keys: 100,
            rdb_save_ok: Some(true),
            aof_write_ok: Some(true),
            master_link_up: None,
            ping_ms: 0.3,
        }
    }

    fn with_redis(r: RedisInfo) -> Vec<Finding> {
        let mut s = healthy();
        s.redis = Some(r);
        evaluate(&s)
    }

    #[test]
    fn a_healthy_redis_is_quiet() {
        assert!(with_redis(redis()).is_empty());
    }

    #[test]
    fn redis_near_its_memory_limit_warns_then_goes_critical() {
        let mut r = redis();
        r.max_memory = 100 * 1024 * 1024; // 50% used
        assert!(with_redis(r.clone()).is_empty());
        r.max_memory = 58 * 1024 * 1024; // 86%
        assert_eq!(with_redis(r.clone())[0].severity, Severity::Warning);
        r.max_memory = 51 * 1024 * 1024; // 98%
        let f = with_redis(r);
        assert_eq!(f[0].id, "redis.memory");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn evictions_and_rejections_are_flagged() {
        let mut r = redis();
        r.evicted_keys = 12;
        r.rejected_connections = 4;
        let ids: Vec<String> = with_redis(r).into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"redis.evictions".to_string()));
        assert!(ids.contains(&"redis.rejected".to_string()));
    }

    #[test]
    fn fragmentation_is_ignored_on_tiny_datasets_but_flagged_on_big_ones() {
        let mut r = redis();
        r.fragmentation_ratio = Some(3.0);
        r.rss = 5 * 1024 * 1024; // tiny: ratio is noise
        assert!(with_redis(r.clone()).is_empty());
        r.rss = 300 * 1024 * 1024;
        assert_eq!(with_redis(r)[0].id, "redis.fragmentation");
    }

    #[test]
    fn a_ratio_below_one_on_a_big_dataset_suggests_swapping() {
        let mut r = redis();
        r.used_memory = 400 * 1024 * 1024;
        r.rss = 300 * 1024 * 1024;
        r.fragmentation_ratio = Some(0.75);
        assert_eq!(with_redis(r)[0].id, "redis.swapping");
    }

    #[test]
    fn failed_persistence_is_critical() {
        let mut r = redis();
        r.rdb_save_ok = Some(false);
        r.aof_write_ok = Some(false);
        let f = with_redis(r);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.severity == Severity::Critical));
    }

    #[test]
    fn a_replica_without_its_master_and_a_slow_ping_are_flagged() {
        let mut r = redis();
        r.role = "slave".into();
        r.master_link_up = Some(false);
        r.ping_ms = 250.0;
        let ids: Vec<String> = with_redis(r).into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"redis.replication".to_string()));
        assert!(ids.contains(&"redis.latency".to_string()));
    }

    #[test]
    fn nearly_full_client_slots_are_flagged() {
        let mut r = redis();
        r.max_clients = Some(100);
        r.connected_clients = 95;
        assert_eq!(with_redis(r)[0].id, "redis.clients");
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
