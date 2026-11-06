use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub uptime_secs: Option<u64>,
    pub cpu_cores: usize,
}

pub fn parse_os_release(s: &str) -> Option<String> {
    s.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        let v = value.trim().trim_matches('"').trim_matches('\'');
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    })
}

pub fn parse_uptime(s: &str) -> Option<u64> {
    let secs: f64 = s.split_whitespace().next()?.parse().ok()?;
    if secs.is_finite() && secs >= 0.0 {
        Some(secs as u64)
    } else {
        None
    }
}

pub fn format_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub fn collect() -> HostInfo {
    HostInfo {
        hostname: crate::hostname(),
        os: std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| parse_os_release(&s)),
        kernel: read_trimmed("/proc/sys/kernel/osrelease"),
        uptime_secs: std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| parse_uptime(&s)),
        cpu_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_os_release() {
        let s = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(
            parse_os_release(s).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(parse_os_release("ID=x\n"), None);
    }

    #[test]
    fn parses_uptime() {
        assert_eq!(parse_uptime("12345.67 9999.00\n"), Some(12345));
        assert_eq!(parse_uptime("nope"), None);
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_uptime(59), "0m");
        assert_eq!(format_uptime(3 * 3600 + 5 * 60), "3h 5m");
        assert_eq!(format_uptime(2 * 86400 + 4 * 3600), "2d 4h");
    }
}
