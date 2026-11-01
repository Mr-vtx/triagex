use std::{fs, io};

#[derive(Debug, Clone, PartialEq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

impl MemInfo {
    pub fn available_pct(&self) -> f64 {
        if self.total_kb == 0 {
            return 100.0;
        }
        self.available_kb as f64 / self.total_kb as f64 * 100.0
    }

    pub fn swap_used_pct(&self) -> Option<f64> {
        if self.swap_total_kb == 0 {
            return None;
        }
        let used = self.swap_total_kb.saturating_sub(self.swap_free_kb);
        Some(used as f64 / self.swap_total_kb as f64 * 100.0)
    }
}

pub fn parse_meminfo(s: &str) -> Option<MemInfo> {
    let mut total = None;
    let mut available = None;
    let mut swap_total = 0;
    let mut swap_free = 0;

    for line in s.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value: u64 = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        match key {
            "MemTotal" => total = Some(value),
            "MemAvailable" => available = Some(value),
            "SwapTotal" => swap_total = value,
            "SwapFree" => swap_free = value,
            _ => {}
        }
    }

    Some(MemInfo {
        total_kb: total?,
        available_kb: available?,
        swap_total_kb: swap_total,
        swap_free_kb: swap_free,
    })
}

pub fn collect() -> io::Result<MemInfo> {
    let raw = fs::read_to_string("/proc/meminfo")?;
    parse_meminfo(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected /proc/meminfo format",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8192000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n";

    #[test]
    fn parses_meminfo() {
        let m = parse_meminfo(SAMPLE).unwrap();
        assert_eq!(m.total_kb, 16384000);
        assert_eq!(m.available_kb, 8192000);
        assert_eq!(m.available_pct(), 50.0);
        assert_eq!(m.swap_used_pct(), Some(50.0));
    }

    #[test]
    fn no_swap_means_none() {
        let m = parse_meminfo("MemTotal: 100 kB\nMemAvailable: 50 kB\n").unwrap();
        assert_eq!(m.swap_used_pct(), None);
    }

    #[test]
    fn missing_fields_fail() {
        assert!(parse_meminfo("MemTotal: 100 kB\n").is_none());
    }
}
