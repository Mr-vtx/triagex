use std::{fs, io};

#[derive(Debug, Clone, PartialEq)]
pub struct LoadInfo {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub cores: usize,
}

impl LoadInfo {
    pub fn per_core_5m(&self) -> f64 {
        self.load5 / self.cores.max(1) as f64
    }
}

pub fn parse_loadavg(s: &str) -> Option<(f64, f64, f64)> {
    let mut it = s.split_whitespace();
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    Some((a, b, c))
}

pub fn collect() -> io::Result<LoadInfo> {
    let raw = fs::read_to_string("/proc/loadavg")?;
    let (load1, load5, load15) = parse_loadavg(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected /proc/loadavg format",
        )
    })?;
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    Ok(LoadInfo {
        load1,
        load5,
        load15,
        cores,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loadavg() {
        let got = parse_loadavg("0.52 0.58 0.59 1/467 12345\n");
        assert_eq!(got, Some((0.52, 0.58, 0.59)));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_loadavg("nope"), None);
    }

    #[test]
    fn per_core_divides_by_cores() {
        let l = LoadInfo {
            load1: 4.0,
            load5: 4.0,
            load15: 4.0,
            cores: 2,
        };
        assert_eq!(l.per_core_5m(), 2.0);
    }
}
