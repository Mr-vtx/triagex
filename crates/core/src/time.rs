use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Offset of local time from UTC, in seconds, at the given instant.
#[allow(clippy::unnecessary_cast)]
pub fn local_utc_offset_secs(at: i64) -> i64 {
    let t: libc::time_t = at as libc::time_t;
    // SAFETY: tm is plain-old-data, so a zeroed value is valid as an out-parameter.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `t` and `tm` are valid for the duration of the call; localtime_r is thread-safe.
    let p = unsafe { libc::localtime_r(&t, &mut tm) };
    if p.is_null() { 0 } else { tm.tm_gmtoff as i64 }
}

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn civil_to_epoch(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
}

pub fn epoch_to_civil(epoch: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    (y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60)
}

pub fn year_of(epoch: i64) -> i64 {
    epoch_to_civil(epoch).0
}

/// "2026-10-27 09:47:01" (UTC)
pub fn format_utc(epoch: i64) -> String {
    let (y, m, d, h, mi, s) = epoch_to_civil(epoch);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// "2026-10-27T09:47:01Z"
pub fn format_rfc3339(epoch: i64) -> String {
    let (y, m, d, h, mi, s) = epoch_to_civil(epoch);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Parses "90s", "30m", "2h", "1d", "1w" into seconds.
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 2 {
        return None;
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.parse().ok()?;
    if n <= 0 {
        return None;
    }
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return None,
    };
    n.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_roundtrip() {
        let e = civil_to_epoch(2026, 10, 27, 9, 47, 1);
        assert_eq!(epoch_to_civil(e), (2026, 10, 27, 9, 47, 1));
        assert_eq!(format_utc(e), "2026-10-27 09:47:01");
        assert_eq!(format_rfc3339(e), "2026-10-27T09:47:01Z");
    }

    #[test]
    fn known_epochs() {
        assert_eq!(civil_to_epoch(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(civil_to_epoch(2000, 3, 1, 0, 0, 0), 951868800);
        assert_eq!(civil_to_epoch(2024, 2, 29, 12, 0, 0), 1709208000);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("1d"), Some(86400));
        assert_eq!(parse_duration("1w"), Some(604800));
        assert_eq!(parse_duration("0h"), None);
        assert_eq!(parse_duration("h"), None);
        assert_eq!(parse_duration("5x"), None);
    }
}
