//! Parses the timestamp / program / message out of common Linux log line formats:
//!   - ISO 8601:   2026-10-27T09:47:01+0000 host sshd[12]: msg   (journalctl -o short-iso)
//!   - nginx-ish:  2026/10/27 09:47:01 [error] 12#12: msg
//!   - classic:    Oct 27 09:47:01 host sshd[12]: msg             (auth.log, syslog)

use crate::time::{civil_to_epoch, year_of};

#[derive(Debug, Clone, Copy)]
pub struct ParseContext {
    pub now: i64,
    /// Local offset from UTC in seconds, used for timestamps with no timezone.
    pub utc_offset: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    pub timestamp: Option<i64>,
    pub program: String,
    pub message: String,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn take_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

fn num(s: &str, start: usize, len: usize) -> Option<i64> {
    let part = s.get(start..start + len)?;
    if part.bytes().all(|b| b.is_ascii_digit()) {
        part.parse().ok()
    } else {
        None
    }
}

fn parse_iso<'a>(s: &'a str, ctx: &ParseContext) -> Option<(i64, &'a str)> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    if !(b[4] == b'-' || b[4] == b'/') || b[7] != b[4] {
        return None;
    }
    if !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(s, 0, 4)?, num(s, 5, 2)?, num(s, 8, 2)?);
    let (h, mi, sec) = (num(s, 11, 2)?, num(s, 14, 2)?, num(s, 17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    let mut idx = 19;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
    }

    let mut offset = ctx.utc_offset;
    if idx < b.len() && b[idx] == b'Z' {
        offset = 0;
        idx += 1;
    } else if idx < b.len() && (b[idx] == b'+' || b[idx] == b'-') {
        let sign = if b[idx] == b'-' { -1 } else { 1 };
        if let (Some(oh), true) = (num(s, idx + 1, 2), idx + 3 <= b.len()) {
            let (om, used) = if b.get(idx + 3) == Some(&b':') {
                (num(s, idx + 4, 2), 6)
            } else {
                (num(s, idx + 3, 2), 5)
            };
            if let Some(om) = om {
                offset = sign * (oh * 3600 + om * 60);
                idx += used;
            }
        }
    }

    let epoch = civil_to_epoch(y, mo, d, h, mi, sec) - offset;
    Some((epoch, &s[idx..]))
}

fn parse_classic<'a>(s: &'a str, ctx: &ParseContext) -> Option<(i64, &'a str)> {
    let (mon, r1) = take_token(s)?;
    let month = MONTHS.iter().position(|m| *m == mon)? as i64 + 1;
    let (day, r2) = take_token(r1)?;
    let day: i64 = day.parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }
    let (time, r3) = take_token(r2)?;
    let tb = time.as_bytes();
    if tb.len() != 8 || tb[2] != b':' || tb[5] != b':' {
        return None;
    }
    let (h, mi, sec) = (num(time, 0, 2)?, num(time, 3, 2)?, num(time, 6, 2)?);
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    // Classic syslog has no year: assume the current one, or last year if that lands in the future.
    let year = year_of(ctx.now + ctx.utc_offset);
    let mut epoch = civil_to_epoch(year, month, day, h, mi, sec) - ctx.utc_offset;
    if epoch > ctx.now + 86400 {
        epoch = civil_to_epoch(year - 1, month, day, h, mi, sec) - ctx.utc_offset;
    }
    Some((epoch, r3))
}

fn is_level_word(s: &str) -> bool {
    s.len() >= 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

fn program_name(token: &str) -> Option<String> {
    let t = token.strip_suffix(':')?;
    let name = t.split('[').next().unwrap_or(t);
    let valid = !name.is_empty()
        && name.len() <= 48
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !is_level_word(name);
    if valid { Some(name.to_string()) } else { None }
}

fn split_program(rest: &str) -> (Option<String>, String) {
    let rest = rest.trim_start();
    if let Some((t1, r1)) = take_token(rest) {
        if let Some(p) = program_name(t1) {
            return (Some(p), r1.trim().to_string());
        }
        if !is_level_word(t1)
            && let Some((t2, r2)) = take_token(r1)
            && let Some(p) = program_name(t2)
        {
            return (Some(p), r2.trim().to_string());
        }
    }
    (None, rest.trim().to_string())
}

pub fn parse_line(raw: &str, ctx: &ParseContext, default_program: &str) -> LogLine {
    let (timestamp, rest) = if let Some((t, r)) = parse_iso(raw, ctx) {
        (Some(t), r)
    } else if let Some((t, r)) = parse_classic(raw, ctx) {
        (Some(t), r)
    } else {
        (None, raw)
    };
    let (program, message) = split_program(rest);
    LogLine {
        timestamp,
        program: program.unwrap_or_else(|| default_program.to_string()),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ParseContext {
        ParseContext {
            now: civil_to_epoch(2026, 10, 29, 12, 0, 0),
            utc_offset: 0,
        }
    }

    #[test]
    fn parses_journal_short_iso() {
        let l = parse_line(
            "2026-10-27T09:47:01+0000 myvps sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
            &ctx(),
            "x",
        );
        assert_eq!(l.timestamp, Some(civil_to_epoch(2026, 10, 27, 9, 47, 1)));
        assert_eq!(l.program, "sshd");
        assert!(l.message.starts_with("Failed password"));
    }

    #[test]
    fn honours_timezone_offsets() {
        let l = parse_line("2026-10-27T10:47:01+01:00 h app: boom", &ctx(), "x");
        assert_eq!(l.timestamp, Some(civil_to_epoch(2026, 10, 27, 9, 47, 1)));
    }

    #[test]
    fn parses_classic_syslog() {
        let l = parse_line(
            "Oct  5 09:00:01 myvps sudo:   vans : TTY=pts/0 ; COMMAND=/bin/ls",
            &ctx(),
            "x",
        );
        assert_eq!(l.timestamp, Some(civil_to_epoch(2026, 10, 5, 9, 0, 1)));
        assert_eq!(l.program, "sudo");
        assert!(l.message.starts_with("vans"));
    }

    #[test]
    fn classic_dates_in_the_future_roll_back_a_year() {
        let l = parse_line("Dec 31 23:00:00 h cron[1]: x", &ctx(), "x");
        assert_eq!(l.timestamp, Some(civil_to_epoch(2025, 12, 31, 23, 0, 0)));
    }

    #[test]
    fn parses_nginx_style_and_uses_default_program() {
        let l = parse_line(
            "2026/10/27 09:47:01 [error] 12#12: *5 connect() failed (111: Connection refused)",
            &ctx(),
            "error.log",
        );
        assert_eq!(l.timestamp, Some(civil_to_epoch(2026, 10, 27, 9, 47, 1)));
        assert_eq!(l.program, "error.log");
        assert!(l.message.starts_with("[error]"));
    }

    #[test]
    fn level_words_are_not_programs() {
        let l = parse_line("2026-10-27T09:47:01Z ERROR: database down", &ctx(), "app");
        assert_eq!(l.program, "app");
        assert_eq!(l.message, "ERROR: database down");
    }

    #[test]
    fn unparseable_lines_keep_their_text() {
        let l = parse_line("something odd happened", &ctx(), "app");
        assert_eq!(l.timestamp, None);
        assert_eq!(l.message, "something odd happened");
    }
}
