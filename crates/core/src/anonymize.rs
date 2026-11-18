//! Scrub identifying details from text that is about to be shown or shared: IP addresses,
//! the machine's hostname and the current user's name. Meant for screenshots and bug reports.
//! It works on finished output (terminal text, JSON, Markdown), so it covers everything.

const LOOPBACK_PREFIX: &str = "127.";

pub struct Scrubber {
    hostname: String,
    users: Vec<String>,
}

impl Scrubber {
    pub fn new(hostname: &str, users: &[String]) -> Self {
        Scrubber {
            hostname: hostname.to_string(),
            users: users.to_vec(),
        }
    }

    /// Hostname from the system; user names from $USER, $LOGNAME and $SUDO_USER.
    pub fn from_env() -> Self {
        let users: Vec<String> = ["USER", "LOGNAME", "SUDO_USER"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .collect();
        Scrubber::new(&crate::hostname(), &users)
    }

    /// Like `apply`, but keeps boxed (panel) lines the same width, so borders stay straight
    /// even though masked text is shorter or longer than the original.
    pub fn apply_aligned(&self, text: &str) -> String {
        text.split_inclusive('\n')
            .map(|line| self.align_line(line))
            .collect()
    }

    fn align_line(&self, line: &str) -> String {
        let body = line.trim_end_matches('\n');
        let newline = &line[body.len()..];
        let scrubbed = self.apply(body);
        let diff = visible_width(body) as isize - visible_width(&scrubbed) as isize;
        if diff == 0 {
            return format!("{scrubbed}{newline}");
        }
        let first = visible_chars(body).next();
        let last = visible_chars(body).last();
        let (Some(first), Some(last)) = (first, last) else {
            return format!("{scrubbed}{newline}");
        };
        let boxed = matches!(first, '│' | '|' | '╭' | '╰' | '+')
            && matches!(last, '│' | '|' | '╮' | '╯' | '+');
        let Some(mut at) = scrubbed.rfind(last).filter(|_| boxed) else {
            return format!("{scrubbed}{newline}");
        };
        // the closing border may be wrapped in a color sequence: work before it
        if scrubbed[..at].ends_with('m')
            && let Some(esc) = scrubbed[..at].rfind('\x1b')
        {
            at = esc;
        }
        let fill = match first {
            '╭' | '╰' => '─',
            '+' => '-',
            _ => ' ',
        };
        let mut out = scrubbed;
        if diff > 0 {
            out.insert_str(at, &fill.to_string().repeat(diff as usize));
        } else {
            let mut remove = (-diff) as usize;
            let mut cut = at;
            while remove > 0 && out[..cut].ends_with(fill) {
                cut -= fill.len_utf8();
                remove -= 1;
            }
            out.replace_range(cut..at, "");
        }
        format!("{out}{newline}")
    }

    pub fn apply(&self, text: &str) -> String {
        let mut s = mask_addresses(text);
        s = mask_home_dirs(&s);
        s = replace_word(&s, &self.hostname, "server");
        for user in &self.users {
            // `root` is a system account, not a person; rewriting it would erase evidence.
            if user != "root" {
                s = replace_word(&s, user, "user");
            }
        }
        s
    }
}

/// Printable width: characters that are not part of an ANSI color sequence.
fn visible_width(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

fn visible_chars(s: &str) -> impl Iterator<Item = char> + '_ {
    let mut in_escape = false;
    s.chars().filter(move |&c| {
        if c == '\x1b' {
            in_escape = true;
            return false;
        }
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
            return false;
        }
        true
    })
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Replace whole-word occurrences. Words shorter than 3 characters are never replaced:
/// they would match inside too many unrelated things.
fn replace_word(text: &str, word: &str, with: &str) -> String {
    if word.len() < 3 || word == with {
        return text.to_string();
    }
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(rel) = text[from..].find(word) {
        let start = from + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_word(b[start - 1]);
        let after_ok = end >= b.len() || !is_word(b[end]);
        if before_ok && after_ok {
            out.push_str(&text[last..start]);
            out.push_str(with);
            last = end;
        }
        from = end;
    }
    out.push_str(&text[last..]);
    out
}

fn mask_home_dirs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("/home/") {
        let (head, tail) = rest.split_at(i + "/home/".len());
        out.push_str(head);
        let name_len = tail
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            .count();
        if name_len == 0 {
            rest = tail;
            continue;
        }
        out.push_str("user");
        rest = &tail[name_len..];
    }
    out.push_str(rest);
    out
}

/// IPv4 becomes `a.b.x.x` (loopback is kept); IPv6 and MAC addresses become `<addr>`.
fn mask_addresses(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        // an address never starts right after a dot (that would be the tail of 1.2.3.4.5)
        let ip_start = boundary && (i == 0 || b[i - 1] != b'.');
        if ip_start
            && b[i].is_ascii_digit()
            && let Some((len, masked)) = ipv4_at(text, i)
        {
            out.push_str(&masked);
            i += len;
            continue;
        }
        if boundary
            && (b[i].is_ascii_hexdigit() || b[i] == b':')
            && let Some(len) = ipv6_at(b, i)
        {
            out.push_str("<addr>");
            i += len;
            continue;
        }
        let ch = text[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn ipv4_at(text: &str, start: usize) -> Option<(usize, String)> {
    let b = text.as_bytes();
    let mut pos = start;
    let mut octets = [0u32; 4];
    for (n, octet) in octets.iter_mut().enumerate() {
        let from = pos;
        while pos < b.len() && b[pos].is_ascii_digit() && pos - from < 3 {
            pos += 1;
        }
        if pos == from {
            return None;
        }
        *octet = text[from..pos].parse().ok()?;
        if *octet > 255 {
            return None;
        }
        if n < 3 {
            if pos < b.len() && b[pos] == b'.' {
                pos += 1;
            } else {
                return None;
            }
        }
    }
    // not the start of a longer number or another dotted group (1.2.3.4.5, 1.2.3.4567)
    if pos < b.len()
        && (b[pos].is_ascii_digit()
            || (b[pos] == b'.' && b.get(pos + 1).is_some_and(u8::is_ascii_digit)))
    {
        return None;
    }
    let ip = &text[start..pos];
    let masked = if ip.starts_with(LOOPBACK_PREFIX) {
        ip.to_string()
    } else {
        format!("{}.{}.x.x", octets[0], octets[1])
    };
    Some((pos - start, masked))
}

fn ipv6_at(b: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut colons = 0;
    while pos < b.len() && (b[pos].is_ascii_hexdigit() || b[pos] == b':') {
        if b[pos] == b':' {
            colons += 1;
        }
        pos += 1;
    }
    let len = pos - start;
    let followed_by_word = pos < b.len() && b[pos].is_ascii_alphanumeric();
    (colons >= 3 && len >= 5 && !followed_by_word).then_some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> Scrubber {
        Scrubber::new("web-prod-1", &["vans".to_string()])
    }

    #[test]
    fn ipv4_keeps_only_the_first_two_octets() {
        assert_eq!(
            s().apply("Failed password from 45.235.78.102 port 22"),
            "Failed password from 45.235.x.x port 22"
        );
        assert_eq!(
            s().apply("a 10.0.0.2 b 192.168.1.15."),
            "a 10.0.x.x b 192.168.x.x."
        );
    }

    #[test]
    fn loopback_and_non_addresses_are_left_alone() {
        assert_eq!(
            s().apply("redis at 127.0.0.1:6379"),
            "redis at 127.0.0.1:6379"
        );
        for text in [
            "999.1.1.1",
            "1.2.3.4.5",
            "version 1.2.3",
            "v10.20.30.4000",
            "1.2.3",
            "2026-11-12",
        ] {
            assert_eq!(s().apply(text), text, "{text}");
        }
    }

    #[test]
    fn ipv6_and_mac_addresses_are_masked() {
        assert_eq!(
            s().apply("from 2001:db8:85a3::8a2e:370:7334 ok"),
            "from <addr> ok"
        );
        assert_eq!(s().apply("link aa:bb:cc:dd:ee:ff up"), "link <addr> up");
        // timestamps and ports are not addresses
        assert_eq!(s().apply("at 10:15:30 port 6379"), "at 10:15:30 port 6379");
    }

    #[test]
    fn home_directories_lose_the_user_name() {
        assert_eq!(
            s().apply("/home/alice/.local/share/triagex and /home/bob.smith/x"),
            "/home/user/.local/share/triagex and /home/user/x"
        );
        assert_eq!(s().apply("/home/"), "/home/");
    }

    #[test]
    fn hostname_and_user_are_replaced_as_whole_words() {
        assert_eq!(s().apply("host web-prod-1 up"), "host server up");
        assert_eq!(s().apply("web-prod-1.example.com"), "server.example.com");
        assert_eq!(
            s().apply("web-prod-10 and xweb-prod-1"),
            "web-prod-10 and xweb-prod-1"
        );
        assert_eq!(
            s().apply("Accepted publickey for vans from x"),
            "Accepted publickey for user from x"
        );
        assert_eq!(s().apply("vansplace"), "vansplace");
    }

    #[test]
    fn the_root_account_is_never_rewritten() {
        let sc = Scrubber::new("web-prod-1", &["root".to_string()]);
        assert_eq!(
            sc.apply("Failed password for root from 45.1.2.3 and /root/.ssh"),
            "Failed password for root from 45.1.x.x and /root/.ssh"
        );
    }

    #[test]
    fn very_short_names_are_never_replaced() {
        let sc = Scrubber::new("ab", &["x".to_string(), "al".to_string()]);
        assert_eq!(sc.apply("ab x al"), "ab x al");
    }

    #[test]
    fn colors_and_json_survive() {
        let colored = "\x1b[1;38;5;141mfrom 45.1.2.3\x1b[0m";
        assert_eq!(s().apply(colored), "\x1b[1;38;5;141mfrom 45.1.x.x\x1b[0m");
        let json = r#"{"host":"web-prod-1","ip":"45.1.2.3","n":[1,2,3]}"#;
        let out = s().apply(json);
        assert_eq!(out, r#"{"host":"server","ip":"45.1.x.x","n":[1,2,3]}"#);
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    #[test]
    fn boxed_lines_keep_their_width_after_masking() {
        let sc = Scrubber::new("web-prod-1", &["vans".to_string()]);
        let lines = [
            "│ Failed password from 45.235.78.102 port 22          │",
            "│ host web-prod-1 and path /home/vans/projects/x      │",
            "╭─ system ───────────────────────────── web-prod-1 ─╮",
            "│ from 2001:db8:85a3::8a2e:370:7334 ok                │",
            "| ascii 203.0.113.250 box                           |",
            "+---------------------- web-prod-1 --------------+",
            "\x1b[2m│\x1b[0m from 45.235.78.102 here          \x1b[2m│\x1b[0m",
        ];
        for line in lines {
            let out = sc.apply_aligned(&format!("{line}\n"));
            assert_eq!(
                visible_width(out.trim_end_matches('\n')),
                visible_width(line),
                "{line}\n{out}"
            );
            assert!(out.ends_with('\n'));
        }
    }

    #[test]
    fn replacing_with_a_longer_word_squeezes_the_padding() {
        // hostname "abc" (3) becomes "server" (6): three spaces of padding are consumed
        let sc = Scrubber::new("abc", &[]);
        let line = "│ host abc          │";
        let out = sc.apply_aligned(line);
        assert_eq!(visible_width(&out), visible_width(line));
        assert!(out.contains("host server"));
    }

    #[test]
    fn unboxed_text_is_not_padded() {
        let sc = Scrubber::new("web-prod-1", &[]);
        assert_eq!(
            sc.apply_aligned("from 45.1.2.3 now\n"),
            "from 45.1.x.x now\n"
        );
        assert_eq!(sc.apply_aligned("no newline 8.8.8.8"), "no newline 8.8.x.x");
    }

    #[test]
    fn non_ascii_text_is_untouched() {
        assert_eq!(s().apply("échec ✓ 8.8.8.8"), "échec ✓ 8.8.x.x");
    }
}
