//! Turns a log message into a stable "pattern" so repeats collapse into one group:
//! IPs, numbers, hex ids, UUIDs and usernames are replaced with placeholders.

const MAX_PATTERN: usize = 200;

fn match_ipv4(b: &[u8], i: usize) -> Option<usize> {
    let mut pos = i;
    for group in 0..4 {
        let start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() && pos - start < 3 {
            pos += 1;
        }
        if pos == start {
            return None;
        }
        if group < 3 {
            if pos < b.len() && b[pos] == b'.' {
                pos += 1;
            } else {
                return None;
            }
        }
    }
    if pos < b.len() && b[pos].is_ascii_digit() {
        return None;
    }
    Some(pos - i)
}

fn match_uuid(b: &[u8], i: usize) -> Option<usize> {
    if i + 36 > b.len() {
        return None;
    }
    for k in 0..36 {
        let c = b[i + k];
        let dash = matches!(k, 8 | 13 | 18 | 23);
        if dash != (c == b'-') || (!dash && !c.is_ascii_hexdigit()) {
            return None;
        }
    }
    if i + 36 < b.len() && b[i + 36].is_ascii_alphanumeric() {
        return None;
    }
    Some(36)
}

/// IPv6 and MAC addresses: a run of hex digits and colons with at least three colons.
fn match_addr(b: &[u8], i: usize) -> Option<usize> {
    let mut pos = i;
    let mut colons = 0;
    while pos < b.len() && (b[pos].is_ascii_hexdigit() || b[pos] == b':') {
        if b[pos] == b':' {
            colons += 1;
        }
        pos += 1;
    }
    let len = pos - i;
    if colons >= 3 && len >= 5 && !(pos < b.len() && b[pos].is_ascii_alphanumeric()) {
        Some(len)
    } else {
        None
    }
}

fn classify_word(w: &str) -> String {
    let all_digits = w.bytes().all(|b| b.is_ascii_digit());
    if all_digits {
        return "<n>".into();
    }
    if (w.starts_with("0x") || w.starts_with("0X"))
        && w.len() > 2
        && w[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return "<hex>".into();
    }
    let all_hex = w.bytes().all(|b| b.is_ascii_hexdigit());
    let any_digit = w.bytes().any(|b| b.is_ascii_digit());
    if w.len() >= 8 && all_hex && any_digit {
        return "<hex>".into();
    }
    let any_alpha = w.bytes().any(|b| b.is_ascii_alphabetic());
    if w.len() >= 12 && any_digit && any_alpha {
        return "<id>".into();
    }
    w.to_string()
}

fn scan(msg: &str) -> String {
    let b = msg.as_bytes();
    let mut out = String::with_capacity(msg.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if boundary
            && c.is_ascii_digit()
            && let Some(n) = match_ipv4(b, i)
        {
            out.push_str("<ip>");
            i += n;
            continue;
        }
        if boundary
            && c.is_ascii_hexdigit()
            && let Some(n) = match_uuid(b, i)
        {
            out.push_str("<uuid>");
            i += n;
            continue;
        }
        if boundary
            && (c.is_ascii_hexdigit() || c == b':')
            && let Some(n) = match_addr(b, i)
        {
            out.push_str("<addr>");
            i += n;
            continue;
        }
        if c.is_ascii_alphanumeric() {
            let start = i;
            while i < b.len() && b[i].is_ascii_alphanumeric() {
                i += 1;
            }
            out.push_str(&classify_word(&msg[start..i]));
            continue;
        }
        let ch = msg[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn normalize(msg: &str) -> String {
    let scanned = scan(msg);
    let tokens: Vec<&str> = scanned.split_whitespace().collect();
    let mut out: Vec<&str> = Vec::with_capacity(tokens.len());
    let mut prev_was_user = false;
    for (i, tok) in tokens.iter().enumerate() {
        let prev = if i >= 1 { tokens[i - 1] } else { "" };
        let prev2 = if i >= 2 { tokens[i - 2] } else { "" };
        // A username can itself be "user"; never treat the word after a username as another one.
        let is_user = !prev_was_user
            && (prev == "user"
                || (prev == "for"
                    && matches!(prev2, "password" | "publickey" | "keyboard-interactive/pam")
                    && *tok != "invalid"));
        prev_was_user = is_user;
        out.push(if is_user { "<user>" } else { tok });
    }
    let mut joined = out.join(" ");
    if joined.len() > MAX_PATTERN {
        let mut cut = MAX_PATTERN;
        while !joined.is_char_boundary(cut) {
            cut -= 1;
        }
        joined.truncate(cut);
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_failures_collapse_to_one_pattern() {
        let a = normalize("Failed password for invalid user admin from 45.12.7.9 port 51234 ssh2");
        let b = normalize("Failed password for invalid user test from 103.4.5.6 port 40022 ssh2");
        assert_eq!(a, b);
        assert_eq!(
            a,
            "Failed password for invalid user <user> from <ip> port <n> ssh2"
        );
    }

    #[test]
    fn valid_users_are_replaced_too() {
        assert_eq!(
            normalize("Failed password for root from 1.2.3.4 port 22 ssh2"),
            "Failed password for <user> from <ip> port <n> ssh2"
        );
        assert_eq!(
            normalize("Accepted publickey for vans from 1.2.3.4 port 22 ssh2"),
            "Accepted publickey for <user> from <ip> port <n> ssh2"
        );
    }

    #[test]
    fn a_user_literally_named_user_does_not_swallow_the_next_word() {
        assert_eq!(
            normalize("Failed password for invalid user user from 1.2.3.4 port 22 ssh2"),
            "Failed password for invalid user <user> from <ip> port <n> ssh2"
        );
    }

    #[test]
    fn numbers_ids_and_hex_are_masked() {
        assert_eq!(
            normalize("worker 4321 exited code 137 at 0xdeadbeef"),
            "worker <n> exited code <n> at <hex>"
        );
        assert_eq!(
            normalize("request 3f2b1c9a-1111-4222-8333-123456789abc failed"),
            "request <uuid> failed"
        );
    }

    #[test]
    fn ipv6_and_mac_are_masked() {
        assert_eq!(normalize("from 2001:db8::1 refused"), "from <addr> refused");
        assert_eq!(normalize("link aa:bb:cc:dd:ee:ff down"), "link <addr> down");
    }

    #[test]
    fn short_words_with_digits_are_kept() {
        assert_eq!(
            normalize("eth0 link down on ext4 sda1"),
            "eth0 link down on ext4 sda1"
        );
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(normalize("Connection refused"), "Connection refused");
    }

    #[test]
    fn handles_non_ascii() {
        assert_eq!(normalize("échec 12 ✓"), "échec <n> ✓");
    }
}
