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
    // A number glued to a unit: 250ms, 2840112kB, 512MB. Keep the unit, mask the number.
    let digits_len = w.bytes().take_while(u8::is_ascii_digit).count();
    if digits_len > 0 && digits_len < w.len() {
        let suffix = &w[digits_len..];
        if suffix.len() <= 4 && suffix.bytes().all(|b| b.is_ascii_alphabetic()) {
            return format!("<n>{suffix}");
        }
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

/// Words that usually introduce an identifier: `session abc123`, `request_id=...`.
const ID_WORDS: &[&str] = &[
    "session",
    "sid",
    "token",
    "request",
    "req",
    "trace",
    "span",
    "transaction",
    "txn",
    "tx",
    "correlation",
    "job",
    "task",
    "ticket",
];

fn is_id_key(key: &str) -> bool {
    let k = key
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .to_ascii_lowercase();
    k.len() >= 2 && (k.ends_with("id") || ID_WORDS.contains(&k.as_str()))
}

/// A value that is clearly an identifier and not a word: it has a digit, or it is a long
/// random-looking mix of upper and lower case. Plain words like "timeout" are left alone.
fn looks_like_id(value: &str) -> bool {
    if value.is_empty() || value.starts_with('<') {
        return false;
    }
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let internal_upper = value
        .chars()
        .skip(1)
        .filter(|c| c.is_ascii_uppercase())
        .count();
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    // 8+ hex characters, even with no digit (deadbeef), is an id when it follows an id key.
    let all_hex = value.len() >= 8 && value.bytes().all(|b| b.is_ascii_hexdigit());
    has_digit || all_hex || (value.chars().count() >= 12 && internal_upper >= 3 && has_lower)
}

const QUOTES: &[char] = &['"', '\''];
const DELIMITERS: &[char] = &['"', '\'', ',', ';', ')', ']', '}'];

/// Replace the identifier at the start of `value` (`abc123",...` -> `<id>",...`), keeping any
/// quotes and everything after it.
fn mask_value(value: &str) -> Option<String> {
    let after_quotes = value.trim_start_matches(QUOTES);
    let lead = &value[..value.len() - after_quotes.len()];
    let end = after_quotes.find(DELIMITERS).unwrap_or(after_quotes.len());
    let (word, rest) = after_quotes.split_at(end);
    let core = word.trim_end_matches('.');
    let dots = &word[core.len()..];
    // After an id-style key, numbers and hex are ids too: unify them so a request id that
    // happens to be all digits does not land in a different group from the hex ones.
    (looks_like_id(core) || core == "<n>" || core == "<hex>")
        .then(|| format!("{lead}<id>{dots}{rest}"))
}

/// Collapse request, trace and session ids that the character-level pass cannot recognise
/// (short or letters-only ids), by looking at the word that introduces them.
fn mask_ids(tokens: &mut [String]) {
    for i in 0..tokens.len() {
        // key=value and "key":"value"
        if let Some(idx) = tokens[i].find(['=', ':'])
            && idx > 0
            && is_id_key(&tokens[i][..idx])
            && let Some(masked) = mask_value(&tokens[i][idx + 1..])
        {
            tokens[i] = format!("{}{masked}", &tokens[i][..idx + 1]);
            continue;
        }
        // "session abc123"
        let word = tokens[i].trim_end_matches(':').to_ascii_lowercase();
        if ID_WORDS.contains(&word.as_str())
            && i + 1 < tokens.len()
            && let Some(masked) = mask_value(&tokens[i + 1])
        {
            tokens[i + 1] = masked;
        }
    }
}

pub fn normalize(msg: &str) -> String {
    let scanned = scan(msg);
    let tokens: Vec<&str> = scanned.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
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
        out.push(if is_user { "<user>" } else { tok }.to_string());
    }
    mask_ids(&mut out);
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
    fn numbers_glued_to_units_collapse() {
        assert_eq!(normalize("took 250ms"), normalize("took 90ms"));
        assert_eq!(normalize("took 250ms"), "took <n>ms");
        assert_eq!(
            normalize("Killed process 4121 (node) total-vm:2840112kB"),
            normalize("Killed process 99 (node) total-vm:512kB")
        );
        assert_eq!(
            normalize("limit 512MB used 3.2GB"),
            "limit <n>MB used <n>.<n>GB"
        );
        // words that merely start with a letter keep their digits
        assert_eq!(normalize("eth0 ext4 ssh2 sda1"), "eth0 ext4 ssh2 sda1");
        // a digit-led word that is not a unit stays intact
        assert_eq!(normalize("code 4f2b9"), "code 4f2b9");
    }

    #[test]
    fn short_and_letter_only_request_ids_collapse() {
        assert_eq!(
            normalize("error request_id=ab12cd upstream reset"),
            normalize("error request_id=zz99yy upstream reset")
        );
        assert_eq!(
            normalize("error request_id=ab12cd upstream reset"),
            "error request_id=<id> upstream reset"
        );
        assert_eq!(
            normalize("error session kQzXpLwRtYuIoPaS expired"),
            normalize("error session mNbVcXzLkJhGfDsA expired")
        );
        assert_eq!(
            normalize("error session abc123 expired"),
            "error session <id> expired"
        );
    }

    #[test]
    fn numeric_and_hex_ids_after_an_id_key_share_one_pattern() {
        assert_eq!(
            normalize("upstream failed request_id=12345678"),
            normalize("upstream failed request_id=1f2e3d4c")
        );
        assert_eq!(
            normalize("upstream failed request_id=12345678"),
            "upstream failed request_id=<id>"
        );
        // plain numbers elsewhere are still just numbers
        assert_eq!(normalize("retry 3 of 5"), "retry <n> of <n>");
    }

    #[test]
    fn hex_ids_without_digits_collapse_after_an_id_key() {
        assert_eq!(
            normalize("failed request_id=deadbeef now"),
            "failed request_id=<id> now"
        );
        // but a plain word that happens to be hex-looking is left alone elsewhere
        assert_eq!(normalize("the deadbeef value"), "the deadbeef value");
        assert_eq!(normalize("paid=decaded"), "paid=decaded");
    }

    #[test]
    fn json_style_ids_keep_their_quotes_and_commas() {
        assert_eq!(
            normalize(r#"{"request_id":"abc123","msg":"failed"}"#),
            r#"{"request_id":"<id>","msg":"failed"}"#
        );
    }

    #[test]
    fn ordinary_words_are_not_mistaken_for_ids() {
        for text in [
            "request authentication failed",
            "job completed",
            "session expired",
            "paid=true",
            "valid=false",
            "request NullPointerException thrown",
            "task scheduler stopped",
        ] {
            assert_eq!(normalize(text), text, "should be unchanged: {text}");
        }
    }

    #[test]
    fn existing_placeholders_are_left_alone() {
        assert_eq!(
            normalize("request 3f2b1c9a-1111-4222-8333-123456789abc failed"),
            "request <uuid> failed"
        );
        assert_eq!(
            normalize("trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span failed"),
            "trace_id=<id> span failed"
        );
    }

    #[test]
    fn handles_non_ascii() {
        assert_eq!(normalize("échec 12 ✓"), "échec <n> ✓");
    }
}
