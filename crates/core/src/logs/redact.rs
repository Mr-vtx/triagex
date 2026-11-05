//! Remove likely secrets from log lines before anything is grouped, printed or exported.

const KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "client_secret",
    "authorization",
];

const MASK: &str = "<redacted>";

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'"' | b'\'' | b',' | b';' | b'&' | b')' | b'}'
    )
}

fn redact_key(s: &str, key: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;

    while let Some(rel) = lower[pos..].find(key) {
        let start = pos + rel;
        let after = start + key.len();
        let mut j = after;
        if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
            j += 1;
        }
        if j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':') {
            j += 1;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                j += 1;
            }
            let vstart = j;
            while j < bytes.len() && !is_delim(bytes[j]) {
                j += 1;
            }
            // "Authorization: Bearer abc" / "Basic abc": mask the credential, not just the scheme.
            if key == "authorization" {
                let scheme = s[vstart..j].to_ascii_lowercase();
                if scheme == "bearer" || scheme == "basic" {
                    while j < bytes.len() && bytes[j] == b' ' {
                        j += 1;
                    }
                    let cstart = j;
                    while j < bytes.len() && !is_delim(bytes[j]) {
                        j += 1;
                    }
                    if j > cstart {
                        out.push_str(&s[pos..cstart]);
                        out.push_str(MASK);
                        pos = j;
                        continue;
                    }
                }
            }
            if j > vstart && &s[vstart..j] != MASK {
                out.push_str(&s[pos..vstart]);
                out.push_str(MASK);
                pos = j;
                continue;
            }
        }
        out.push_str(&s[pos..after]);
        pos = after;
    }
    out.push_str(&s[pos..]);
    out
}

fn redact_bearer(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(rel) = lower[pos..].find("bearer ") {
        let after = pos + rel + "bearer ".len();
        let mut j = after;
        while j < bytes.len() && !is_delim(bytes[j]) {
            j += 1;
        }
        out.push_str(&s[pos..after]);
        if j > after && &s[after..j] != MASK {
            out.push_str(MASK);
        } else {
            out.push_str(&s[after..j]);
        }
        pos = j;
    }
    out.push_str(&s[pos..]);
    out
}

fn redact_url_credentials(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(rel) = s[pos..].find("://") {
        let host_start = pos + rel + 3;
        let rest = &s[host_start..];
        let seg_end = rest
            .find(|c: char| c == '/' || c == '?' || c.is_whitespace())
            .unwrap_or(rest.len());
        let segment = &rest[..seg_end];
        out.push_str(&s[pos..host_start]);
        match segment.find('@') {
            Some(at) if segment[..at].contains(':') => {
                out.push_str(MASK);
                out.push_str(&segment[at..]);
            }
            _ => out.push_str(segment),
        }
        pos = host_start + seg_end;
    }
    out.push_str(&s[pos..]);
    out
}

pub fn redact(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let has_key = KEYS.iter().any(|k| lower.contains(k));
    let has_bearer = lower.contains("bearer ");
    let has_url = line.contains("://");
    if !has_key && !has_bearer && !has_url {
        return line.to_string();
    }
    let mut s = line.to_string();
    if has_url {
        s = redact_url_credentials(&s);
    }
    if has_key {
        for key in KEYS {
            s = redact_key(&s, key);
        }
    }
    if has_bearer {
        s = redact_bearer(&s);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_normal_ssh_lines_alone() {
        let l = "Failed password for root from 1.2.3.4 port 22 ssh2";
        assert_eq!(redact(l), l);
    }

    #[test]
    fn masks_key_value_secrets() {
        assert_eq!(
            redact("login ok password=hunter2 user=bob"),
            "login ok password=<redacted> user=bob"
        );
        assert_eq!(
            redact(r#"{"token":"abc123","x":1}"#),
            r#"{"token":"<redacted>","x":1}"#
        );
        assert_eq!(redact("API_KEY: sk-live-123"), "API_KEY: <redacted>");
    }

    #[test]
    fn masks_bearer_and_authorization() {
        assert_eq!(
            redact("Authorization: Bearer abc.def.ghi"),
            "Authorization: Bearer <redacted>"
        );
        assert_eq!(
            redact("sent Bearer abc123 to api"),
            "sent Bearer <redacted> to api"
        );
    }

    #[test]
    fn masks_url_credentials() {
        assert_eq!(
            redact("connect postgres://admin:s3cret@db:5432/app failed"),
            "connect postgres://<redacted>@db:5432/app failed"
        );
    }

    #[test]
    fn urls_without_credentials_are_untouched() {
        let l = "GET https://example.com/path?x=1 failed";
        assert_eq!(redact(l), l);
    }
}
