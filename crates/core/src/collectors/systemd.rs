use std::{io::ErrorKind, process::Command};

pub fn parse_failed(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches('●').trim();
            line.split_whitespace().next().map(str::to_owned)
        })
        .filter(|unit| unit.contains('.'))
        .collect()
}

pub fn collect() -> Result<Vec<String>, String> {
    let out = Command::new("systemctl")
        .args(["--failed", "--no-legend", "--plain", "--no-pager"])
        .output()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                "systemctl not found".to_string()
            } else {
                format!("could not run systemctl: {e}")
            }
        })?;
    if !out.status.success() {
        return Err(format!("systemctl exited with {}", out.status));
    }
    Ok(parse_failed(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_units() {
        let sample = "nginx.service loaded failed failed A high performance web server\nfoo.timer loaded failed failed Foo timer\n";
        assert_eq!(parse_failed(sample), vec!["nginx.service", "foo.timer"]);
    }

    #[test]
    fn empty_output_means_none() {
        assert!(parse_failed("").is_empty());
    }
}
