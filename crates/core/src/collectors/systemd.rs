use std::{io::ErrorKind, process::Command, time::Duration};

use crate::guard;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT: usize = 1024 * 1024;

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
    let mut cmd = Command::new("systemctl");
    cmd.args(["--failed", "--no-legend", "--plain", "--no-pager"]);
    let out = guard::run_command(cmd, TIMEOUT, MAX_OUTPUT)
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                "systemctl not found".to_string()
            } else {
                format!("could not run systemctl: {e}")
            }
        })?
        .ok_or_else(|| {
            if guard::expired() {
                "systemctl did not answer before the run deadline (systemd may be hung)".to_string()
            } else {
                format!(
                    "systemctl did not answer within {} s (systemd may be hung)",
                    TIMEOUT.as_secs()
                )
            }
        })?;
    if !out.success {
        return Err("systemctl exited with an error".to_string());
    }
    Ok(parse_failed(&out.stdout))
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
