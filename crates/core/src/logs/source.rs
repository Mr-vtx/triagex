use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
    process::{Command, Stdio},
};

const MAX_LINE_BYTES: usize = 4096;

pub fn for_each_line<R: BufRead>(mut reader: R, mut f: impl FnMut(&str)) -> io::Result<()> {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        buf.truncate(MAX_LINE_BYTES);
        let text = String::from_utf8_lossy(&buf);
        f(text.trim_end_matches(['\n', '\r']));
    }
    Ok(())
}

pub fn read_file(path: &Path, f: impl FnMut(&str)) -> io::Result<()> {
    let file = File::open(path)?;
    for_each_line(BufReader::new(file), f)
}

/// Stream warnings and worse from the systemd journal. Err carries a skip reason.
pub fn read_journal(since_secs: Option<i64>, f: impl FnMut(&str)) -> Result<(), String> {
    let mut cmd = Command::new("journalctl");
    cmd.args(["--no-pager", "-q", "-o", "short-iso", "-p", "warning"]);
    if let Some(secs) = since_secs {
        cmd.arg("--since").arg(format!("{secs} seconds ago"));
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            "journalctl not found".to_string()
        } else {
            format!("could not run journalctl: {e}")
        }
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "could not read journalctl output".to_string())?;

    let read = for_each_line(BufReader::new(stdout), f);
    let status = child.wait().map_err(|e| format!("journalctl: {e}"))?;
    read.map_err(|e| format!("journalctl: {e}"))?;
    if !status.success() {
        return Err(format!(
            "journalctl exited with {status} (you may need sudo or the systemd-journal group)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lines_and_strips_newlines() {
        let mut got = Vec::new();
        for_each_line(&b"a\r\nb\nc"[..], |l| got.push(l.to_string())).unwrap();
        assert_eq!(got, vec!["a", "b", "c"]);
    }

    #[test]
    fn tolerates_invalid_utf8() {
        let mut got = Vec::new();
        for_each_line(&b"ok \xff\xfe bad\n"[..], |l| got.push(l.to_string())).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].starts_with("ok "));
    }
}
