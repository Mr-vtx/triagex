use std::{collections::HashSet, ffi::CString, fs, io};

const REAL_FS: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "jfs",
    "reiserfs",
];

#[derive(Debug, Clone, PartialEq)]
pub struct MountEntry {
    pub device: String,
    pub mount: String,
    pub fstype: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiskInfo {
    pub mount: String,
    pub fstype: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub avail_bytes: u64,
    pub inodes_total: u64,
    pub inodes_used: u64,
}

impl DiskInfo {
    pub fn used_pct(&self) -> f64 {
        let denom = self.used_bytes + self.avail_bytes;
        if denom == 0 {
            return 0.0;
        }
        self.used_bytes as f64 / denom as f64 * 100.0
    }

    pub fn inode_used_pct(&self) -> Option<f64> {
        if self.inodes_total == 0 {
            return None;
        }
        Some(self.inodes_used as f64 / self.inodes_total as f64 * 100.0)
    }
}

fn unescape(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

pub fn parse_mounts(s: &str) -> Vec<MountEntry> {
    s.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let device = it.next()?;
            let mount = it.next()?;
            let fstype = it.next()?;
            Some(MountEntry {
                device: unescape(device),
                mount: unescape(mount),
                fstype: fstype.to_string(),
            })
        })
        .collect()
}

#[allow(clippy::unnecessary_cast)]
fn stat(m: &MountEntry) -> Option<DiskInfo> {
    let path = CString::new(m.mount.as_str()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut s) };
    if rc != 0 {
        return None;
    }
    let frsize = s.f_frsize as u64;
    let blocks = s.f_blocks as u64;
    let files = s.f_files as u64;
    Some(DiskInfo {
        mount: m.mount.clone(),
        fstype: m.fstype.clone(),
        total_bytes: blocks * frsize,
        used_bytes: blocks.saturating_sub(s.f_bfree as u64) * frsize,
        avail_bytes: s.f_bavail as u64 * frsize,
        inodes_total: files,
        inodes_used: files.saturating_sub(s.f_ffree as u64),
    })
}

pub fn collect() -> io::Result<Vec<DiskInfo>> {
    let raw = fs::read_to_string("/proc/mounts")?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for m in parse_mounts(&raw) {
        if !REAL_FS.contains(&m.fstype.as_str()) {
            continue;
        }
        if !seen.insert(m.device.clone()) {
            continue;
        }
        if let Some(info) = stat(&m) {
            out.push(info);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mounts() {
        let sample = "/dev/vda1 / ext4 rw,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n";
        let m = parse_mounts(sample);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].mount, "/");
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[2].mount, "/mnt/my disk");
    }

    #[test]
    fn used_pct_matches_df_math() {
        let d = DiskInfo {
            mount: "/".into(),
            fstype: "ext4".into(),
            total_bytes: 100,
            used_bytes: 90,
            avail_bytes: 10,
            inodes_total: 1000,
            inodes_used: 500,
        };
        assert_eq!(d.used_pct(), 90.0);
        assert_eq!(d.inode_used_pct(), Some(50.0));
    }

    #[test]
    fn no_inodes_means_none() {
        let d = DiskInfo {
            mount: "/".into(),
            fstype: "btrfs".into(),
            total_bytes: 100,
            used_bytes: 10,
            avail_bytes: 90,
            inodes_total: 0,
            inodes_used: 0,
        };
        assert_eq!(d.inode_used_pct(), None);
    }
}
