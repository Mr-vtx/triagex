use std::collections::{BTreeMap, HashMap};

use super::normalize::normalize;

const MAX_SAMPLE: usize = 240;

#[derive(Debug, Clone)]
pub struct LogGroup {
    pub program: String,
    pub pattern: String,
    pub count: u64,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub sample: String,
    pub minutes: BTreeMap<i64, u32>,
}

#[derive(Debug, Default)]
pub struct Grouper {
    groups: HashMap<(String, String), LogGroup>,
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &s[..cut])
}

impl Grouper {
    pub fn new() -> Self {
        Self::default()
    }

    /// `message` must already be redacted.
    pub fn add(&mut self, program: &str, message: &str, ts: Option<i64>) {
        let pattern = normalize(message);
        if pattern.is_empty() {
            return;
        }
        let group = self
            .groups
            .entry((program.to_string(), pattern.clone()))
            .or_insert_with(|| LogGroup {
                program: program.to_string(),
                pattern,
                count: 0,
                first_seen: None,
                last_seen: None,
                sample: truncate(message, MAX_SAMPLE),
                minutes: BTreeMap::new(),
            });
        group.count += 1;
        if let Some(t) = ts {
            group.first_seen = Some(group.first_seen.map_or(t, |f| f.min(t)));
            group.last_seen = Some(group.last_seen.map_or(t, |l| l.max(t)));
            *group.minutes.entry(t.div_euclid(60)).or_insert(0) += 1;
        }
    }

    pub fn into_sorted(self) -> Vec<LogGroup> {
        let mut groups: Vec<LogGroup> = self.groups.into_values().collect();
        groups.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
                .then_with(|| a.pattern.cmp(&b.pattern))
        });
        groups
    }
}

/// Spreads a group's per-minute counts over `buckets` equal slices of [gmin, gmax] (minutes).
pub fn timeline(minutes: &BTreeMap<i64, u32>, gmin: i64, gmax: i64, buckets: usize) -> Vec<u32> {
    let mut out = vec![0u32; buckets];
    if buckets == 0 || gmax < gmin {
        return out;
    }
    let span = (gmax - gmin + 1) as u128;
    for (m, c) in minutes {
        let idx = (((m - gmin).max(0) as u128 * buckets as u128) / span) as usize;
        out[idx.min(buckets - 1)] += c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_collapse_and_track_time() {
        let mut g = Grouper::new();
        g.add(
            "sshd",
            "Failed password for root from 1.1.1.1 port 1 ssh2",
            Some(1000),
        );
        g.add(
            "sshd",
            "Failed password for admin from 2.2.2.2 port 2 ssh2",
            Some(2000),
        );
        g.add(
            "sshd",
            "Failed password for bob from 3.3.3.3 port 3 ssh2",
            Some(1500),
        );
        g.add("cron", "job failed", Some(10));
        let groups = g.into_sorted();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].program, "sshd");
        assert_eq!(groups[0].count, 3);
        assert_eq!(groups[0].first_seen, Some(1000));
        assert_eq!(groups[0].last_seen, Some(2000));
    }

    #[test]
    fn same_text_from_different_programs_stays_separate() {
        let mut g = Grouper::new();
        g.add("a", "boom", None);
        g.add("b", "boom", None);
        assert_eq!(g.into_sorted().len(), 2);
    }

    #[test]
    fn timeline_buckets_events() {
        let mut m = BTreeMap::new();
        m.insert(0, 5);
        m.insert(9, 2);
        let t = timeline(&m, 0, 9, 5);
        assert_eq!(t, vec![5, 0, 0, 0, 2]);
    }

    #[test]
    fn long_samples_are_truncated_on_char_boundaries() {
        let mut g = Grouper::new();
        g.add("p", &"é".repeat(400), None);
        let groups = g.into_sorted();
        assert!(groups[0].sample.ends_with("..."));
    }
}
