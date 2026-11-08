//! Turns reports into terminal text. Every function returns a String, so the
//! layout can be tested without a terminal.

use std::fmt::Write;

use triagex_core::{
    Meter,
    collectors::docker::{ContainerInfo, DockerInfo},
    finding::{Finding, Severity},
    host::{HostInfo, format_uptime},
    investigation::Investigation,
    logs::{GroupView, LogReport},
};

use crate::{
    about,
    ui::{LOGO_WIDTH, Style, Ui, fit, pad_to, wrap},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

macro_rules! line {
    ($out:expr) => { let _ = writeln!($out); };
    ($out:expr, $($arg:tt)*) => { let _ = writeln!($out, $($arg)*); };
}

fn short_time(rfc3339: &str) -> String {
    rfc3339.replace('T', " ").trim_end_matches('Z').to_string()
}

/// The ASCII logo with the tagline, version and repo beside it (or below it on narrow terminals).
fn banner(ui: &Ui, out: &mut String) {
    let logo = ui.logo();
    let tagline = ui.paint(about::TAGLINE, Style::Bold);
    let version = ui.paint(
        &format!("v{VERSION} {} \"{}\"", ui.sep(), about::CODENAME),
        Style::Dim,
    );
    let repo = ui.paint(about::REPO, Style::Dim);

    if ui.width >= LOGO_WIDTH + 3 + 26 {
        let side = [String::new(), tagline, version, repo, String::new()];
        for (row, text) in logo.iter().zip(side) {
            if text.is_empty() {
                line!(out, " {row}");
            } else {
                line!(out, " {row}   {text}");
            }
        }
    } else {
        for row in &logo {
            line!(out, " {row}");
        }
        line!(out, " {tagline}");
        line!(out, " {version}");
        line!(out, " {repo}");
    }
    line!(out);
}

fn title_line(ui: &Ui, label: &str, out: &mut String) {
    line!(
        out,
        " {} {}",
        ui.paint("triagex", Style::Brand),
        ui.paint(&format!("{VERSION} {} {label}", ui.sep()), Style::Dim)
    );
    if !ui.compact {
        line!(out);
    }
}

/// OS, kernel, uptime and cores. On narrow terminals the least useful details
/// (kernel, then OS, then uptime) are dropped so the line never wraps.
fn host_text(ui: &Ui, h: &HostInfo, max: usize) -> String {
    let sep = format!(" {} ", ui.sep());
    let build = |kernel: bool, os: bool, uptime: bool| {
        let mut parts = Vec::new();
        if os && let Some(v) = &h.os {
            parts.push(v.clone());
        }
        if kernel && let Some(k) = &h.kernel {
            parts.push(format!("kernel {k}"));
        }
        if uptime && let Some(u) = h.uptime_secs {
            parts.push(format!("up {}", format_uptime(u)));
        }
        parts.push(format!("{} cores", h.cpu_cores));
        parts.join(&sep)
    };
    for (kernel, os, uptime) in [
        (true, true, true),
        (false, true, true),
        (false, false, true),
    ] {
        let text = build(kernel, os, uptime);
        if text.chars().count() <= max {
            return text;
        }
    }
    ui.truncate(&build(false, false, false), max)
}

fn status_row(ui: &Ui, label: &str, state: &str) -> String {
    format!("{} {state}", ui.paint(&format!("{label:<10}"), Style::Bold))
}

fn system_panel(
    ui: &Ui,
    host: &HostInfo,
    meters: &[Meter],
    failed: &Option<Vec<String>>,
    docker: &Option<DockerInfo>,
) -> String {
    let inner = ui.inner();
    let mut body = vec![
        ui.paint(&host_text(ui, host, inner), Style::Dim),
        String::new(),
    ];
    body.extend(meters.iter().map(|m| ui.meter_row(m, inner)));
    body.push(String::new());

    let systemd = match failed {
        Some(units) if units.is_empty() => format!("{} no failed units", ui.check_mark()),
        Some(units) => format!(
            "{} {} failed: {}",
            ui.cross_mark(),
            units.len(),
            ui.truncate(&units.join(", "), inner.saturating_sub(22).max(12))
        ),
        None => ui.paint("not available (see Skipped)", Style::Dim),
    };
    body.push(status_row(ui, "SYSTEMD", &systemd));

    let docker_state = match docker {
        Some(d) if d.containers.is_empty() => format!("{} no containers", ui.check_mark()),
        Some(d) => {
            let mark = if d.problems() == 0 {
                ui.check_mark()
            } else {
                ui.cross_mark()
            };
            let mut text = format!(
                "{mark} {} containers {} {} running",
                d.containers.len(),
                ui.sep(),
                d.running()
            );
            if d.stopped() > 0 {
                text.push_str(&format!(" {} {} stopped", ui.sep(), d.stopped()));
            }
            if d.problems() > 0 {
                text.push_str(&format!(" {} {} with problems", ui.sep(), d.problems()));
            }
            text
        }
        None => ui.paint("not detected", Style::Dim),
    };
    body.push(status_row(ui, "DOCKER", &docker_state));

    ui.panel("system", &host.hostname, &body)
}

fn counts_label(findings: &[Finding]) -> String {
    let n = |s| findings.iter().filter(|f| f.severity == s).count();
    let (c, w, i) = (
        n(Severity::Critical),
        n(Severity::Warning),
        n(Severity::Info),
    );
    let mut parts = Vec::new();
    if c > 0 {
        parts.push(format!("{c} critical"));
    }
    if w > 0 {
        parts.push(format!("{w} warning"));
    }
    if i > 0 {
        parts.push(format!("{i} info"));
    }
    if parts.is_empty() {
        "all clear".to_string()
    } else {
        parts.join(", ")
    }
}

fn findings_panel(ui: &Ui, findings: &[Finding], max: Option<usize>) -> String {
    let inner = ui.inner();
    let mut body = Vec::new();

    if findings.is_empty() {
        body.push(format!(
            "{} {}",
            ui.check_mark(),
            ui.paint("No issues found.", Style::Bold)
        ));
    }
    let shown = max.unwrap_or(findings.len()).min(findings.len());
    for (i, f) in findings[..shown].iter().enumerate() {
        if i > 0 {
            body.push(String::new());
        }
        body.push(format!(
            "{} {}",
            ui.badge(f.severity),
            ui.paint(&f.title, Style::Bold)
        ));
        body.extend(ui.field_lines("evidence", &f.evidence, 7, inner));
        body.extend(ui.field_lines("next", &f.next_step, 7, inner));
    }
    if findings.len() > shown {
        body.push(String::new());
        body.push(ui.paint(
            &format!(
                "... and {} more findings (see `triagex report`)",
                findings.len() - shown
            ),
            Style::Dim,
        ));
    }
    ui.panel("findings", &counts_label(findings), &body)
}

fn container_note(ui: &Ui, c: &ContainerInfo) -> String {
    if c.oom_killed {
        ui.paint("OOM killed", Style::Crit)
    } else if c.state == "restarting" {
        ui.paint(&format!("restarting, {}x", c.restart_count), Style::Warn)
    } else if (c.state == "exited" || c.state == "dead") && c.exit_code.unwrap_or(0) != 0 {
        ui.paint(
            &format!("exit {}", c.exit_code.unwrap_or_default()),
            Style::Crit,
        )
    } else if c.health.as_deref() == Some("unhealthy") {
        ui.paint("unhealthy", Style::Warn)
    } else if c.state == "running" && c.restart_count > 0 {
        ui.paint(&format!("restarted {}x", c.restart_count), Style::Warn)
    } else if c.health.as_deref() == Some("healthy") {
        ui.paint("healthy", Style::Ok)
    } else {
        String::new()
    }
}

fn container_state(ui: &Ui, c: &ContainerInfo) -> String {
    let style = match c.state.as_str() {
        "running" => Style::Ok,
        "restarting" => Style::Warn,
        "dead" => Style::Crit,
        "exited" if c.exit_code.unwrap_or(0) != 0 => Style::Crit,
        "paused" => Style::Info,
        _ => Style::Dim,
    };
    ui.paint(&format!("{} {}", ui.dot(), c.state), style)
}

fn docker_panel(ui: &Ui, d: &DockerInfo, max_rows: Option<usize>) -> String {
    let inner = ui.inner();
    let (name_w, state_w) = (16usize, 13usize);
    let show_image = inner >= 66;
    let note_w = 16usize;
    let image_w = inner.saturating_sub(name_w + state_w + note_w + 6);

    let mut list: Vec<&ContainerInfo> = d.containers.iter().collect();
    list.sort_by_key(|c| (!c.is_problem(), c.state != "running", c.name.clone()));

    let cell = |text: String, w: usize| pad_to(&fit(&text, w, "…"), w);
    let mut header = cell("NAME".into(), if show_image { name_w } else { name_w + 2 });
    if show_image {
        header.push_str(&format!("  {}", cell("IMAGE".into(), image_w)));
    }
    header.push_str(&format!("  {}  NOTE", cell("STATE".into(), state_w)));

    let mut body = vec![ui.paint(&header, Style::Dim)];
    let shown = max_rows.unwrap_or(list.len()).min(list.len());
    for c in &list[..shown] {
        let mut row = cell(c.name.clone(), if show_image { name_w } else { name_w + 2 });
        if show_image {
            row.push_str(&format!(
                "  {}",
                ui.paint(&cell(c.image.clone(), image_w), Style::Dim)
            ));
        }
        row.push_str(&format!(
            "  {}  {}",
            pad_to(&container_state(ui, c), state_w),
            container_note(ui, c)
        ));
        body.push(row);
    }
    if list.len() > shown {
        body.push(ui.paint(
            &format!("... and {} more (see `triagex report`)", list.len() - shown),
            Style::Dim,
        ));
    }

    let right = format!(
        "{} running {} {} stopped",
        d.running(),
        ui.sep(),
        d.stopped()
    );
    ui.panel("docker", &right, &body)
}

fn group_lines(ui: &Ui, rank: usize, g: &GroupView, show_sample: bool) -> Vec<String> {
    let inner = ui.inner();
    let mut lines = vec![format!(
        "{}  {}  {}   {}",
        ui.paint(&format!("#{rank}"), Style::Bold),
        ui.paint(&format!("x{}", g.count), Style::Count),
        ui.paint(&g.program, Style::Info),
        ui.sparkline(&g.timeline)
    )];
    for l in wrap(&g.pattern, inner.saturating_sub(4)) {
        lines.push(format!("    {l}"));
    }
    if let (Some(a), Some(b)) = (&g.first_seen, &g.last_seen) {
        lines.push(format!(
            "    {}",
            ui.paint(
                &format!("first {}   last {}  (UTC)", short_time(a), short_time(b)),
                Style::Dim
            )
        ));
    }
    if show_sample {
        lines.extend(ui.field_lines("e.g.", &g.sample, 4, inner));
    }
    lines
}

fn logs_panel(
    ui: &Ui,
    groups: &[GroupView],
    total_groups: usize,
    right: &str,
    show_sample: bool,
) -> String {
    let mut body = Vec::new();
    for (i, g) in groups.iter().enumerate() {
        if i > 0 {
            body.push(String::new());
        }
        body.extend(group_lines(ui, i + 1, g, show_sample));
    }
    if total_groups > groups.len() {
        body.push(String::new());
        body.push(ui.paint(
            &format!(
                "... and {} more groups (use --top {})",
                total_groups - groups.len(),
                total_groups
            ),
            Style::Dim,
        ));
    }
    ui.panel("logs", right, &body)
}

fn skipped_panel(ui: &Ui, skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let inner = ui.inner();
    let mut body = Vec::new();
    for s in skipped {
        for (i, l) in wrap(s, inner.saturating_sub(3)).into_iter().enumerate() {
            let lead = if i == 0 { "-  " } else { "   " };
            body.push(format!("{}{l}", ui.paint(lead, Style::Dim)));
        }
    }
    ui.panel("skipped", "", &body)
}

/// Dim, word-wrapped text with a one-space margin, for footers and notes.
fn dim_wrapped(ui: &Ui, text: &str, out: &mut String) {
    for l in wrap(text, ui.width.saturating_sub(2)) {
        line!(out, " {}", ui.paint(&l, Style::Dim));
    }
}

fn summary_line(ui: &Ui, findings: &[Finding]) -> String {
    let n = |s| findings.iter().filter(|f| f.severity == s).count();
    let part = |count: usize, word: &str, style: Style| {
        let text = format!("{count} {word}");
        ui.paint(&text, if count > 0 { style } else { Style::Dim })
    };
    format!(
        " {}",
        [
            part(n(Severity::Critical), "critical", Style::Crit),
            part(n(Severity::Warning), "warning", Style::Warn),
            part(n(Severity::Info), "info", Style::Info),
        ]
        .join(&format!(" {} ", ui.sep()))
    )
}

fn docker_panel_if_any(ui: &Ui, docker: &Option<DockerInfo>, max_rows: Option<usize>) -> String {
    match docker {
        Some(d) if !d.containers.is_empty() => docker_panel(ui, d, max_rows),
        _ => String::new(),
    }
}

pub fn overview(
    ui: &Ui,
    inv: &Investigation,
    max_findings: Option<usize>,
    show_banner: bool,
    hint: bool,
) -> String {
    let mut out = String::new();
    if show_banner {
        banner(ui, &mut out);
    } else {
        title_line(ui, &inv.host.hostname, &mut out);
    }

    out.push_str(&system_panel(
        ui,
        &inv.host,
        &inv.meters,
        &inv.failed_units,
        &inv.docker,
    ));
    out.push_str(&findings_panel(ui, &inv.findings, max_findings));
    out.push_str(&docker_panel_if_any(
        ui,
        &inv.docker,
        max_findings.map(|_| 8),
    ));

    if !inv.log_groups.is_empty() {
        let window = inv
            .since
            .as_deref()
            .map(|s| format!("last {s}"))
            .unwrap_or_else(|| "all time".to_string());
        let right = format!(
            "{window} {} {} lines {} {} groups",
            ui.sep(),
            inv.log_lines_scanned,
            ui.sep(),
            inv.log_groups_total
        );
        out.push_str(&logs_panel(
            ui,
            &inv.log_groups,
            inv.log_groups_total,
            &right,
            false,
        ));
    }
    out.push_str(&skipped_panel(ui, &inv.skipped));

    line!(out, "{}", summary_line(ui, &inv.findings));
    if hint {
        dim_wrapped(
            ui,
            "Run `triagex report` for the full investigation, or `triagex logs` for log triage.",
            &mut out,
        );
    }
    out
}

pub fn check(
    ui: &Ui,
    host: &HostInfo,
    meters: &[Meter],
    failed: &Option<Vec<String>>,
    docker: &Option<DockerInfo>,
    findings: &[Finding],
    skipped: &[String],
) -> String {
    let mut out = String::new();
    title_line(ui, &host.hostname, &mut out);
    out.push_str(&system_panel(ui, host, meters, failed, docker));
    out.push_str(&findings_panel(ui, findings, None));
    out.push_str(&docker_panel_if_any(ui, docker, None));
    out.push_str(&skipped_panel(ui, skipped));
    line!(out, "{}", summary_line(ui, findings));
    out
}

pub fn logs(ui: &Ui, report: &LogReport) -> String {
    let mut out = String::new();
    let window = report
        .since
        .as_deref()
        .map(|s| format!("last {s}"))
        .unwrap_or_else(|| "all time".to_string());
    title_line(
        ui,
        &format!(
            "logs {} {} {} {window}",
            ui.sep(),
            report.hostname,
            ui.sep()
        ),
        &mut out,
    );

    if report.groups.is_empty() && report.skipped.is_empty() {
        out.push_str(&ui.panel(
            "logs",
            &format!("{} lines scanned", report.lines_scanned),
            &[format!(
                "{} {}",
                ui.check_mark(),
                ui.paint("No matching log lines.", Style::Bold)
            )],
        ));
    } else if !report.groups.is_empty() {
        let right = format!(
            "{} lines {} {} kept {} {} groups",
            report.lines_scanned,
            ui.sep(),
            report.lines_matched,
            ui.sep(),
            report.groups_total
        );
        out.push_str(&logs_panel(
            ui,
            &report.groups,
            report.groups_total,
            &right,
            true,
        ));
    }
    if !report.findings.is_empty() {
        out.push_str(&findings_panel(ui, &report.findings, None));
    }
    if !report.sources.is_empty() {
        dim_wrapped(
            ui,
            &format!("sources: {}", report.sources.join(", ")),
            &mut out,
        );
    }
    out.push_str(&skipped_panel(ui, &report.skipped));
    out
}

pub fn about_screen(ui: &Ui) -> String {
    let mut out = String::new();
    line!(out);
    banner(ui, &mut out);
    let rows = [
        ("version", format!("{VERSION}  \"{}\"", about::CODENAME)),
        ("built by", about::BUILT_BY.to_string()),
        ("source", about::REPO.to_string()),
        ("license", about::LICENSE.to_string()),
    ];
    let mut body: Vec<String> = rows
        .into_iter()
        .map(|(k, v)| format!("{} {v}", ui.paint(&format!("{k:<10}"), Style::Dim)))
        .collect();
    body.push(String::new());
    body.push(ui.paint(
        "Read-only. Single binary. No outbound network. Shows evidence, not guesses.",
        Style::Dim,
    ));
    out.push_str(&ui.panel("about", "", &body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{Theme, visible_width};

    fn ui(color: bool, width: usize) -> Ui {
        Ui {
            color,
            utf8: true,
            width,
            theme: Theme::Purple,
            compact: false,
        }
    }

    fn container(name: &str, state: &str) -> ContainerInfo {
        ContainerInfo {
            id: "abc".into(),
            name: name.into(),
            image: "nginx:1.27".into(),
            state: state.into(),
            status: String::new(),
            health: None,
            restart_count: 0,
            exit_code: None,
            oom_killed: false,
        }
    }

    fn sample() -> Investigation {
        let mut broken = container("worker", "restarting");
        broken.restart_count = 7;
        let mut fine = container("web", "running");
        fine.health = Some("healthy".into());
        Investigation {
            tool: "triagex",
            version: "0.1.0",
            generated_at: "2026-11-08T10:00:00Z".into(),
            host: HostInfo {
                hostname: "myvps".into(),
                os: Some("Debian 12".into()),
                kernel: Some("6.1.0".into()),
                uptime_secs: Some(90000),
                cpu_cores: 4,
            },
            since: Some("24h".into()),
            readings: vec![],
            meters: vec![
                Meter {
                    label: "LOAD".into(),
                    percent: 11.0,
                    value: "0.11/core".into(),
                    detail: "load 0.40 0.40 0.40".into(),
                    severity: None,
                },
                Meter {
                    label: "DISK /".into(),
                    percent: 95.0,
                    value: "95.0%".into(),
                    detail: "5.0 GiB free of 100.0 GiB".into(),
                    severity: Some(Severity::Critical),
                },
            ],
            failed_units: Some(vec!["nginx.service".into()]),
            docker: Some(DockerInfo {
                socket: "/var/run/docker.sock".into(),
                containers: vec![fine, broken],
            }),
            findings: vec![Finding {
                id: "disk.usage:/".into(),
                severity: Severity::Critical,
                title: "Disk space is running low on /".into(),
                evidence: "95.0% used; 5.0 GiB free of 100.0 GiB (ext4).".into(),
                next_step:
                    "See what is taking space with: du -xh / --max-depth=1 | sort -h | tail -n 10"
                        .into(),
                source: "statvfs".into(),
            }],
            log_sources: vec![],
            log_lines_scanned: 0,
            log_groups_total: 1,
            log_groups: vec![GroupView {
                program: "sshd".into(),
                pattern: "Failed password for invalid user <user> from <ip> port <n> ssh2".into(),
                count: 420,
                first_seen: Some("2026-11-06T02:00:00Z".into()),
                last_seen: Some("2026-11-06T05:00:00Z".into()),
                sample: "x".into(),
                timeline: vec![1, 5, 9, 4, 0, 0],
            }],
            skipped: vec!["something was skipped".into()],
        }
    }

    #[test]
    fn no_line_is_wider_than_the_terminal_at_any_width() {
        for width in [40usize, 50, 60, 80, 100] {
            for color in [false, true] {
                let u = ui(color, width);
                for banner in [false, true] {
                    let text = overview(&u, &sample(), Some(5), banner, true);
                    for l in text.lines() {
                        assert!(
                            visible_width(l) <= width,
                            "width {width}, color {color}: {l:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn panel_borders_line_up() {
        let text = overview(&ui(false, 80), &sample(), Some(5), false, false);
        let mut panel_lines = 0;
        for l in text.lines().filter(|l| l.starts_with(['╭', '│', '╰'])) {
            assert_eq!(visible_width(l), 80, "{l}");
            panel_lines += 1;
        }
        assert!(panel_lines > 20);
    }

    #[test]
    fn plain_overview_has_every_panel_and_no_escape_codes() {
        let text = overview(&ui(false, 80), &sample(), Some(5), false, true);
        assert!(!text.contains('\x1b'));
        for needle in [
            "system",
            "findings",
            "docker",
            "logs",
            "skipped",
            "[CRIT] Disk space is running low on /",
            "LOAD",
            "▰",
            "x420",
            "nginx.service",
            "restarting, 7x",
            "healthy",
        ] {
            assert!(text.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn containers_with_problems_are_listed_first() {
        let text = overview(&ui(false, 80), &sample(), Some(5), false, false);
        let worker = text.find("worker").unwrap();
        let web = text.rfind("web").unwrap();
        assert!(worker < web);
    }

    #[test]
    fn docker_panel_is_absent_without_docker() {
        let mut inv = sample();
        inv.docker = None;
        let text = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(!text.contains("─ docker"));
        assert!(text.contains("not detected"));
    }

    #[test]
    fn banner_shows_the_ascii_logo_and_brand_details() {
        let text = overview(&ui(true, 80), &sample(), Some(5), true, false);
        assert!(text.contains("#####"));
        assert!(text.contains(about::TAGLINE));
        assert!(text.contains(about::REPO));
        assert!(text.contains(about::CODENAME));
        let narrow = overview(&ui(false, 50), &sample(), Some(5), true, false);
        assert!(narrow.contains("#####"));
        assert!(narrow.contains(about::REPO));
    }

    #[test]
    fn healthy_machine_says_so() {
        let mut inv = sample();
        inv.findings.clear();
        inv.failed_units = Some(vec![]);
        inv.log_groups.clear();
        inv.docker = None;
        let text = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(text.contains("No issues found."));
        assert!(text.contains("all clear"));
        assert!(text.contains("no failed units"));
    }

    #[test]
    fn findings_are_capped_with_a_pointer_to_the_report() {
        let mut inv = sample();
        let f = inv.findings[0].clone();
        inv.findings = vec![f; 7];
        let text = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(text.contains("and 2 more findings"));
        assert_eq!(text.matches("[CRIT] Disk space").count(), 5);
    }

    #[test]
    fn compact_mode_drops_the_spacing() {
        let spaced = overview(&ui(false, 80), &sample(), Some(5), false, false);
        let tight = overview(
            &Ui {
                compact: true,
                ..ui(false, 80)
            },
            &sample(),
            Some(5),
            false,
            false,
        );
        assert!(tight.lines().count() < spaced.lines().count());
    }

    #[test]
    fn about_shows_brand_details() {
        let text = about_screen(&ui(false, 80));
        for needle in [
            about::BUILT_BY,
            about::REPO,
            about::CODENAME,
            about::LICENSE,
        ] {
            assert!(text.contains(needle), "missing {needle}");
        }
        for l in text.lines() {
            assert!(visible_width(l) <= 80);
        }
    }
}
