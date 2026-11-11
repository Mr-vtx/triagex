//! Turns reports into terminal text. Every function returns a String, so the
//! layout can be tested without a terminal.

use std::fmt::Write;

use triagex_core::{
    Meter,
    collectors::{
        docker::{ContainerInfo, DockerInfo},
        redis::RedisInfo,
    },
    finding::{Finding, Severity},
    host::{HostInfo, format_uptime},
    integrity::{BaselineSummary, VerifyReport},
    investigation::Investigation,
    logs::{GroupView, LogReport},
    util::human_bytes,
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
    redis: &Option<RedisInfo>,
    redis_bad: bool,
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

    let redis_state = match redis {
        Some(r) => {
            let mark = if redis_bad {
                ui.cross_mark()
            } else {
                ui.check_mark()
            };
            let memory = match r.memory_pct() {
                Some(p) => format!("{p:.0}% of {} limit", human_bytes(r.max_memory)),
                None => format!("{} used", human_bytes(r.used_memory)),
            };
            let sep = ui.sep();
            format!(
                "{mark} {} {sep} {} {sep} {} clients {sep} {memory}",
                r.version, r.role, r.connected_clients
            )
        }
        None => ui.paint("not detected", Style::Dim),
    };
    body.push(status_row(ui, "REDIS", &redis_state));

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
        body.extend(ui.field_lines("id", &f.id, 7, inner));
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
    lines.extend(ui.field_lines("id", &g.id, 4, inner));
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
        &inv.redis,
        has_redis_finding(&inv.findings),
    ));
    out.push_str(&findings_panel(ui, &inv.findings, max_findings));
    out.push_str(&docker_panel_if_any(
        ui,
        &inv.docker,
        max_findings.map(|_| 8),
    ));
    if let Some(r) = &inv.integrity {
        out.push_str(&integrity_panel(ui, r));
    }

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

fn path_list(ui: &Ui, title: &str, paths: &[String], inner: usize, body: &mut Vec<String>) {
    if paths.is_empty() {
        return;
    }
    body.push(String::new());
    body.push(ui.paint(&format!("{title} ({})", paths.len()), Style::Bold));
    for p in paths.iter().take(8) {
        body.push(format!(
            "  {}",
            ui.paint(&ui.truncate(p, inner.saturating_sub(2)), Style::Dim)
        ));
    }
    if paths.len() > 8 {
        body.push(ui.paint(&format!("  ... and {} more", paths.len() - 8), Style::Dim));
    }
}

fn integrity_panel(ui: &Ui, r: &VerifyReport) -> String {
    let inner = ui.inner();
    let mut body = Vec::new();
    let mut kv = |label: &str, text: &str| body.extend(ui.field_lines(label, text, 0, inner));

    kv(
        "baseline",
        &format!(
            "{} (created {} UTC on {})",
            r.name,
            short_time(&r.created_at),
            r.hostname
        ),
    );
    kv("watching", &r.roots.join(", "));
    kv(
        "checked",
        &format!(
            "{} paths now, {} in the baseline",
            r.checked, r.baseline_entries
        ),
    );
    let digest_state = if r.digest_ok {
        format!("{} matches the digest stored with it", ui.check_mark())
    } else {
        format!(
            "{} DOES NOT MATCH: the baseline was edited or damaged",
            ui.cross_mark()
        )
    };
    kv("digest", &digest_state);
    if let Some(ok) = r.expected_digest_ok {
        let text = if ok {
            format!("{} matches the digest you passed", ui.check_mark())
        } else {
            format!("{} differs from the digest you passed", ui.cross_mark())
        };
        kv("expected", &text);
    }
    body.push(String::new());

    if r.changes() == 0 {
        body.push(format!(
            "{} {}",
            ui.check_mark(),
            ui.paint("No changes since the baseline.", Style::Bold)
        ));
    } else {
        let count = |n: usize, word: &str| {
            let text = format!("{word} {n}");
            ui.paint(&text, if n > 0 { Style::Warn } else { Style::Dim })
        };
        body.push(
            [
                count(r.modified.len(), "modified"),
                count(r.added.len(), "added"),
                count(r.deleted.len(), "deleted"),
                count(r.permissions.len(), "permissions"),
                count(r.type_changed.len(), "type"),
            ]
            .join(&format!("  {}  ", ui.sep())),
        );
    }

    path_list(ui, "MODIFIED", &r.modified, inner, &mut body);
    path_list(ui, "ADDED", &r.added, inner, &mut body);
    path_list(ui, "DELETED", &r.deleted, inner, &mut body);
    path_list(ui, "CHANGED TYPE", &r.type_changed, inner, &mut body);
    let perms: Vec<String> = r
        .permissions
        .iter()
        .map(|c| format!("{} ({:04o} -> {:04o})", c.path, c.old_mode, c.new_mode))
        .collect();
    path_list(ui, "PERMISSIONS OR OWNER", &perms, inner, &mut body);
    let unreadable: Vec<String> = r
        .unreadable
        .iter()
        .map(|s| format!("{} ({})", s.path, s.reason))
        .collect();
    path_list(ui, "COULD NOT CHECK", &unreadable, inner, &mut body);

    let right = if r.changes() == 0 {
        "unchanged".to_string()
    } else {
        format!("{} changes", r.changes())
    };
    ui.panel("file integrity", &right, &body)
}

pub fn verify_screen(ui: &Ui, r: &VerifyReport) -> String {
    let mut out = String::new();
    title_line(ui, &format!("verify {} {}", ui.sep(), r.hostname), &mut out);
    out.push_str(&integrity_panel(ui, r));
    if !r.findings.is_empty() {
        out.push_str(&findings_panel(ui, &r.findings, None));
    }
    line!(out, "{}", summary_line(ui, &r.findings));
    out
}

pub fn baseline_screen(ui: &Ui, b: &BaselineSummary) -> String {
    let inner = ui.inner();
    let mut body = Vec::new();
    let mut kv = |label: &str, text: &str| body.extend(ui.field_lines(label, text, 0, inner));

    kv("saved to", &b.path);
    kv("watching", &b.roots.join(", "));
    kv(
        "recorded",
        &format!(
            "{} files ({} hashed), {} directories, {} symlinks",
            b.files, b.hashed, b.dirs, b.symlinks
        ),
    );
    kv("digest", &b.digest);
    if b.skipped_total > 0 {
        body.push(String::new());
        body.push(ui.paint(
            &format!("{} path(s) could not be recorded", b.skipped_total),
            Style::Warn,
        ));
        for s in b.skipped.iter().take(5) {
            let line = format!("{} ({})", s.path, s.reason);
            body.push(format!(
                "  {}",
                ui.paint(&ui.truncate(&line, inner.saturating_sub(2)), Style::Dim)
            ));
        }
        if b.skipped_total > 5 {
            body.push(ui.paint(
                &format!("  ... and {} more", b.skipped_total - 5),
                Style::Dim,
            ));
        }
    }

    let mut out = String::new();
    title_line(ui, &format!("baseline {} {}", ui.sep(), b.name), &mut out);
    out.push_str(&ui.panel(
        "baseline saved",
        &b.created_at.replace('T', " ").replace('Z', " UTC"),
        &body,
    ));
    dim_wrapped(
        ui,
        "Keep the digest somewhere off this server. Later, `triagex verify --expect-digest <digest>` proves this baseline was not edited.",
        &mut out,
    );
    if b.skipped_total > 0 {
        dim_wrapped(
            ui,
            "Some paths were unreadable. Run with sudo to include them, or leave them out with --exclude.",
            &mut out,
        );
    }
    dim_wrapped(
        ui,
        &format!("Compare later with: triagex verify --name {}", b.name),
        &mut out,
    );
    out
}

fn has_redis_finding(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.id.starts_with("redis."))
}

#[allow(clippy::too_many_arguments)]
pub fn check(
    ui: &Ui,
    host: &HostInfo,
    meters: &[Meter],
    failed: &Option<Vec<String>>,
    docker: &Option<DockerInfo>,
    redis: &Option<RedisInfo>,
    findings: &[Finding],
    skipped: &[String],
) -> String {
    let mut out = String::new();
    title_line(ui, &host.hostname, &mut out);
    out.push_str(&system_panel(
        ui,
        host,
        meters,
        failed,
        docker,
        redis,
        has_redis_finding(findings),
    ));
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
            integrity: None,
            redis: Some(RedisInfo {
                addr: "127.0.0.1:6379".into(),
                version: "7.2.4".into(),
                role: "master".into(),
                uptime_secs: 100,
                connected_clients: 12,
                max_clients: Some(10000),
                used_memory: 90 * 1024 * 1024,
                max_memory: 100 * 1024 * 1024,
                rss: 100 * 1024 * 1024,
                fragmentation_ratio: Some(1.1),
                evicted_keys: 0,
                rejected_connections: 0,
                keys: 10,
                rdb_save_ok: Some(true),
                aof_write_ok: Some(true),
                master_link_up: None,
                ping_ms: 0.2,
            }),
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
                id: "sshd:5e1f0c2a".into(),
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
            "disk.usage:/",
            "sshd:5e1f0c2a",
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
    fn redis_shows_a_status_row_and_flags_trouble() {
        let text = overview(&ui(false, 80), &sample(), Some(5), false, false);
        assert!(text.contains("REDIS"));
        assert!(text.contains("7.2.4 · master · 12 clients · 90% of 100.0 MiB limit"));

        let mut inv = sample();
        inv.redis = None;
        let text = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(text.contains("not detected"));
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

    fn verify_report() -> VerifyReport {
        VerifyReport {
            name: "web".into(),
            created_at: "2026-11-10T08:00:00Z".into(),
            hostname: "myvps".into(),
            roots: vec!["/etc".into(), "/usr/local/bin".into()],
            baseline_entries: 1200,
            checked: 1203,
            digest_ok: true,
            digest: "a".repeat(64),
            expected_digest_ok: Some(true),
            added: vec!["/etc/new.conf".into()],
            deleted: vec![],
            modified: (0..12).map(|i| format!("/etc/changed-{i}.conf")).collect(),
            permissions: vec![triagex_core::integrity::PermChange {
                path: "/usr/local/bin/tool".into(),
                old_mode: 0o755,
                new_mode: 0o4755,
                old_owner: (0, 0),
                new_owner: (0, 0),
            }],
            type_changed: vec![],
            unreadable: vec![],
            findings: vec![Finding {
                id: "integrity.permissions.risky".into(),
                severity: Severity::Critical,
                title: "1 file(s) gained setuid, setgid or world-write".into(),
                evidence: "/usr/local/bin/tool (0755 -> 4755)".into(),
                next_step: "chmod u-s /usr/local/bin/tool".into(),
                source: "baseline comparison".into(),
            }],
        }
    }

    #[test]
    fn verify_screen_lists_changes_and_findings_and_fits_every_width() {
        let r = verify_report();
        for width in [40usize, 60, 80, 100] {
            let text = verify_screen(&ui(false, width), &r);
            for l in text.lines() {
                assert!(visible_width(l) <= width, "width {width}: {l:?}");
            }
        }
        let text = verify_screen(&ui(false, 80), &r);
        for needle in [
            "file integrity",
            "14 changes",
            "modified 12",
            "added 1",
            "/etc/new.conf",
            "... and 4 more",
            "0755 -> 4755",
            "matches the digest stored",
            "[CRIT]",
            "integrity.permissions.risky",
        ] {
            assert!(text.contains(needle), "missing {needle}\n{text}");
        }
    }

    #[test]
    fn a_clean_verify_and_a_tampered_baseline_read_clearly() {
        let mut clean = verify_report();
        clean.added.clear();
        clean.modified.clear();
        clean.permissions.clear();
        clean.findings.clear();
        let text = verify_screen(&ui(false, 80), &clean);
        assert!(text.contains("No changes since the baseline."));
        assert!(text.contains("unchanged"));

        let mut bad = verify_report();
        bad.digest_ok = false;
        bad.expected_digest_ok = Some(false);
        let text = verify_screen(&ui(false, 80), &bad);
        assert!(text.contains("DOES NOT MATCH"));
        assert!(text.contains("differs from the digest you passed"));
    }

    #[test]
    fn the_report_overview_includes_integrity_when_present() {
        let mut inv = sample();
        inv.integrity = Some(verify_report());
        let text = overview(&ui(false, 80), &inv, None, false, false);
        assert!(text.contains("file integrity"));
        let none = overview(&ui(false, 80), &sample(), None, false, false);
        assert!(!none.contains("file integrity"));
    }

    #[test]
    fn baseline_screen_shows_the_digest_and_what_to_do_with_it() {
        let b = BaselineSummary {
            name: "web".into(),
            path: "/var/lib/triagex/baselines/web.json".into(),
            created_at: "2026-11-10T08:00:00Z".into(),
            roots: vec!["/etc".into()],
            files: 1200,
            dirs: 90,
            symlinks: 12,
            hashed: 1198,
            skipped_total: 7,
            skipped: vec![triagex_core::integrity::Skipped {
                path: "/etc/shadow".into(),
                reason: "permission denied".into(),
            }],
            digest: "b".repeat(64),
        };
        for width in [40usize, 80, 100] {
            for l in baseline_screen(&ui(false, width), &b).lines() {
                assert!(visible_width(l) <= width, "width {width}: {l:?}");
            }
        }
        let text = baseline_screen(&ui(false, 100), &b);
        assert!(text.contains(&"b".repeat(64)));
        assert!(text.contains("1200 files (1198 hashed)"));
        assert!(text.contains("7 path(s) could not be recorded"));
        assert!(text.contains("/etc/shadow (permission denied)"));
        assert!(text.contains("--expect-digest"));
        assert!(text.contains("triagex verify --name web"));
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
