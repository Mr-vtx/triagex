//! Turns reports into terminal text. Every function returns a String, so the
//! layout can be tested without a terminal.

use std::fmt::Write;

use triagex_core::{
    Meter,
    collectors::{
        docker::{ContainerInfo, DockerInfo},
        nginx::{ConfigState, NginxInfo},
        process::{ProcessEntry, ProcessInfo},
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

#[allow(clippy::too_many_arguments)]
fn system_panel(
    ui: &Ui,
    host: &HostInfo,
    meters: &[Meter],
    failed: &Option<Vec<String>>,
    docker: &Option<DockerInfo>,
    redis: &Option<RedisInfo>,
    redis_bad: bool,
    nginx: &Option<NginxInfo>,
    nginx_bad: bool,
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

    let nginx_state = match nginx {
        Some(n) => {
            let mark = if nginx_bad {
                ui.cross_mark()
            } else {
                ui.check_mark()
            };
            let sep = ui.sep();
            let mut text = format!("{mark} {}", n.version.as_deref().unwrap_or("nginx"));
            if n.running() {
                text.push_str(&format!(" {sep} {} processes", n.processes));
            } else {
                text.push_str(&format!(" {sep} not running"));
            }
            text.push_str(&format!(" {sep} {}", config_word(n.config.state)));
            if let Some(s) = &n.status {
                text.push_str(&format!(" {sep} {} active", s.active));
            }
            text
        }
        None => ui.paint("not detected", Style::Dim),
    };
    body.push(status_row(ui, "NGINX", &nginx_state));

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
    } else if (c.state == "exited" || c.state == "dead")
        && c.exit_code == Some(137)
        && c.memory_limit > 0
    {
        ui.paint("probably OOM", Style::Warn)
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

/// One row of the process table. Numbers are right-aligned and padded BEFORE coloring,
/// because color codes would otherwise break the alignment.
fn process_row(ui: &Ui, e: &ProcessEntry, cores: usize, w: &ProcCols) -> String {
    let cpu_text = format!("{:>w$.1}", e.cpu_pct, w = w.cpu);
    let cpu_hot = e.cpu_pct / cores.max(1) as f64 >= 80.0;
    let mem_hot = e.mem_pct >= 50.0;

    let mut row = pad_to(&fit(&e.name, w.name, "~"), w.name);
    row.push_str(&format!("  {:>w$}", e.pid, w = w.pid));
    if w.user > 0 {
        row.push_str(&format!("  {}", pad_to(&fit(&e.user, w.user, "~"), w.user)));
    }
    row.push_str(&format!(
        "  {}",
        ui.paint(&cpu_text, if cpu_hot { Style::Warn } else { Style::Bold })
    ));
    let mem_text = format!("{:>w$}", human_bytes(e.rss_bytes), w = w.mem);
    row.push_str(&format!(
        "  {}",
        ui.paint(&mem_text, if mem_hot { Style::Warn } else { Style::Bold })
    ));
    if w.ram > 0 {
        row.push_str(&format!("  {:>w$.1}", e.mem_pct, w = w.ram));
    }
    row
}

/// Column widths for the process table, chosen from the space the panel has.
struct ProcCols {
    name: usize,
    pid: usize,
    user: usize,
    cpu: usize,
    mem: usize,
    ram: usize,
}

impl ProcCols {
    fn for_width(inner: usize) -> Self {
        let (pid, cpu, mem) = (7usize, 6usize, 9usize);
        // Full table: name, pid, user, cpu, mem, ram%. Gaps are two spaces.
        let (user, ram) = if inner >= 66 {
            (10usize, 5usize)
        } else {
            (0, 0)
        };
        let columns = 4 + usize::from(user > 0) + usize::from(ram > 0);
        let fixed = pid + cpu + mem + user + ram + (columns - 1) * 2;
        ProcCols {
            name: inner.saturating_sub(fixed).clamp(8, 24),
            pid,
            user,
            cpu,
            mem,
            ram,
        }
    }

    fn header(&self, ui: &Ui, title: &str) -> String {
        let mut h = pad_to(title, self.name);
        h.push_str(&format!("  {:>w$}", "PID", w = self.pid));
        if self.user > 0 {
            h.push_str(&format!("  {}", pad_to("USER", self.user)));
        }
        h.push_str(&format!("  {:>w$}", "CPU%", w = self.cpu));
        h.push_str(&format!("  {:>w$}", "MEM", w = self.mem));
        if self.ram > 0 {
            h.push_str(&format!("  {:>w$}", "RAM%", w = self.ram));
        }
        ui.paint(&h, Style::Dim)
    }
}

fn process_panel(ui: &Ui, p: &ProcessInfo, cores: usize, max_rows: Option<usize>) -> String {
    let cols = ProcCols::for_width(ui.inner());
    let rows = max_rows.unwrap_or(p.top_cpu.len().max(p.top_mem.len()));
    let mut body = Vec::new();

    body.push(cols.header(ui, "TOP CPU"));
    if p.top_cpu.is_empty() {
        dim_lines(
            ui,
            "no process used more than 0.05% CPU during the sample",
            &mut body,
        );
    }
    for e in p.top_cpu.iter().take(rows) {
        body.push(process_row(ui, e, cores, &cols));
    }

    body.push(String::new());
    body.push(cols.header(ui, "TOP MEMORY"));
    for e in p.top_mem.iter().take(rows) {
        body.push(process_row(ui, e, cores, &cols));
    }

    body.push(String::new());
    dim_lines(
        ui,
        "CPU% is per core (200 = two cores busy), sampled over a short window.",
        &mut body,
    );
    if p.partial_view {
        dim_lines(
            ui,
            "/proc hides other users' processes here (hidepid). Run with sudo for all of them.",
            &mut body,
        );
    }

    let sep = ui.sep();
    let right = format!(
        "{} total {sep} {} running {sep} {} zombie",
        p.total, p.running, p.zombies
    );
    ui.panel("processes", &right, &body)
}

/// Wraps a plain sentence to the panel width, then colors each line. Wrapping must happen
/// before painting, or color codes would be split across lines.
fn dim_lines(ui: &Ui, text: &str, body: &mut Vec<String>) {
    for l in wrap(text, ui.inner()) {
        body.push(ui.paint(&l, Style::Dim));
    }
}

fn process_panel_if_any(
    ui: &Ui,
    processes: &Option<ProcessInfo>,
    cores: usize,
    max_rows: Option<usize>,
) -> String {
    match processes {
        Some(p) if p.total > 0 => process_panel(ui, p, cores, max_rows),
        _ => String::new(),
    }
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
        &inv.nginx,
        has_nginx_finding(&inv.findings),
    ));
    out.push_str(&findings_panel(ui, &inv.findings, max_findings));
    if max_findings.is_none() {
        out.push_str(&nginx_panel_if_any(ui, &inv.nginx));
    }
    out.push_str(&process_panel_if_any(
        ui,
        &inv.processes,
        inv.host.cpu_cores,
        max_findings.map(|_| 3),
    ));
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

fn config_word(state: ConfigState) -> &'static str {
    match state {
        ConfigState::Passed => "config ok",
        ConfigState::Failed => "config FAILED",
        ConfigState::NeedsRoot => "config untested (needs root)",
        ConfigState::TimedOut => "config test timed out",
        ConfigState::NotRun => "config untested",
    }
}

fn has_nginx_finding(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.id == "nginx.config" || f.id == "nginx.dropped")
}

/// Details for the full views: the config test result and the live counters.
fn nginx_panel(ui: &Ui, n: &NginxInfo) -> String {
    let mut body = Vec::new();
    let sep = ui.sep();

    let config = match n.config.state {
        ConfigState::Passed => format!("{} passed", ui.check_mark()),
        ConfigState::Failed => format!(
            "{} {}",
            ui.cross_mark(),
            if n.config.syntax_ok {
                "syntax ok, but the test failed"
            } else {
                "has an error"
            }
        ),
        ConfigState::NeedsRoot => "not tested: needs root (try sudo)".to_string(),
        ConfigState::TimedOut => "not finished: nginx -t timed out".to_string(),
        ConfigState::NotRun => {
            "not tested: no nginx binary here, so it probably runs in a container (docker exec <name> nginx -t)"
                .to_string()
        }
    };
    let mut first = true;
    for l in wrap(&config, ui.inner().saturating_sub(10).max(20)) {
        let label = if first { "CONFIG" } else { "" };
        body.push(format!(
            "{} {l}",
            ui.paint(&format!("{label:<8}"), Style::Bold)
        ));
        first = false;
    }
    for e in n.config.errors.iter().take(3) {
        for l in wrap(e, ui.inner().saturating_sub(10).max(20)) {
            body.push(format!("{:<8} {}", "", ui.paint(&l, Style::Warn)));
        }
    }
    if let Some(w) = n.config.warnings.first() {
        for l in wrap(
            &format!("warning: {w}"),
            ui.inner().saturating_sub(10).max(20),
        ) {
            body.push(format!("{:<8} {}", "", ui.paint(&l, Style::Dim)));
        }
    }

    match &n.status {
        Some(s) => {
            body.push(format!(
                "{} {} active {sep} {} reading {sep} {} writing {sep} {} waiting",
                ui.paint(&format!("{:<8}", "STATUS"), Style::Bold),
                s.active,
                s.reading,
                s.writing,
                s.waiting
            ));
            body.push(format!(
                "{:<8} {} requests {sep} {} accepted {sep} {} dropped",
                "",
                s.requests,
                s.accepts,
                s.dropped()
            ));
        }
        None if n.running() => {
            let hint = "stub_status not found. To see live connections add: location = /nginx_status { stub_status; allow 127.0.0.1; deny all; }";
            for (i, l) in wrap(hint, ui.inner().saturating_sub(10).max(20))
                .iter()
                .enumerate()
            {
                let label = if i == 0 { "STATUS" } else { "" };
                body.push(format!(
                    "{} {}",
                    ui.paint(&format!("{label:<8}"), Style::Bold),
                    ui.paint(l, Style::Dim)
                ));
            }
        }
        None => {}
    }

    let right = format!(
        "{} {sep} {} process(es)",
        n.version.as_deref().unwrap_or("unknown version"),
        n.processes
    );
    ui.panel("nginx", &right, &body)
}

fn nginx_panel_if_any(ui: &Ui, nginx: &Option<NginxInfo>) -> String {
    nginx
        .as_ref()
        .map(|n| nginx_panel(ui, n))
        .unwrap_or_default()
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
    nginx: &Option<NginxInfo>,
    processes: &Option<ProcessInfo>,
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
        nginx,
        has_nginx_finding(findings),
    ));
    out.push_str(&findings_panel(ui, findings, None));
    out.push_str(&nginx_panel_if_any(ui, nginx));
    out.push_str(&process_panel_if_any(ui, processes, host.cpu_cores, None));
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
            memory_limit: 0,
        }
    }

    fn proc_entry(pid: u32, name: &str, cpu: f64, rss: u64, mem: f64) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.into(),
            user: "deploy".into(),
            state: 'S',
            cpu_pct: cpu,
            rss_bytes: rss,
            mem_pct: mem,
            threads: 8,
        }
    }

    fn sample_processes() -> ProcessInfo {
        ProcessInfo {
            total: 214,
            running: 2,
            sleeping: 200,
            zombies: 1,
            stuck: vec![],
            sample_ms: 262,
            partial_view: false,
            top_cpu: vec![
                proc_entry(4021, "node", 187.4, 1_288_490_188, 31.2),
                proc_entry(988, "postgres", 12.0, 536_870_912, 13.0),
                proc_entry(1, "systemd", 0.3, 12_582_912, 0.3),
            ],
            top_mem: vec![
                proc_entry(4021, "node", 187.4, 1_288_490_188, 31.2),
                proc_entry(988, "postgres", 12.0, 536_870_912, 13.0),
            ],
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
            nginx: None,
            processes: Some(sample_processes()),
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
            "processes",
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

    fn sample_nginx(state: ConfigState, errors: &[&str], status: bool) -> NginxInfo {
        use triagex_core::collectors::nginx::{ConfigTest, StubStatus};
        NginxInfo {
            binary: Some("/usr/sbin/nginx".into()),
            version: Some("1.24.0".into()),
            processes: 3,
            config: ConfigTest {
                state,
                syntax_ok: false,
                errors: errors.iter().map(|e| e.to_string()).collect(),
                warnings: vec![],
            },
            status: status.then_some(StubStatus {
                active: 12,
                accepts: 500,
                handled: 498,
                requests: 4521,
                reading: 0,
                writing: 2,
                waiting: 10,
            }),
            status_url: None,
        }
    }

    #[test]
    fn nginx_shows_a_status_row_always_and_a_panel_only_in_full_views() {
        let mut inv = sample();
        assert!(overview(&ui(false, 80), &inv, None, false, false).contains("NGINX"));
        assert!(overview(&ui(false, 80), &inv, None, false, false).contains("not detected"));

        inv.nginx = Some(sample_nginx(ConfigState::Passed, &[], true));
        let short = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(
            short.contains("1.24.0") && short.contains("config ok") && short.contains("12 active")
        );
        assert!(!short.contains("─ nginx"));

        let full = overview(&ui(false, 80), &inv, None, false, false);
        assert!(full.contains("─ nginx"));
        assert!(full.contains("4521 requests"));
        assert!(full.contains("2 dropped"));
        assert!(full.lines().all(|l| crate::ui::visible_width(l) <= 80));
    }

    #[test]
    fn a_failed_config_test_shows_the_error_and_marks_the_row() {
        let mut inv = sample();
        inv.nginx = Some(sample_nginx(
            ConfigState::Failed,
            &["[emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/app:3"],
            false,
        ));
        let text = overview(&ui(false, 80), &inv, None, false, false);
        assert!(text.contains("config FAILED"));
        assert!(text.contains("has an error"));
        assert!(text.contains("unknown directive"));
        assert!(text.contains("stub_status not found"));
        assert!(text.lines().all(|l| crate::ui::visible_width(l) <= 80));
    }

    #[test]
    fn nginx_without_root_or_without_a_binary_explains_itself() {
        let mut inv = sample();
        inv.nginx = Some(sample_nginx(ConfigState::NeedsRoot, &[], false));
        assert!(overview(&ui(false, 80), &inv, None, false, false).contains("needs root"));
        let mut n = sample_nginx(ConfigState::NotRun, &[], false);
        n.binary = None;
        n.version = None;
        inv.nginx = Some(n);
        let text = overview(&ui(false, 80), &inv, None, false, false);
        assert!(text.contains("container"));
        assert!(text.lines().all(|l| crate::ui::visible_width(l) <= 80));
    }

    #[test]
    fn process_panel_lists_both_rankings_with_aligned_columns() {
        let text = overview(&ui(false, 80), &sample(), None, false, false);
        assert!(text.contains("─ processes"));
        assert!(text.contains("214 total"));
        assert!(text.contains("TOP CPU"));
        assert!(text.contains("TOP MEMORY"));
        let node: Vec<&str> = text.lines().filter(|l| l.contains(" node ")).collect();
        assert_eq!(node.len(), 2, "node appears once per ranking");
        // the cpu column lines up between the header and the row
        let header = text.lines().find(|l| l.contains("TOP CPU")).unwrap();
        let cpu_end = header.find("CPU%").unwrap() + 4;
        assert!(node[0].contains("187.4"));
        assert_eq!(node[0].find("187.4").unwrap() + 5, cpu_end);
    }

    #[test]
    fn the_overview_shows_three_rows_per_ranking_and_the_report_shows_all() {
        let mut inv = sample();
        inv.processes = Some(ProcessInfo {
            top_cpu: (1..=5)
                .map(|i| proc_entry(i, &format!("cpu{i}"), 50.0, 1, 1.0))
                .collect(),
            top_mem: (1..=5)
                .map(|i| proc_entry(i, &format!("mem{i}"), 0.1, 1_000_000 * i as u64, 1.0))
                .collect(),
            ..sample_processes()
        });
        let short = overview(&ui(false, 80), &inv, Some(5), false, false);
        assert!(short.contains("cpu3") && !short.contains("cpu4"));
        let full = overview(&ui(false, 80), &inv, None, false, false);
        assert!(full.contains("cpu5") && full.contains("mem5"));
    }

    #[test]
    fn narrow_terminals_drop_columns_instead_of_breaking_the_layout() {
        let narrow = overview(&ui(false, 50), &sample(), None, false, false);
        assert!(narrow.contains("TOP CPU"));
        assert!(!narrow.contains("USER"));
        let wide = overview(&ui(false, 100), &sample(), None, false, false);
        assert!(wide.contains("USER") && wide.contains("RAM%") && wide.contains("deploy"));
    }

    #[test]
    fn busy_processes_are_highlighted_only_when_they_hog_the_machine() {
        let hot = overview(&ui(true, 80), &sample(), None, false, false);
        // node: 187% of 4 cores is under 80% of the machine, so no warning color on it
        let warn = "\x1b[";
        assert!(hot.contains(warn));
        let mut inv = sample();
        inv.host.cpu_cores = 2;
        let hotter = overview(&ui(true, 80), &inv, None, false, false);
        assert_ne!(
            hot, hotter,
            "187% on 2 cores is a hog and is colored differently"
        );
    }

    #[test]
    fn an_idle_machine_and_a_hidden_proc_both_explain_themselves() {
        let mut inv = sample();
        inv.processes = Some(ProcessInfo {
            top_cpu: vec![],
            partial_view: true,
            ..sample_processes()
        });
        let text = overview(&ui(false, 80), &inv, None, false, false);
        assert!(text.contains("no process used more than 0.05% CPU"));
        assert!(text.contains("hidepid"));
        assert!(text.lines().all(|l| crate::ui::visible_width(l) <= 80));
    }

    #[test]
    fn the_process_panel_is_absent_when_proc_was_unreadable() {
        let mut inv = sample();
        inv.processes = None;
        assert!(!overview(&ui(false, 80), &inv, None, false, false).contains("─ processes"));
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
