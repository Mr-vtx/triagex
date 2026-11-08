//! Terminal styling primitives: themes, colors, panels, bars, badges, wrapping.
//! Every function returns a String so the layout can be unit-tested.

use std::io::IsTerminal;

use clap::ValueEnum;
use triagex_core::{Meter, finding::Severity};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Theme {
    Purple,
    Green,
}

#[derive(Clone, Copy)]
pub enum Style {
    Brand,
    Accent,
    Dim,
    Bold,
    Ok,
    Warn,
    Crit,
    Info,
    Count,
}

pub struct Ui {
    pub color: bool,
    pub utf8: bool,
    pub width: usize,
    pub theme: Theme,
    /// No padding lines inside panels and no gaps between them.
    pub compact: bool,
}

const LABEL_W: usize = 10;
const VALUE_W: usize = 9;

/// The logo is plain ASCII on purpose: it renders on any terminal, any font, any locale.
const GLYPHS: [[&str; 5]; 7] = [
    ["#####", "  #  ", "  #  ", "  #  ", "  #  "], // T
    ["#### ", "#   #", "#### ", "#  # ", "#   #"], // R
    ["###", " # ", " # ", " # ", "###"],           // I
    [" ### ", "#   #", "#####", "#   #", "#   #"], // A
    [" ####", "#    ", "# ###", "#   #", " ### "], // G
    ["#####", "#    ", "#### ", "#    ", "#####"], // E
    ["#   #", " # # ", "  #  ", " # # ", "#   #"], // X
];
/// Logo width with 2 columns between letters (39 with 1, used on very narrow terminals).
pub const LOGO_WIDTH: usize = 45;

impl Ui {
    pub fn detect(mode: ColorMode, theme: Theme, compact: bool) -> Self {
        let tty = std::io::stdout().is_terminal();
        let color = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                tty && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
            }
        };
        Ui {
            color,
            utf8: locale_is_utf8(),
            width: terminal_width(tty),
            theme,
            compact,
        }
    }

    /// Usable columns inside a panel (borders and one space of padding each side).
    pub fn inner(&self) -> usize {
        self.width.saturating_sub(4)
    }

    pub fn paint(&self, text: &str, style: Style) -> String {
        if !self.color || text.is_empty() {
            return text.to_string();
        }
        let purple = self.theme == Theme::Purple;
        let code = match style {
            Style::Brand => {
                if purple {
                    "1;38;5;141"
                } else {
                    "1;38;5;46"
                }
            }
            Style::Accent => {
                if purple {
                    "38;5;141"
                } else {
                    "38;5;40"
                }
            }
            Style::Dim => "38;5;245",
            Style::Bold => "1",
            Style::Ok => "38;5;78",
            Style::Warn => "38;5;214",
            Style::Crit => "1;38;5;203",
            Style::Info => "38;5;75",
            Style::Count => "1;38;5;221",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    pub fn sep(&self) -> &'static str {
        if self.utf8 { "·" } else { "|" }
    }

    pub fn dot(&self) -> &'static str {
        if self.utf8 { "●" } else { "*" }
    }

    pub fn check_mark(&self) -> String {
        self.paint(if self.utf8 { "✔" } else { "ok" }, Style::Ok)
    }

    pub fn cross_mark(&self) -> String {
        self.paint(if self.utf8 { "✖" } else { "!!" }, Style::Crit)
    }

    pub fn severity_style(sev: Option<Severity>) -> Style {
        match sev {
            None => Style::Accent,
            Some(Severity::Info) => Style::Info,
            Some(Severity::Warning) => Style::Warn,
            Some(Severity::Critical) => Style::Crit,
        }
    }

    /// Always 6 columns wide, colored or not, so titles line up.
    pub fn badge(&self, sev: Severity) -> String {
        let (text, code) = match sev {
            Severity::Critical => (" CRIT ", "1;97;48;5;160"),
            Severity::Warning => (" WARN ", "1;30;48;5;214"),
            Severity::Info => (" INFO ", "1;30;48;5;75"),
        };
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            format!("[{}]", text.trim())
        }
    }

    pub fn bar(&self, percent: f64, width: usize, sev: Option<Severity>) -> String {
        let p = percent.clamp(0.0, 100.0);
        let mut filled = ((p / 100.0) * width as f64).round() as usize;
        if p > 0.0 {
            filled = filled.clamp(1, width); // any non-zero value shows at least one cell
        }
        let (on, off) = if self.utf8 {
            ("▰", "▱")
        } else {
            ("#", "-")
        };
        format!(
            "{}{}",
            self.paint(&on.repeat(filled), Self::severity_style(sev)),
            self.paint(&off.repeat(width - filled), Style::Dim)
        )
    }

    /// The five-row ASCII logo with a top-to-bottom gradient.
    pub fn logo(&self) -> [String; 5] {
        const PURPLE: [u8; 5] = [183, 177, 141, 135, 99];
        const GREEN: [u8; 5] = [157, 120, 83, 46, 34];
        let shades = if self.theme == Theme::Purple {
            PURPLE
        } else {
            GREEN
        };
        // Two columns between letters when there is room, one on very narrow terminals.
        let gap = if self.width > LOGO_WIDTH + 1 {
            "  "
        } else {
            " "
        };
        std::array::from_fn(|row| {
            let text = GLYPHS.iter().map(|g| g[row]).collect::<Vec<_>>().join(gap);
            if self.color {
                format!("\x1b[1;38;5;{}m{text}\x1b[0m", shades[row])
            } else {
                text
            }
        })
    }

    /// A bordered panel with the title (and an optional right-hand label) set into the top edge.
    pub fn panel(&self, title: &str, right: &str, body: &[String]) -> String {
        let (tl, tr, bl, br, h, v) = if self.utf8 {
            ("╭", "╮", "╰", "╯", "─", "│")
        } else {
            ("+", "+", "+", "+", "-", "|")
        };
        let w = self.width;
        let inner = self.inner();

        let title = fit(title, w.saturating_sub(14), "…");
        let right = fit(right, w.saturating_sub(visible_width(&title) + 14), "…");
        let right_len = if right.is_empty() {
            0
        } else {
            visible_width(&right) + 2
        };
        let fill = w
            .saturating_sub(6 + visible_width(&title) + right_len)
            .max(1);

        let edge = |s: &str| self.paint(s, Style::Dim);
        let mut out = String::new();

        out.push_str(&edge(&format!("{tl}{h} ")));
        out.push_str(&self.paint(&title, Style::Brand));
        out.push_str(&edge(&format!(" {}", h.repeat(fill))));
        if !right.is_empty() {
            out.push(' ');
            out.push_str(&self.paint(&right, Style::Accent));
            out.push(' ');
        }
        out.push_str(&edge(&format!("{h}{tr}")));
        out.push('\n');

        let row = |content: &str| -> String {
            format!(
                "{} {} {}\n",
                edge(v),
                pad_to(&fit(content, inner, "…"), inner),
                edge(v)
            )
        };
        if !self.compact {
            out.push_str(&row(""));
        }
        for line in body {
            out.push_str(&row(line));
        }
        if !self.compact {
            out.push_str(&row(""));
        }
        out.push_str(&edge(&format!("{bl}{}{br}", h.repeat(w.saturating_sub(2)))));
        out.push('\n');
        if !self.compact {
            out.push('\n');
        }
        out
    }

    pub fn sparkline(&self, values: &[u32]) -> String {
        let bars: &[char] = if self.utf8 {
            &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
        } else {
            &['.', ':', '-', '=', '+', '*', '#', '%']
        };
        let zero = if self.utf8 { '·' } else { '_' };
        let max = values.iter().copied().max().unwrap_or(0);
        let text: String = values
            .iter()
            .map(|&v| {
                if v == 0 || max == 0 {
                    zero
                } else {
                    bars[((v as u64 * (bars.len() as u64 - 1)) / max as u64) as usize]
                }
            })
            .collect();
        self.paint(&text, Style::Accent)
    }

    /// "label   wrapped text" with continuation lines aligned under the text.
    pub fn field_lines(&self, label: &str, text: &str, indent: usize, width: usize) -> Vec<String> {
        const FIELD_W: usize = 10;
        let avail = width.saturating_sub(indent + FIELD_W).max(20);
        let pad = " ".repeat(indent);
        wrap(text, avail)
            .into_iter()
            .enumerate()
            .map(|(i, line)| {
                if i == 0 {
                    let l = format!("{label:<FIELD_W$}");
                    format!("{pad}{}{line}", self.paint(&l, Style::Dim))
                } else {
                    format!("{pad}{}{line}", " ".repeat(FIELD_W))
                }
            })
            .collect()
    }

    /// One gauge row: label, bar, value, and (if there is room) a short detail.
    pub fn meter_row(&self, m: &Meter, inner: usize) -> String {
        let bar_w = inner.saturating_sub(24 + 38).clamp(8, 22);
        let detail_w = inner.saturating_sub(LABEL_W + 1 + bar_w + 2 + VALUE_W + 2);

        let label = format!("{:<LABEL_W$}", self.truncate(&m.label, LABEL_W));
        let value = format!("{:>VALUE_W$}", m.value);
        let detail = if detail_w >= 12 {
            self.paint(&self.truncate(&m.detail, detail_w), Style::Dim)
        } else {
            String::new()
        };
        let value_style = match m.severity {
            None => Style::Bold,
            sev => Self::severity_style(sev),
        };
        format!(
            "{} {}  {}  {}",
            self.paint(&label, Style::Bold),
            self.bar(m.percent, bar_w, m.severity),
            self.paint(&value, value_style),
            detail
        )
        .trim_end()
        .to_string()
    }

    pub fn truncate(&self, s: &str, max: usize) -> String {
        fit(s, max, if self.utf8 { "…" } else { "~" })
    }
}

/// Printable width of a string, ignoring ANSI color sequences.
pub fn visible_width(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for d in chars.by_ref() {
                if d == 'm' {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

/// Cut a (possibly colored) string to `max` printable columns, keeping its color codes valid.
pub fn fit(s: &str, max: usize, ellipsis: &str) -> String {
    if visible_width(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(ellipsis.chars().count());
    let mut out = String::new();
    let mut shown = 0;
    let mut saw_escape = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            saw_escape = true;
            out.push(c);
            for d in chars.by_ref() {
                out.push(d);
                if d == 'm' {
                    break;
                }
            }
            continue;
        }
        if shown >= keep {
            break;
        }
        out.push(c);
        shown += 1;
    }
    out.push_str(ellipsis);
    if saw_escape {
        out.push_str("\x1b[0m");
    }
    out
}

pub fn pad_to(s: &str, width: usize) -> String {
    let w = visible_width(s);
    format!("{s}{}", " ".repeat(width.saturating_sub(w)))
}

pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(10);
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

pub fn is_utf8_locale(value: &str) -> bool {
    let l = value.to_ascii_lowercase();
    l.contains("utf-8") || l.contains("utf8")
}

fn locale_is_utf8() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return is_utf8_locale(&v);
        }
    }
    false
}

fn terminal_width(tty: bool) -> usize {
    let mut cols = 0usize;
    if tty {
        // SAFETY: winsize is plain-old-data, so a zeroed value is valid as an out-parameter.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: the fd is stdout and `ws` is a valid, writable winsize for the call.
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 {
            cols = ws.ws_col as usize;
        }
    }
    if cols == 0 {
        cols = std::env::var("COLUMNS")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(80);
    }
    cols.clamp(40, 100)
}

pub fn resolve_theme(flag: Option<Theme>) -> Theme {
    if let Some(t) = flag {
        return t;
    }
    match std::env::var("TRIAGEX_THEME")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "green" => Theme::Green,
        _ => Theme::Purple,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Ui {
        Ui {
            color: false,
            utf8: true,
            width: 80,
            theme: Theme::Purple,
            compact: false,
        }
    }

    fn colored() -> Ui {
        Ui {
            color: true,
            ..plain()
        }
    }

    #[test]
    fn bar_fills_proportionally_and_never_hides_small_values() {
        let ui = plain();
        assert_eq!(ui.bar(50.0, 4, None), "▰▰▱▱");
        assert_eq!(ui.bar(0.0, 4, None), "▱▱▱▱");
        assert_eq!(ui.bar(1.0, 4, None), "▰▱▱▱");
        assert_eq!(ui.bar(250.0, 4, None), "▰▰▰▰");
    }

    #[test]
    fn ascii_fallback_uses_plain_characters() {
        let ui = Ui {
            utf8: false,
            ..plain()
        };
        assert_eq!(ui.bar(50.0, 4, None), "##--");
        assert_eq!(ui.sparkline(&[0, 4, 8]), "_=%");
        assert_eq!(ui.badge(Severity::Critical), "[CRIT]");
        assert!(ui.panel("t", "", &[]).starts_with("+- t "));
    }

    #[test]
    fn visible_width_ignores_color_codes() {
        assert_eq!(visible_width("abc"), 3);
        assert_eq!(visible_width(&colored().paint("abc", Style::Crit)), 3);
        assert_eq!(visible_width(&colored().badge(Severity::Critical)), 6);
    }

    #[test]
    fn fit_truncates_colored_text_and_keeps_it_valid() {
        let s = colored().paint("abcdefghij", Style::Crit);
        let cut = fit(&s, 5, "…");
        assert_eq!(visible_width(&cut), 5);
        assert!(cut.ends_with("\x1b[0m"));
        assert_eq!(fit("abc", 5, "…"), "abc");
        assert_eq!(fit("abcdefghij", 5, "…"), "abcd…");
    }

    #[test]
    fn panels_are_exactly_as_wide_as_the_terminal() {
        for ui in [
            plain(),
            colored(),
            Ui {
                width: 50,
                ..plain()
            },
            Ui {
                utf8: false,
                ..plain()
            },
        ] {
            let body = vec![
                "short".to_string(),
                ui.paint("colored text here", Style::Warn),
                "x".repeat(300),
            ];
            let text = ui.panel("system", "myhost", &body);
            for line in text.lines().filter(|l| !l.is_empty()) {
                assert_eq!(visible_width(line), ui.width, "line: {line:?}");
            }
        }
    }

    #[test]
    fn panels_have_breathing_room_unless_compact() {
        let spaced = plain().panel("t", "", &["hello".to_string()]);
        assert_eq!(spaced.lines().count(), 6); // top, pad, body, pad, bottom, gap
        let tight = Ui {
            compact: true,
            ..plain()
        }
        .panel("t", "", &["hello".to_string()]);
        assert_eq!(tight.lines().count(), 3);
    }

    #[test]
    fn long_titles_do_not_break_the_border() {
        let ui = Ui {
            width: 40,
            ..plain()
        };
        let text = ui.panel(&"T".repeat(80), &"R".repeat(80), &[]);
        for line in text.lines().filter(|l| !l.is_empty()) {
            assert_eq!(visible_width(line), 40);
        }
    }

    #[test]
    fn no_escape_codes_without_color() {
        let ui = plain();
        assert_eq!(ui.paint("hi", Style::Crit), "hi");
        assert!(!ui.panel("x", "y", &["z".into()]).contains('\x1b'));
        assert!(colored().paint("hi", Style::Crit).contains('\x1b'));
    }

    #[test]
    fn wrap_breaks_on_words_and_keeps_long_words_intact() {
        assert_eq!(wrap("aaa bbb ccc", 10), vec!["aaa bbb", "ccc"]);
        assert_eq!(wrap("", 20), vec![""]);
        let long = "x".repeat(40);
        assert_eq!(wrap(&long, 20), vec![long]);
    }

    #[test]
    fn field_lines_align_continuations() {
        let lines = plain().field_lines("next", "one two three four five six seven eight", 4, 40);
        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("    next      one"));
        assert!(lines[1].starts_with("              "));
    }

    #[test]
    fn locale_detection() {
        assert!(is_utf8_locale("en_US.UTF-8"));
        assert!(is_utf8_locale("C.utf8"));
        assert!(!is_utf8_locale("C"));
    }

    #[test]
    fn meter_rows_fit_the_panel() {
        let m = Meter {
            label: "DISK /boot/efi/very/long".into(),
            percent: 41.2,
            value: "41.2%".into(),
            detail: "123.4 GiB free of 500.0 GiB, inodes 3.1%, and a lot more text".into(),
            severity: None,
        };
        for inner in [36usize, 56, 76, 96] {
            assert!(visible_width(&plain().meter_row(&m, inner)) <= inner);
        }
    }

    #[test]
    fn the_logo_is_ascii_five_rows_of_equal_width() {
        let rows = plain().logo();
        assert_eq!(rows.len(), 5);
        for r in &rows {
            assert_eq!(r.chars().count(), LOGO_WIDTH);
            assert!(r.is_ascii());
        }
        assert!(rows[0].contains("#####"));
    }

    #[test]
    fn the_logo_tightens_to_fit_the_narrowest_terminal() {
        let narrow = Ui {
            width: 40,
            ..plain()
        };
        for r in narrow.logo() {
            assert_eq!(r.chars().count(), 39);
            assert!(r.chars().count() < 40);
        }
    }
}
