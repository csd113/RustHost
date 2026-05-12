use std::{
    collections::VecDeque,
    fmt::Write as _,
    path::{Path, PathBuf},
    time::SystemTime,
};

use chrono::{DateTime, Local};

use crate::{config::Config, console::ui, runtime::state::format_bytes};

const SCAN_LIMIT: usize = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePageState {
    report: Option<SiteReport>,
    scroll: usize,
}

impl SitePageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            report: None,
            scroll: 0,
        }
    }

    #[must_use]
    pub const fn report(&self) -> Option<&SiteReport> {
        self.report.as_ref()
    }

    pub fn set_report(&mut self, report: SiteReport) {
        self.report = Some(report);
        self.scroll = 0;
    }

    pub const fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub const fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }
}

impl Default for SitePageState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteReport {
    root: PathBuf,
    primary_files: Vec<PrimaryFile>,
    summary: StaticSummary,
    truncated: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryFile {
    label: String,
    state: FileState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FileState {
    Present { size: u64, modified: Option<String> },
    Missing,
    Unavailable(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StaticSummary {
    html: u64,
    css: u64,
    js: u64,
    images: u64,
    other: u64,
}

#[must_use]
pub fn collect_report(data_dir: &Path, config: &Config) -> SiteReport {
    let root = data_dir.join(&config.site.directory);
    let root_canon = root.canonicalize().ok();
    let mut warnings = Vec::new();
    if !root.is_dir() {
        warnings.push(format!("Site root is unavailable at {}", root.display()));
    }
    if !root.join(&config.site.index_file).is_file() {
        warnings.push(format!(
            "Configured index file is missing: {}",
            config.site.index_file
        ));
    }
    let primary_files = primary_files(&root, root_canon.as_deref(), config);
    let (summary, truncated) = scan_summary(&root, root_canon.as_deref());

    SiteReport {
        root,
        primary_files,
        summary,
        truncated,
        warnings,
    }
}

#[must_use]
pub fn render(page: &SitePageState) -> String {
    let mut out = String::with_capacity(1_536);
    ui::push_header(&mut out, "RustHost Menu / Site");
    out.push_str("\r\n");

    let Some(report) = page.report() else {
        out.push_str("Site snapshot has not been collected yet.\r\n");
        out.push_str("\r\n");
        ui::push_controls_footer(&mut out, "[R] Refresh  [Esc] Back");
        return out;
    };

    let _ = writeln!(out, "{}\r", ui::bold("Served Content"));
    out.push_str("\r\n");
    let _ = writeln!(out, "Root: {}\r", report.root.display());
    for warning in &report.warnings {
        let _ = writeln!(out, "{}\r", ui::yellow(warning));
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Primary files"));
    out.push_str("\r\n");
    for file in &report.primary_files {
        let _ = writeln!(
            out,
            "{:<16} {}\r",
            file.label,
            file_state_label(&file.state)
        );
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Static summary"));
    out.push_str("\r\n");
    let _ = writeln!(out, "HTML files:        {}\r", report.summary.html);
    let _ = writeln!(out, "CSS files:         {}\r", report.summary.css);
    let _ = writeln!(out, "JS files:          {}\r", report.summary.js);
    let _ = writeln!(out, "Images:            {}\r", report.summary.images);
    let _ = writeln!(out, "Other files:       {}\r", report.summary.other);

    if report.truncated {
        out.push_str("\r\n");
        let _ = writeln!(
            out,
            "{}\r",
            ui::yellow("Static summary truncated after 5000 entries.")
        );
    }

    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[R] Refresh  [↑↓/jk] Scroll  [Esc] Back");
    out
}

fn primary_files(root: &Path, root_canon: Option<&Path>, config: &Config) -> Vec<PrimaryFile> {
    vec![
        primary_file(root, root_canon, &config.site.index_file),
        primary_file(root, root_canon, &config.site.favicon),
        primary_file(root, root_canon, "404.html"),
        primary_file(root, root_canon, "robots.txt"),
    ]
}

fn primary_file(root: &Path, root_canon: Option<&Path>, relative: &str) -> PrimaryFile {
    let path = root.join(relative);
    let state = inspect_file(root_canon, &path);
    PrimaryFile {
        label: relative.to_owned(),
        state,
    }
}

fn inspect_file(root_canon: Option<&Path>, path: &Path) -> FileState {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return FileState::Missing;
    };

    if meta.file_type().is_symlink() && !safe_symlink_target(root_canon, path) {
        return FileState::Unavailable("unsafe symlink".to_owned());
    }

    let Ok(meta) = std::fs::metadata(path) else {
        return FileState::Unavailable("unreadable".to_owned());
    };

    if !meta.is_file() {
        return FileState::Unavailable("not a file".to_owned());
    }

    FileState::Present {
        size: meta.len(),
        modified: meta.modified().ok().map(modified_label),
    }
}

fn scan_summary(root: &Path, root_canon: Option<&Path>) -> (StaticSummary, bool) {
    let mut summary = StaticSummary::default();
    let mut queue = VecDeque::from([root.to_path_buf()]);
    let mut visited = 0usize;

    while let Some(dir) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry_result in entries {
            if visited >= SCAN_LIMIT {
                return (summary, true);
            }
            visited = visited.saturating_add(1);

            let Ok(entry) = entry_result else {
                continue;
            };
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let file_type = meta.file_type();

            if file_type.is_symlink() && !safe_symlink_target(root_canon, &path) {
                continue;
            }

            if file_type.is_dir() {
                queue.push_back(path);
            } else if file_type.is_file() || file_type.is_symlink() {
                count_file(&mut summary, &path);
            }
        }
    }

    (summary, false)
}

fn safe_symlink_target(root_canon: Option<&Path>, path: &Path) -> bool {
    let Some(root_canon) = root_canon else {
        return false;
    };
    path.canonicalize()
        .is_ok_and(|target| target.starts_with(root_canon))
}

fn count_file(summary: &mut StaticSummary, path: &Path) {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => summary.html = summary.html.saturating_add(1),
        Some("css") => summary.css = summary.css.saturating_add(1),
        Some("js" | "mjs" | "cjs") => summary.js = summary.js.saturating_add(1),
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "avif") => {
            summary.images = summary.images.saturating_add(1);
        }
        _ => summary.other = summary.other.saturating_add(1),
    }
}

fn file_state_label(state: &FileState) -> String {
    match state {
        FileState::Present { size, modified } => {
            let modified = modified.as_deref().unwrap_or("modified unknown");
            format!("{:<10} {modified}", format_bytes(*size))
        }
        FileState::Missing => ui::dim("missing"),
        FileState::Unavailable(reason) => ui::yellow(reason),
    }
}

fn modified_label(modified: SystemTime) -> String {
    let modified: DateTime<Local> = modified.into();
    let now = Local::now().date_naive();
    let modified_date = modified.date_naive();
    if modified_date == now {
        "modified today".to_owned()
    } else if modified_date.succ_opt() == Some(now) {
        "modified yesterday".to_owned()
    } else {
        format!("modified {}", modified.format("%Y-%m-%d"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{collect_report, render, FileState, SitePageState};
    use crate::config::Config;

    #[test]
    fn missing_optional_files_render_without_crashing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");
        std::fs::write(tmp.path().join("site/index.html"), b"ok").expect("index");

        let report = collect_report(tmp.path(), &Config::default());
        let mut page = SitePageState::new();
        page.set_report(report);
        let output = render(&page);

        assert!(output.contains("404.html"));
        assert!(output.contains("robots.txt"));
        assert!(output.contains("missing"));
        assert!(!output.contains("[Q] Quit"));
    }

    #[test]
    fn favicon_missing_is_optional_in_primary_listing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");

        let report = collect_report(tmp.path(), &Config::default());

        assert!(report
            .primary_files
            .iter()
            .any(|file| file.label == "favicon.ico" && file.state == FileState::Missing));
    }
}
