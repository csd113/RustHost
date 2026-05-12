use std::fmt::Write as _;

use crate::console::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpTopic {
    ConsoleControls,
    CliCommands,
    DoctorVsDiagnostics,
    NetworkAndHttps,
    Tor,
    SiteFiles,
    Logs,
    Troubleshooting,
}

impl HelpTopic {
    const ALL: [Self; 8] = [
        Self::ConsoleControls,
        Self::CliCommands,
        Self::DoctorVsDiagnostics,
        Self::NetworkAndHttps,
        Self::Tor,
        Self::SiteFiles,
        Self::Logs,
        Self::Troubleshooting,
    ];

    const fn title(self) -> &'static str {
        match self {
            Self::ConsoleControls => "Console controls",
            Self::CliCommands => "CLI commands",
            Self::DoctorVsDiagnostics => "Doctor vs diagnostics",
            Self::NetworkAndHttps => "Network and HTTPS",
            Self::Tor => "Tor",
            Self::SiteFiles => "Site files",
            Self::Logs => "Logs",
            Self::Troubleshooting => "Troubleshooting",
        }
    }

    const fn body(self) -> &'static [&'static str] {
        match self {
            Self::ConsoleControls => &[
                "Use [M] from the home screen to open the menu.",
                "Use [Esc] to return to the previous page.",
                "Use [Q] only from Home or Menu to quit RustHost.",
            ],
            Self::CliCommands => &[
                "rusthost-cli",
                "rusthost-cli --headless",
                "rusthost-cli --version",
                "rusthost-cli doctor",
                "rusthost-cli doctor --data-dir ./rusthost-data",
            ],
            Self::DoctorVsDiagnostics => &[
                "Doctor runs readiness checks and marks PASS, WARN, FAIL, or NOT RUN.",
                "Diagnostics collects a compact support snapshot for troubleshooting.",
                "Deep Doctor checks stay bounded and avoid public internet probes.",
            ],
            Self::NetworkAndHttps => &[
                "Network shows configured local listeners and safe local readiness checks.",
                "TLS disabled by settings is shown as disabled, not as a warning.",
                "Redirect disabled by settings is shown as off.",
            ],
            Self::Tor => &[
                "Tor status comes from RustHost-managed runtime state.",
                "The TUI does not start, stop, or restart Tor.",
                "Restart Tor is intentionally not supported yet.",
            ],
            Self::SiteFiles => &[
                "Site shows the configured served directory and primary files.",
                "Missing optional files such as 404.html or robots.txt are shown as missing.",
                "Large directory scans are bounded to keep the console responsive.",
            ],
            Self::Logs => &[
                "Use [L] from Home to open the log view.",
                "Doctor writes doctor.log when logging is enabled.",
                "Access logs are controlled by the logging setting.",
            ],
            Self::Troubleshooting => &[
                "Run rusthost-cli doctor for preflight checks outside the TUI.",
                "Use Diagnostics when sharing runtime details for support.",
                "Check logs for startup, TLS, Tor, and file-serving errors.",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpPageState {
    selected_topic: usize,
    open_topic: usize,
}

impl HelpPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected_topic: 0,
            open_topic: 0,
        }
    }

    pub const fn move_up(&mut self) {
        self.selected_topic = if self.selected_topic == 0 {
            HelpTopic::ALL.len() - 1
        } else {
            self.selected_topic - 1
        };
    }

    pub const fn move_down(&mut self) {
        self.selected_topic = (self.selected_topic + 1) % HelpTopic::ALL.len();
    }

    pub const fn open_selected(&mut self) {
        self.open_topic = self.selected_topic;
    }
}

impl Default for HelpPageState {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn render(page: &HelpPageState) -> String {
    let mut out = String::with_capacity(1_536);
    ui::push_header(&mut out, "RustHost Menu / Help");
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Help Topics"));
    out.push_str("\r\n");

    for (index, topic) in HelpTopic::ALL.iter().copied().enumerate() {
        let marker = if index == page.selected_topic {
            ui::bold(">")
        } else {
            " ".to_owned()
        };
        let _ = writeln!(out, "{marker} {}\r", topic.title());
    }

    let topic = HelpTopic::ALL
        .get(page.open_topic)
        .copied()
        .unwrap_or(HelpTopic::ConsoleControls);
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold(topic.title()));
    out.push_str("\r\n");
    for line in topic.body() {
        let _ = writeln!(out, "{line}\r");
    }

    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[↑↓/jk] Select  [Enter] Open  [Esc] Back");
    out
}

#[cfg(test)]
mod tests {
    use super::{render, HelpPageState};

    #[test]
    fn help_opens_selected_topic_on_same_page() {
        let mut page = HelpPageState::new();
        page.move_down();
        page.open_selected();
        let output = render(&page);

        assert!(output.contains("rusthost-cli --headless"));
        assert!(!output.contains("check-config"));
        assert!(!output.contains("[Q] Quit"));
    }
}
