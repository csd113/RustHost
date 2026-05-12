use std::fmt::Write as _;

use crate::{
    config::Config,
    console::ui,
    runtime::state::{AppState, TorStatus},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorAction {
    Restart,
    CopyOnion,
    Diagnostics,
    BootstrapLog,
    Back,
}

impl TorAction {
    const ALL: [Self; 5] = [
        Self::Restart,
        Self::CopyOnion,
        Self::Diagnostics,
        Self::BootstrapLog,
        Self::Back,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Restart => "Restart Tor: not supported yet",
            Self::CopyOnion => "Copy onion address",
            Self::Diagnostics => "Open Tor diagnostics",
            Self::BootstrapLog => "Show bootstrap log",
            Self::Back => "Back",
        }
    }

    const fn is_disabled(self) -> bool {
        matches!(self, Self::Restart)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorPageState {
    selected_action: usize,
    status: Option<String>,
    show_bootstrap_log: bool,
}

impl TorPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected_action: 0,
            status: None,
            show_bootstrap_log: false,
        }
    }

    #[must_use]
    pub fn selected_action(&self) -> TorAction {
        TorAction::ALL
            .get(self.selected_action)
            .copied()
            .unwrap_or(TorAction::Restart)
    }

    pub const fn move_up(&mut self) {
        self.selected_action = if self.selected_action == 0 {
            TorAction::ALL.len() - 1
        } else {
            self.selected_action - 1
        };
    }

    pub const fn move_down(&mut self) {
        self.selected_action = (self.selected_action + 1) % TorAction::ALL.len();
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = Some(status.into());
    }

    pub const fn show_bootstrap_log(&mut self) {
        self.show_bootstrap_log = true;
    }
}

impl Default for TorPageState {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn render(page: &TorPageState, config: &Config, state: &AppState) -> String {
    let mut out = String::with_capacity(1_024);
    ui::push_header(&mut out, "RustHost Menu / Tor");
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Tor"));
    let _ = writeln!(out, "Status: {}\r", tor_status_label(config, state));
    let _ = writeln!(out, "Onion:  {}\r", onion_label(config, state));
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Actions"));
    out.push_str("\r\n");

    for (index, action) in TorAction::ALL.iter().copied().enumerate() {
        let marker = if index == page.selected_action {
            ui::bold(">")
        } else {
            " ".to_owned()
        };
        let label = if action.is_disabled() {
            ui::dim(action.label())
        } else {
            action.label().to_owned()
        };
        let _ = writeln!(out, "{marker} {label}\r");
    }

    out.push_str("\r\n");
    out.push_str("Tor controls are limited to RustHost-managed Tor state.\r\n");

    if page.show_bootstrap_log {
        out.push_str("\r\n");
        let _ = writeln!(out, "{}\r", ui::bold("Bootstrap log"));
        let _ = writeln!(out, "{}\r", bootstrap_log_label(state));
    }

    if let Some(status) = &page.status {
        out.push_str("\r\n");
        let _ = writeln!(out, "{}\r", ui::dim(status));
    }

    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[↑↓/jk] Navigate  [Enter] Select  [Esc] Back");
    out
}

#[must_use]
pub fn copy_onion_status(state: &AppState) -> String {
    state.onion_address.as_deref().map_or_else(
        || "No onion address is available to copy.".to_owned(),
        |addr| format!("Clipboard support unavailable; onion address remains visible: {addr}"),
    )
}

fn tor_status_label(config: &Config, state: &AppState) -> String {
    if !config.tor.enabled {
        return ui::dim("Disabled");
    }

    match &state.tor_status {
        TorStatus::Disabled => ui::dim("Disabled"),
        TorStatus::Starting => ui::yellow("Starting"),
        TorStatus::Ready => ui::green("Running"),
        TorStatus::Failed(reason) => ui::red(&format!("Failed ({})", single_line(reason))),
    }
}

fn onion_label(config: &Config, state: &AppState) -> String {
    if !config.tor.enabled || matches!(state.tor_status, TorStatus::Disabled) {
        return ui::dim("not configured");
    }

    state
        .onion_address
        .as_deref()
        .map_or_else(|| ui::dim("unavailable"), ToOwned::to_owned)
}

fn bootstrap_log_label(state: &AppState) -> String {
    match &state.tor_status {
        TorStatus::Failed(reason) => format!("Last Tor failure: {}", single_line(reason)),
        TorStatus::Starting => "No bootstrap log available; Tor is still starting.".to_owned(),
        TorStatus::Ready | TorStatus::Disabled => "No bootstrap log available.".to_owned(),
    }
}

fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{copy_onion_status, render, TorPageState};
    use crate::{config::Config, runtime::state::AppState};

    #[test]
    fn restart_action_is_rendered_as_unsupported() {
        let output = render(&TorPageState::new(), &Config::default(), &AppState::new());

        assert!(output.contains("Restart Tor: not supported yet"));
        assert!(!output.contains("[Q] Quit"));
    }

    #[test]
    fn copy_onion_degrades_without_clipboard() {
        let mut state = AppState::new();
        state.onion_address = Some("abcdefghijklmnop.onion".to_owned());

        assert!(copy_onion_status(&state).contains("Clipboard support unavailable"));
        assert!(copy_onion_status(&state).contains("abcdefghijklmnop.onion"));
    }
}
