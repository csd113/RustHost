use std::fmt::Write as _;

use super::{pages::Page, state::pulse_visible, MenuState};

const RULE: &str = "──────────────────────────────────────────────────────────";

fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}

fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

#[must_use]
pub fn render(state: &MenuState) -> String {
    state
        .active_page()
        .map_or_else(|| render_index(*state), render_page)
}

fn render_index(state: MenuState) -> String {
    let selected_page = state.selected_page();
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "RustHost Menu\r");
    out.push_str("\r\n");

    for (index, page) in Page::ALL.iter().enumerate() {
        let marker = if index == state.selected_index() {
            if pulse_visible() {
                bold(">")
            } else {
                dim(">")
            }
        } else {
            " ".to_owned()
        };
        let _ = writeln!(out, "{marker} {}\r", page.label());
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", selected_page.description());
    out.push_str("\r\n");
    out.push_str("[↑↓] Navigate  [Enter] Open  [Esc] Back  [Q] Quit\r\n");
    out
}

fn render_page(page: Page) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold(page.label()));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", page.description());
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", page.placeholder_text());
    out.push_str("\r\n");
    out.push_str("This page is not implemented yet.\r\n");
    out.push_str("\r\n");
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("[Esc] Back\r\n");
    let _ = writeln!(out, "{RULE}\r");
    out
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::console::menu::MenuState;

    #[test]
    fn menu_renders_selected_marker_and_selected_description() {
        let output = render(&MenuState::new());

        assert!(output.contains("Home"));
        assert!(output.contains("Logs"));
        assert!(output.contains("Doctor"));
        assert!(output.contains("Return to the main RustHost dashboard."));
        assert!(output.contains("[↑↓] Navigate  [Enter] Open  [Esc] Back  [Q] Quit"));
    }

    #[test]
    fn placeholder_page_renders_minimal_not_implemented_state() {
        let mut state = MenuState::new();
        state.move_down();
        state.move_down();
        let _ = state.open_selected();

        let output = render(&state);

        assert!(output.contains("Doctor"));
        assert!(
            output.contains("Check config, paths, ports, TLS, Tor, favicon, and runtime safety.")
        );
        assert!(output.contains("This page is not implemented yet."));
        assert!(output.contains("[Esc] Back"));
        assert!(!output.contains("[Q] Quit"));
    }
}
