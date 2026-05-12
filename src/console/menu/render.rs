use std::fmt::Write as _;

use std::path::Path;

use crate::{config::Config, console::ui, runtime::state::AppState};

use super::{
    doctor::{status_style_label, DoctorStatus},
    pages::Page,
    state::pulse_visible,
    MenuState,
};

#[must_use]
pub fn render(menu: &MenuState, config: &Config, state: &AppState, data_dir: &Path) -> String {
    menu.active_page().map_or_else(
        || render_index(menu),
        |page| render_page(page, menu, config, state, data_dir),
    )
}

fn render_index(state: &MenuState) -> String {
    let selected_page = state.selected_page();
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "RustHost Menu\r");
    out.push_str("\r\n");

    for (index, page) in Page::ALL.iter().enumerate() {
        let marker = if index == state.selected_index() {
            if pulse_visible() {
                ui::bold(">")
            } else {
                ui::dim(">")
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

fn render_page(
    page: Page,
    menu: &MenuState,
    config: &Config,
    state: &AppState,
    data_dir: &Path,
) -> String {
    if page == Page::Doctor {
        return render_doctor(menu);
    }
    if page == Page::Diagnostics {
        return render_diagnostics(menu);
    }
    match page {
        Page::Tor => super::tor::render(menu.tor(), config, state),
        Page::Network => super::network::render(menu.network()),
        Page::Site => super::site::render(menu.site()),
        Page::Settings => super::settings::render(menu.settings(), config, state, data_dir),
        Page::Help => super::help::render(menu.help()),
        Page::Home | Page::Logs | Page::Doctor | Page::Diagnostics => render_index(menu),
    }
}

fn render_diagnostics(state: &MenuState) -> String {
    let mut out = String::with_capacity(1_024);
    ui::push_header(&mut out, "RustHost Diagnostics");
    out.push_str("\r\n");

    let diagnostics = state.diagnostics();
    if let Some(report) = diagnostics.report() {
        for line in report.text().lines() {
            let _ = writeln!(out, "{line}\r");
        }
    } else {
        out.push_str("Diagnostics snapshot has not been collected yet.\r\n");
    }

    if let Some(status) = diagnostics.status() {
        out.push_str("\r\n");
        let _ = writeln!(out, "{}\r", ui::dim(status));
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::RULE);
    out.push_str("[C] Copy diagnostics  [R] Refresh  [X] Clear status  [Esc] Back\r\n");
    let _ = writeln!(out, "{}\r", ui::RULE);
    out
}

fn render_doctor(state: &MenuState) -> String {
    let mut out = String::with_capacity(2_048);
    ui::push_header(&mut out, "Doctor");
    out.push_str("\r\n");

    let doctor = state.doctor();
    if let Some(report) = doctor.report() {
        for (index, section) in report.sections().iter().enumerate() {
            let marker = if index == doctor.selected_section() {
                ui::bold(">")
            } else {
                " ".to_owned()
            };
            let status = color_status(section.summary_status());
            let _ = writeln!(out, "{marker} {:<12} {status}\r", section.name());

            if doctor.expanded_section() == Some(index) {
                for check in section.checks() {
                    let status = color_status(check.status());
                    let _ = writeln!(out, "    {:<7} {}\r", status, check.message());
                }
            }
        }

        out.push_str("\r\n");
        let result = if report.has_failures() {
            color_status(DoctorStatus::Fail)
        } else {
            color_status(DoctorStatus::Pass)
        };
        let message = if report.has_failures() {
            "RustHost is not ready to start."
        } else {
            "RustHost appears ready to start."
        };
        let _ = writeln!(out, "Result: {result} {message}\r");
    } else {
        out.push_str("Doctor report has not run yet.\r\n");
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::RULE);
    out.push_str("[R] Re-run fast checks  [D] Run deep checks  [Enter] Expand/collapse\r\n");
    out.push_str("[↑↓/jk] Navigate sections  [Esc] Back\r\n");
    let _ = writeln!(out, "{}\r", ui::RULE);
    out
}

fn color_status(status: DoctorStatus) -> String {
    let (label, color) = status_style_label(status);
    format!("{color}{label}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::{config::Config, console::menu::MenuState, runtime::state::AppState};

    fn render_test(state: &MenuState) -> String {
        render(
            state,
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("."),
        )
    }

    #[test]
    fn menu_renders_selected_marker_and_selected_description() {
        let output = render_test(&MenuState::new());

        assert!(output.contains("Home"));
        assert!(output.contains("Logs"));
        assert!(output.contains("Doctor"));
        assert!(output.contains("Diagnostics"));
        assert!(output.contains("Return to the main RustHost dashboard."));
        assert!(output.contains("[↑↓] Navigate  [Enter] Open  [Esc] Back  [Q] Quit"));
    }

    #[test]
    fn doctor_page_renders_without_quit_control() {
        let mut state = MenuState::new();
        state.move_down();
        state.move_down();
        let _ = state.open_selected();

        let output = render_test(&state);

        assert!(output.contains("Doctor"));
        assert!(output.contains("Doctor report has not run yet."));
        assert!(output.contains("[Esc] Back"));
        assert!(!output.contains("[Q] Quit"));
    }
}
