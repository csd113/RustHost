use std::time::{SystemTime, UNIX_EPOCH};

use super::{diagnostics::DiagnosticsReport, doctor::DoctorReport, Page};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuOpenTarget {
    Dashboard,
    LogView,
    Page(Page),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuState {
    selected: usize,
    active_page: Option<Page>,
    doctor: DoctorPageState,
    diagnostics: DiagnosticsPageState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorPageState {
    selected_section: usize,
    expanded_section: Option<usize>,
    report: Option<DoctorReport>,
}

impl DoctorPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected_section: 0,
            expanded_section: None,
            report: None,
        }
    }

    #[must_use]
    pub const fn selected_section(&self) -> usize {
        self.selected_section
    }

    #[must_use]
    pub const fn expanded_section(&self) -> Option<usize> {
        self.expanded_section
    }

    #[must_use]
    pub const fn report(&self) -> Option<&DoctorReport> {
        self.report.as_ref()
    }

    pub fn set_report(&mut self, report: DoctorReport) {
        let section_count = report.sections().len();
        self.selected_section = clamp_section(self.selected_section, section_count);
        self.report = Some(report);
    }

    pub fn move_up(&mut self) {
        let section_count = self.report.as_ref().map_or(0, |r| r.sections().len());
        if section_count == 0 {
            self.selected_section = 0;
            return;
        }
        self.selected_section = if self.selected_section == 0 {
            section_count - 1
        } else {
            self.selected_section - 1
        };
    }

    pub fn move_down(&mut self) {
        let section_count = self.report.as_ref().map_or(0, |r| r.sections().len());
        if section_count == 0 {
            self.selected_section = 0;
            return;
        }
        self.selected_section = (self.selected_section + 1) % section_count;
    }

    pub fn toggle_expanded(&mut self) {
        self.expanded_section = if self.expanded_section == Some(self.selected_section) {
            None
        } else {
            Some(self.selected_section)
        };
    }
}

impl Default for DoctorPageState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsPageState {
    report: Option<DiagnosticsReport>,
    status: Option<String>,
}

impl DiagnosticsPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            report: None,
            status: None,
        }
    }

    #[must_use]
    pub const fn report(&self) -> Option<&DiagnosticsReport> {
        self.report.as_ref()
    }

    #[must_use]
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn set_report(&mut self, report: DiagnosticsReport) {
        self.report = Some(report);
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = Some(status.into());
    }

    pub fn clear_status(&mut self) {
        self.status = None;
    }
}

impl Default for DiagnosticsPageState {
    fn default() -> Self {
        Self::new()
    }
}

impl MenuState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: 0,
            active_page: None,
            doctor: DoctorPageState::new(),
            diagnostics: DiagnosticsPageState::new(),
        }
    }

    #[must_use]
    pub const fn selected_index(&self) -> usize {
        self.selected
    }

    #[must_use]
    pub fn selected_page(&self) -> Page {
        Page::ALL.get(self.selected).copied().unwrap_or(Page::Home)
    }

    #[must_use]
    pub const fn active_page(&self) -> Option<Page> {
        self.active_page
    }

    #[must_use]
    pub const fn has_active_page(&self) -> bool {
        self.active_page.is_some()
    }

    pub const fn enter(&mut self) {
        self.active_page = None;
    }

    pub const fn leave(&mut self) {
        self.active_page = None;
    }

    pub fn move_up(&mut self) {
        if matches!(self.active_page, Some(Page::Doctor)) {
            self.doctor.move_up();
            return;
        }
        if self.has_active_page() {
            return;
        }

        self.selected = if self.selected == 0 {
            Page::ALL.len() - 1
        } else {
            self.selected - 1
        };
    }

    pub fn move_down(&mut self) {
        if matches!(self.active_page, Some(Page::Doctor)) {
            self.doctor.move_down();
            return;
        }
        if self.has_active_page() {
            return;
        }

        self.selected = (self.selected + 1) % Page::ALL.len();
    }

    pub fn open_selected(&mut self) -> MenuOpenTarget {
        self.active_page = None;

        match self.selected_page() {
            Page::Home => MenuOpenTarget::Dashboard,
            Page::Logs => MenuOpenTarget::LogView,
            page => {
                self.active_page = Some(page);
                MenuOpenTarget::Page(page)
            }
        }
    }

    #[must_use]
    pub const fn back(&mut self) -> bool {
        self.active_page.take().is_some()
    }

    #[must_use]
    pub const fn doctor(&self) -> &DoctorPageState {
        &self.doctor
    }

    #[must_use]
    pub const fn diagnostics(&self) -> &DiagnosticsPageState {
        &self.diagnostics
    }

    pub fn set_doctor_report(&mut self, report: DoctorReport) {
        self.doctor.set_report(report);
    }

    pub fn set_diagnostics_report(&mut self, report: DiagnosticsReport) {
        self.diagnostics.set_report(report);
    }

    pub fn set_diagnostics_status(&mut self, status: impl Into<String>) {
        self.diagnostics.set_status(status);
    }

    pub fn clear_diagnostics_status(&mut self) {
        self.diagnostics.clear_status();
    }

    pub fn toggle_doctor_section(&mut self) {
        if matches!(self.active_page, Some(Page::Doctor)) {
            self.doctor.toggle_expanded();
        }
    }
}

impl Default for MenuState {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn pulse_visible() -> bool {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(true, |duration| (duration.as_millis() / 700) % 2 == 0)
}

const fn clamp_section(selected: usize, section_count: usize) -> usize {
    if section_count == 0 || selected < section_count {
        selected
    } else {
        section_count - 1
    }
}

#[cfg(test)]
mod tests {
    use super::{MenuOpenTarget, MenuState};
    use crate::console::menu::Page;

    #[test]
    fn navigation_wraps_around_menu_items() {
        let mut state = MenuState::new();

        state.move_up();
        assert_eq!(state.selected_page(), Page::Help);

        state.move_down();
        assert_eq!(state.selected_page(), Page::Home);
    }

    #[test]
    fn open_selected_routes_home_and_logs_without_placeholder_state() {
        let mut state = MenuState::new();
        assert_eq!(state.open_selected(), MenuOpenTarget::Dashboard);
        assert_eq!(state.active_page(), None);

        state.move_down();
        assert_eq!(state.open_selected(), MenuOpenTarget::LogView);
        assert_eq!(state.active_page(), None);
    }

    #[test]
    fn back_closes_active_page_before_exiting_menu() {
        let mut state = MenuState::new();
        state.move_down();
        state.move_down();

        assert_eq!(state.open_selected(), MenuOpenTarget::Page(Page::Doctor));
        assert!(state.back());
        assert_eq!(state.active_page(), None);
        assert!(!state.back());
    }
}
