use std::time::{SystemTime, UNIX_EPOCH};

use super::Page;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuOpenTarget {
    Dashboard,
    LogView,
    Page(Page),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuState {
    selected: usize,
    active_page: Option<Page>,
}

impl MenuState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selected: 0,
            active_page: None,
        }
    }

    #[must_use]
    pub const fn selected_index(self) -> usize {
        self.selected
    }

    #[must_use]
    pub fn selected_page(self) -> Page {
        Page::ALL.get(self.selected).copied().unwrap_or(Page::Home)
    }

    #[must_use]
    pub const fn active_page(self) -> Option<Page> {
        self.active_page
    }

    #[must_use]
    pub const fn has_active_page(self) -> bool {
        self.active_page.is_some()
    }

    pub const fn enter(&mut self) {
        self.active_page = None;
    }

    pub const fn leave(&mut self) {
        self.active_page = None;
    }

    pub const fn move_up(&mut self) {
        if self.has_active_page() {
            return;
        }

        self.selected = if self.selected == 0 {
            Page::ALL.len() - 1
        } else {
            self.selected - 1
        };
    }

    pub const fn move_down(&mut self) {
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
