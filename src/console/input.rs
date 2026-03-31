//! # Console Input
//!
//! **File:** `input.rs`
//! **Location:** `src/console/input.rs`

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use tokio::sync::{mpsc::UnboundedSender, watch};

use crate::runtime::events::KeyEvent;

pub fn spawn(tx: UnboundedSender<KeyEvent>, shutdown: watch::Receiver<bool>) {
    tokio::task::spawn_blocking(move || loop {
        if *shutdown.borrow() {
            break;
        }

        match event::poll(Duration::from_millis(50)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) => {
                    if tx.send(map_key(key.code, key.modifiers)).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    });
}

fn map_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        return KeyEvent::ForceQuit;
    }

    match code {
        KeyCode::Char('h' | 'H') => KeyEvent::Help,
        KeyCode::Char('r' | 'R') => KeyEvent::Reload,
        KeyCode::Char('o' | 'O') => KeyEvent::Open,
        KeyCode::Char('l' | 'L') => KeyEvent::ToggleLogs,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => KeyEvent::Quit,
        KeyCode::Char('y' | 'Y') => KeyEvent::Confirm,
        KeyCode::Char('n' | 'N') => KeyEvent::Cancel,
        _ => KeyEvent::Other,
    }
}
