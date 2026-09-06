//! # Console Input

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use tokio::sync::{mpsc::Sender, watch};

use crate::runtime::events::KeyEvent;

pub fn spawn(tx: Sender<KeyEvent>, shutdown: watch::Receiver<bool>) {
    tokio::task::spawn_blocking(move || loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() || tx.is_closed() {
            break;
        }

        match event::poll(Duration::from_millis(50)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) => {
                    let mut pending = map_key(key.code, key.modifiers);
                    loop {
                        match tx.try_send(pending) {
                            Ok(()) => break,
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                                pending = event;
                            }
                        }
                        if *shutdown.borrow() || shutdown.has_changed().is_err() {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(20));
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
        KeyCode::Char('m' | 'M') => KeyEvent::Menu,
        KeyCode::Char('c' | 'C') => KeyEvent::CopyDiagnostics,
        KeyCode::Char('r' | 'R') => KeyEvent::Reload,
        KeyCode::Char('d' | 'D') => KeyEvent::RunDoctorDeep,
        KeyCode::Char('o' | 'O') => KeyEvent::Open,
        KeyCode::Char('l' | 'L') => KeyEvent::ToggleLogs,
        KeyCode::Char('x' | 'X') => KeyEvent::ClearStatus,
        KeyCode::Up | KeyCode::Char('k' | 'K') => KeyEvent::NavigateUp,
        KeyCode::Down | KeyCode::Char('j' | 'J') => KeyEvent::NavigateDown,
        KeyCode::Enter => KeyEvent::OpenSelected,
        KeyCode::Esc => KeyEvent::Back,
        KeyCode::Char('q' | 'Q') => KeyEvent::Quit,
        KeyCode::Char('y' | 'Y') => KeyEvent::Confirm,
        KeyCode::Char('n' | 'N') => KeyEvent::Cancel,
        _ => KeyEvent::Other,
    }
}
