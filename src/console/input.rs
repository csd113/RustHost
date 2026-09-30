//! # Console Input

use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use tokio::sync::{mpsc::Sender, watch, Notify};

use crate::runtime::events::KeyEvent;

pub fn spawn(tx: Sender<KeyEvent>, shutdown: watch::Receiver<bool>, render_notify: Arc<Notify>) {
    tokio::task::spawn_blocking(move || loop {
        if *shutdown.borrow() || shutdown.has_changed().is_err() || tx.is_closed() {
            break;
        }

        match event::poll(Duration::from_millis(50)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) => {
                    // Terminals using the kitty keyboard protocol and the
                    // Windows console report key release/repeat events; only
                    // act on presses to avoid duplicate navigation.
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
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
                // Repaint promptly after a resize rather than waiting for the
                // next refresh tick.
                Ok(Event::Resize(_, _)) => render_notify.notify_one(),
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
