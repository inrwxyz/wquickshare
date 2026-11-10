//! Single owner of stdin.
//!
//! One background thread reads every line you type and forwards it into a channel.
//! Prompts (`read_line`) and live transfer commands (`try_line`: p / r / c) both take
//! lines from that channel, so they never fight over stdin.

use std::sync::OnceLock;
use tokio::sync::mpsc;

static TX: OnceLock<mpsc::UnboundedSender<String>> = OnceLock::new();
static RX: OnceLock<tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>> = OnceLock::new();

fn ensure_channel() -> (&'static mpsc::UnboundedSender<String>, &'static tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>) {
    let tx = TX.get_or_init(|| {
        let (tx, rx) = mpsc::unbounded_channel::<String>();
        let _ = RX.set(tokio::sync::Mutex::new(rx));
        tx
    });
    let rx = RX.get().unwrap();
    (tx, rx)
}

/// Optional: read stdin if running in a terminal console
pub fn init() {
    let (tx, _) = ensure_channel();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let cleaned = line.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
                    if tx.send(cleaned).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Lets the UI send a control command (p / r / c) immediately.
pub fn inject(line: &str) {
    let (tx, _) = ensure_channel();
    let _ = tx.send(line.to_string());
}

/// Non-blocking: returns a command only if one is waiting (used for p / r / c during transfers).
pub fn try_line() -> Option<String> {
    let (_, rx) = ensure_channel();
    let mut guard = rx.try_lock().ok()?;
    guard.try_recv().ok()
}

/// Throws away anything queued earlier.
pub fn drain() {
    while try_line().is_some() {}
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Pause,
    Resume,
    Cancel,
    Other,
}

pub fn parse_command(line: &str) -> Command {
    match line.trim().to_lowercase().as_str() {
        "p" | "pause" => Command::Pause,
        "r" | "resume" => Command::Resume,
        "c" | "cancel" | "x" => Command::Cancel,
        _ => Command::Other,
    }
}
