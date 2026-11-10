//! Headless event bus: the engine (client/server/mdns) emits JSON events,
//! and registered listeners or CLI loggers receive them without any UI dependency.

use std::sync::RwLock;

pub type EventListener = Box<dyn Fn(&serde_json::Value) + Send + Sync>;

static LISTENERS: RwLock<Vec<EventListener>> = RwLock::new(Vec::new());

/// Register a custom event listener callback (e.g. CLI display, WebSocket, or parent app).
pub fn add_listener<F>(f: F)
where
    F: Fn(&serde_json::Value) + Send + Sync + 'static,
{
    if let Ok(mut list) = LISTENERS.write() {
        list.push(Box::new(f));
    }
}

/// Emit an event to all registered listeners.
pub fn emit(v: serde_json::Value) {
    if let Ok(list) = LISTENERS.read() {
        for listener in list.iter() {
            listener(&v);
        }
    }
}

/// level: "info" | "ok" | "warn" | "error"
pub fn status(level: &str, text: &str) {
    emit(serde_json::json!({
        "type": "status",
        "level": level,
        "text": text,
    }));
}
