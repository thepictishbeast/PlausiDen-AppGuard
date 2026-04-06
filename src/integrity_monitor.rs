//! Integrity monitor — track binary hashes for installed apps and detect changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A baseline hash for an application binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryBaseline {
    pub app_id: String,
    pub binary_path: PathBuf,
    pub hash_hex: String,
    pub hash_algorithm: String,
    pub size_bytes: u64,
    pub recorded_at: DateTime<Utc>,
    pub version: String,
}

/// An integrity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityEvent {
    pub app_id: String,
    pub binary_path: PathBuf,
    pub event_type: EventType,
    pub old_hash: Option<String>,
    pub new_hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Baseline,
    Unchanged,
    HashChanged,
    SizeChanged,
    Missing,
    NewBinary,
}

/// Integrity monitor.
pub struct IntegrityMonitor {
    baselines: HashMap<PathBuf, BinaryBaseline>,
    events: Vec<IntegrityEvent>,
    history_limit: usize,
}

impl IntegrityMonitor {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            events: Vec::new(),
            history_limit: 5000,
        }
    }

    /// Record a baseline hash.
    pub fn record_baseline(&mut self, baseline: BinaryBaseline) {
        self.events.push(IntegrityEvent {
            app_id: baseline.app_id.clone(),
            binary_path: baseline.binary_path.clone(),
            event_type: EventType::Baseline,
            old_hash: None,
            new_hash: baseline.hash_hex.clone(),
            timestamp: Utc::now(),
        });
        self.baselines.insert(baseline.binary_path.clone(), baseline);
        self.trim_events();
    }

    /// Check observed binary state against baseline.
    pub fn check(
        &mut self,
        app_id: &str,
        path: &std::path::Path,
        new_hash: &str,
        new_size: u64,
    ) -> IntegrityEvent {
        let now = Utc::now();
        let baseline = self.baselines.get(path).cloned();

        let event = match baseline {
            None => IntegrityEvent {
                app_id: app_id.into(),
                binary_path: path.into(),
                event_type: EventType::NewBinary,
                old_hash: None,
                new_hash: new_hash.into(),
                timestamp: now,
            },
            Some(b) => {
                if b.hash_hex == new_hash && b.size_bytes == new_size {
                    IntegrityEvent {
                        app_id: app_id.into(),
                        binary_path: path.into(),
                        event_type: EventType::Unchanged,
                        old_hash: Some(b.hash_hex),
                        new_hash: new_hash.into(),
                        timestamp: now,
                    }
                } else if b.size_bytes != new_size {
                    IntegrityEvent {
                        app_id: app_id.into(),
                        binary_path: path.into(),
                        event_type: EventType::SizeChanged,
                        old_hash: Some(b.hash_hex),
                        new_hash: new_hash.into(),
                        timestamp: now,
                    }
                } else {
                    IntegrityEvent {
                        app_id: app_id.into(),
                        binary_path: path.into(),
                        event_type: EventType::HashChanged,
                        old_hash: Some(b.hash_hex),
                        new_hash: new_hash.into(),
                        timestamp: now,
                    }
                }
            }
        };

        self.events.push(event.clone());
        self.trim_events();
        event
    }

    /// Mark a binary as missing.
    pub fn mark_missing(&mut self, app_id: &str, path: &std::path::Path) {
        let now = Utc::now();
        self.events.push(IntegrityEvent {
            app_id: app_id.into(),
            binary_path: path.into(),
            event_type: EventType::Missing,
            old_hash: self.baselines.get(path).map(|b| b.hash_hex.clone()),
            new_hash: String::new(),
            timestamp: now,
        });
        self.trim_events();
    }

    fn trim_events(&mut self) {
        if self.events.len() > self.history_limit {
            let excess = self.events.len() - self.history_limit;
            self.events.drain(0..excess);
        }
    }

    /// Events of a specific type.
    pub fn events_by_type(&self, kind: &EventType) -> Vec<&IntegrityEvent> {
        self.events.iter().filter(|e| &e.event_type == kind).collect()
    }

    /// All events for an app.
    pub fn events_for_app(&self, app_id: &str) -> Vec<&IntegrityEvent> {
        self.events.iter().filter(|e| e.app_id == app_id).collect()
    }

    /// Recent events.
    pub fn recent(&self, n: usize) -> Vec<&IntegrityEvent> {
        let start = self.events.len().saturating_sub(n);
        self.events.iter().skip(start).collect()
    }

    pub fn baseline_count(&self) -> usize { self.baselines.len() }
    pub fn event_count(&self) -> usize { self.events.len() }
}

impl Default for IntegrityMonitor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(path: &str, hash: &str, size: u64) -> BinaryBaseline {
        BinaryBaseline {
            app_id: "app".into(),
            binary_path: PathBuf::from(path),
            hash_hex: hash.into(),
            hash_algorithm: "blake3".into(),
            size_bytes: size,
            recorded_at: Utc::now(),
            version: "1.0".into(),
        }
    }

    #[test]
    fn test_record_baseline() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        assert_eq!(m.baseline_count(), 1);
    }

    #[test]
    fn test_unchanged_detection() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        let event = m.check("app", std::path::Path::new("/bin/app"), "hash1", 1000);
        assert_eq!(event.event_type, EventType::Unchanged);
    }

    #[test]
    fn test_hash_changed() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        let event = m.check("app", std::path::Path::new("/bin/app"), "hash2", 1000);
        assert_eq!(event.event_type, EventType::HashChanged);
    }

    #[test]
    fn test_size_changed() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        let event = m.check("app", std::path::Path::new("/bin/app"), "hash2", 2000);
        assert_eq!(event.event_type, EventType::SizeChanged);
    }

    #[test]
    fn test_new_binary() {
        let mut m = IntegrityMonitor::new();
        let event = m.check("newapp", std::path::Path::new("/bin/new"), "hash1", 1000);
        assert_eq!(event.event_type, EventType::NewBinary);
    }

    #[test]
    fn test_mark_missing() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        m.mark_missing("app", std::path::Path::new("/bin/app"));
        assert_eq!(m.events_by_type(&EventType::Missing).len(), 1);
    }

    #[test]
    fn test_events_for_app() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/app", "hash1", 1000));
        m.check("app", std::path::Path::new("/bin/app"), "hash2", 1000);
        assert!(m.events_for_app("app").len() >= 2);
    }

    #[test]
    fn test_recent() {
        let mut m = IntegrityMonitor::new();
        m.record_baseline(baseline("/bin/a", "h", 1));
        m.record_baseline(baseline("/bin/b", "h", 1));
        assert_eq!(m.recent(5).len(), 2);
    }
}
