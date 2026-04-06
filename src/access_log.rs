//! Access log — record file/network/IPC access events for forensic review.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Access event type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessType {
    FileRead,
    FileWrite,
    FileDelete,
    FileExecute,
    NetworkConnect,
    NetworkListen,
    IpcSend,
    IpcReceive,
    DeviceAccess,
    SyscallExec,
}

/// Access event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub timestamp: DateTime<Utc>,
    pub app_id: String,
    pub access_type: AccessType,
    pub resource: String,
    pub success: bool,
    pub user: String,
}

/// Access log with bounded storage.
pub struct AccessLog {
    events: VecDeque<AccessEvent>,
    max_events: usize,
}

impl AccessLog {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_events,
        }
    }

    /// Record an access event.
    pub fn record(&mut self, event: AccessEvent) {
        self.events.push_back(event);
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    /// Get events for an app.
    pub fn for_app(&self, app_id: &str) -> Vec<&AccessEvent> {
        self.events.iter().filter(|e| e.app_id == app_id).collect()
    }

    /// Get events of a specific type.
    pub fn by_type(&self, access_type: &AccessType) -> Vec<&AccessEvent> {
        self.events.iter().filter(|e| &e.access_type == access_type).collect()
    }

    /// Get events for a resource.
    pub fn for_resource(&self, resource: &str) -> Vec<&AccessEvent> {
        self.events.iter().filter(|e| e.resource.contains(resource)).collect()
    }

    /// Get failed access attempts.
    pub fn failures(&self) -> Vec<&AccessEvent> {
        self.events.iter().filter(|e| !e.success).collect()
    }

    /// Get the most recent N events.
    pub fn recent(&self, n: usize) -> Vec<&AccessEvent> {
        let start = self.events.len().saturating_sub(n);
        self.events.iter().skip(start).collect()
    }

    /// Apps with the most access attempts.
    pub fn top_accessors(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for e in &self.events {
            *counts.entry(e.app_id.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    pub fn count(&self) -> usize { self.events.len() }
}

impl Default for AccessLog {
    fn default() -> Self { Self::new(100_000) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(app: &str, access: AccessType, resource: &str) -> AccessEvent {
        AccessEvent {
            timestamp: Utc::now(),
            app_id: app.into(),
            access_type: access,
            resource: resource.into(),
            success: true,
            user: "user".into(),
        }
    }

    #[test]
    fn test_record_and_count() {
        let mut log = AccessLog::default();
        log.record(make_event("firefox", AccessType::FileRead, "/etc/hosts"));
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn test_for_app() {
        let mut log = AccessLog::default();
        log.record(make_event("a", AccessType::FileRead, "/file1"));
        log.record(make_event("b", AccessType::FileRead, "/file2"));
        log.record(make_event("a", AccessType::FileWrite, "/file3"));
        assert_eq!(log.for_app("a").len(), 2);
    }

    #[test]
    fn test_by_type() {
        let mut log = AccessLog::default();
        log.record(make_event("a", AccessType::FileRead, "/f1"));
        log.record(make_event("a", AccessType::FileWrite, "/f2"));
        log.record(make_event("a", AccessType::FileRead, "/f3"));
        assert_eq!(log.by_type(&AccessType::FileRead).len(), 2);
    }

    #[test]
    fn test_for_resource() {
        let mut log = AccessLog::default();
        log.record(make_event("a", AccessType::FileRead, "/etc/hosts"));
        log.record(make_event("a", AccessType::FileRead, "/var/log/auth"));
        log.record(make_event("a", AccessType::FileRead, "/etc/passwd"));
        let etc_events = log.for_resource("/etc");
        assert_eq!(etc_events.len(), 2);
    }

    #[test]
    fn test_failures() {
        let mut log = AccessLog::default();
        let mut failed = make_event("a", AccessType::FileRead, "/etc/shadow");
        failed.success = false;
        log.record(failed);
        log.record(make_event("a", AccessType::FileRead, "/etc/hosts"));
        assert_eq!(log.failures().len(), 1);
    }

    #[test]
    fn test_recent() {
        let mut log = AccessLog::default();
        for i in 0..10 {
            log.record(make_event("a", AccessType::FileRead, &format!("/f{i}")));
        }
        let last = log.recent(3);
        assert_eq!(last.len(), 3);
    }

    #[test]
    fn test_top_accessors() {
        let mut log = AccessLog::default();
        for _ in 0..10 { log.record(make_event("heavy", AccessType::FileRead, "/f")); }
        for _ in 0..3 { log.record(make_event("light", AccessType::FileRead, "/f")); }
        let top = log.top_accessors(1);
        assert_eq!(top[0].0, "heavy");
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_eviction() {
        let mut log = AccessLog::new(5);
        for i in 0..10 {
            log.record(make_event("a", AccessType::FileRead, &format!("/f{i}")));
        }
        assert_eq!(log.count(), 5);
    }

    #[test]
    fn test_clear() {
        let mut log = AccessLog::default();
        log.record(make_event("a", AccessType::FileRead, "/f"));
        log.clear();
        assert_eq!(log.count(), 0);
    }
}
