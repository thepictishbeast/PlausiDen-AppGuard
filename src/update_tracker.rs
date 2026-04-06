//! App update tracker — monitor application version changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An application version change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEvent {
    pub app_id: String,
    pub old_version: String,
    pub new_version: String,
    pub timestamp: DateTime<Utc>,
    pub update_source: UpdateSource,
    pub security_update: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateSource {
    OfficialRepo,
    DirectDownload,
    PackageManager,
    Unknown,
}

/// App update tracker.
pub struct UpdateTracker {
    events: Vec<UpdateEvent>,
    current_versions: HashMap<String, String>,
}

impl UpdateTracker {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            current_versions: HashMap::new(),
        }
    }

    /// Record an update.
    pub fn record_update(&mut self, event: UpdateEvent) {
        self.current_versions.insert(event.app_id.clone(), event.new_version.clone());
        self.events.push(event);
    }

    /// Get current version of an app.
    pub fn current_version(&self, app_id: &str) -> Option<&String> {
        self.current_versions.get(app_id)
    }

    /// Find all updates for an app.
    pub fn history_for(&self, app_id: &str) -> Vec<&UpdateEvent> {
        self.events.iter().filter(|e| e.app_id == app_id).collect()
    }

    /// Find recent updates.
    pub fn recent(&self, max_age_secs: i64) -> Vec<&UpdateEvent> {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs);
        self.events.iter().filter(|e| e.timestamp > cutoff).collect()
    }

    /// Find security updates.
    pub fn security_updates(&self) -> Vec<&UpdateEvent> {
        self.events.iter().filter(|e| e.security_update).collect()
    }

    /// Apps that haven't been updated in N days.
    pub fn outdated_apps(&self, max_age_days: i64) -> Vec<String> {
        let cutoff = Utc::now() - chrono::Duration::days(max_age_days);
        let mut latest_update: HashMap<String, DateTime<Utc>> = HashMap::new();
        for event in &self.events {
            latest_update.entry(event.app_id.clone())
                .and_modify(|t| if event.timestamp > *t { *t = event.timestamp })
                .or_insert(event.timestamp);
        }
        latest_update.into_iter()
            .filter(|(_, t)| *t < cutoff)
            .map(|(app, _)| app)
            .collect()
    }

    /// Count updates by source.
    pub fn source_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for event in &self.events {
            *counts.entry(format!("{:?}", event.update_source)).or_default() += 1;
        }
        counts
    }

    pub fn event_count(&self) -> usize { self.events.len() }
    pub fn tracked_apps(&self) -> usize { self.current_versions.len() }
}

impl Default for UpdateTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(app: &str, old: &str, new: &str, security: bool) -> UpdateEvent {
        UpdateEvent {
            app_id: app.into(),
            old_version: old.into(),
            new_version: new.into(),
            timestamp: Utc::now(),
            update_source: UpdateSource::OfficialRepo,
            security_update: security,
        }
    }

    #[test]
    fn test_record_update() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("firefox", "100.0", "101.0", false));
        assert_eq!(tracker.current_version("firefox"), Some(&"101.0".to_string()));
    }

    #[test]
    fn test_history_for() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("app", "1.0", "1.1", false));
        tracker.record_update(make_event("app", "1.1", "1.2", false));
        tracker.record_update(make_event("other", "2.0", "2.1", false));
        assert_eq!(tracker.history_for("app").len(), 2);
    }

    #[test]
    fn test_security_updates() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("a", "1.0", "1.1", true));
        tracker.record_update(make_event("b", "1.0", "1.1", false));
        tracker.record_update(make_event("c", "1.0", "1.1", true));
        assert_eq!(tracker.security_updates().len(), 2);
    }

    #[test]
    fn test_outdated_apps() {
        let mut tracker = UpdateTracker::new();
        let mut old_event = make_event("old_app", "1.0", "1.1", false);
        old_event.timestamp = Utc::now() - chrono::Duration::days(60);
        tracker.record_update(old_event);
        tracker.record_update(make_event("current_app", "1.0", "1.1", false));
        let outdated = tracker.outdated_apps(30);
        assert!(outdated.contains(&"old_app".to_string()));
        assert!(!outdated.contains(&"current_app".to_string()));
    }

    #[test]
    fn test_recent() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("app", "1.0", "1.1", false));
        assert_eq!(tracker.recent(3600).len(), 1);
    }

    #[test]
    fn test_tracked_apps() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("a", "1", "2", false));
        tracker.record_update(make_event("b", "1", "2", false));
        tracker.record_update(make_event("a", "2", "3", false));
        assert_eq!(tracker.tracked_apps(), 2);
    }

    #[test]
    fn test_source_counts() {
        let mut tracker = UpdateTracker::new();
        tracker.record_update(make_event("a", "1", "2", false));
        tracker.record_update(make_event("b", "1", "2", false));
        let counts = tracker.source_counts();
        assert_eq!(*counts.get("OfficialRepo").unwrap(), 2);
    }
}
