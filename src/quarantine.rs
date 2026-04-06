//! App quarantine — temporarily isolate suspicious applications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A quarantined app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedApp {
    pub app_id: String,
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
    pub release_after: Option<DateTime<Utc>>,
    pub original_permissions: Vec<String>,
    pub network_disabled: bool,
    pub auto_quarantine: bool,
}

/// Quarantine reason categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    SuspiciousBehavior,
    PolicyViolation,
    UnauthorizedAccess,
    UnknownPublisher,
    ManualReview,
    SignatureMismatch,
}

/// Quarantine manager.
pub struct QuarantineManager {
    quarantined: HashMap<String, QuarantinedApp>,
    /// History of quarantine actions.
    history: Vec<QuarantineRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub app_id: String,
    pub action: QuarantineAction,
    pub timestamp: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineAction {
    Quarantined,
    Released,
    Expired,
}

impl QuarantineManager {
    pub fn new() -> Self {
        Self {
            quarantined: HashMap::new(),
            history: Vec::new(),
        }
    }

    /// Quarantine an app.
    pub fn quarantine(&mut self, app_id: &str, reason: &str, release_after: Option<DateTime<Utc>>) {
        self.quarantined.insert(app_id.into(), QuarantinedApp {
            app_id: app_id.into(),
            reason: reason.into(),
            quarantined_at: Utc::now(),
            release_after,
            original_permissions: Vec::new(),
            network_disabled: true,
            auto_quarantine: false,
        });
        self.history.push(QuarantineRecord {
            app_id: app_id.into(),
            action: QuarantineAction::Quarantined,
            timestamp: Utc::now(),
            reason: reason.into(),
        });
    }

    /// Release an app from quarantine.
    pub fn release(&mut self, app_id: &str) -> bool {
        if let Some(app) = self.quarantined.remove(app_id) {
            self.history.push(QuarantineRecord {
                app_id: app_id.into(),
                action: QuarantineAction::Released,
                timestamp: Utc::now(),
                reason: app.reason,
            });
            true
        } else {
            false
        }
    }

    /// Check if an app is quarantined.
    pub fn is_quarantined(&self, app_id: &str) -> bool {
        self.quarantined.contains_key(app_id)
    }

    /// Get all quarantined apps.
    pub fn list(&self) -> Vec<&QuarantinedApp> {
        self.quarantined.values().collect()
    }

    /// Process expirations (release apps past their TTL).
    pub fn process_expirations(&mut self) -> Vec<String> {
        let now = Utc::now();
        let to_release: Vec<String> = self.quarantined.iter()
            .filter(|(_, app)| app.release_after.map(|t| t <= now).unwrap_or(false))
            .map(|(id, _)| id.clone())
            .collect();

        for id in &to_release {
            if let Some(app) = self.quarantined.remove(id) {
                self.history.push(QuarantineRecord {
                    app_id: id.clone(),
                    action: QuarantineAction::Expired,
                    timestamp: now,
                    reason: app.reason,
                });
            }
        }

        to_release
    }

    /// Get history for an app.
    pub fn history_for(&self, app_id: &str) -> Vec<&QuarantineRecord> {
        self.history.iter().filter(|r| r.app_id == app_id).collect()
    }

    pub fn quarantine_count(&self) -> usize { self.quarantined.len() }
    pub fn history_count(&self) -> usize { self.history.len() }
}

impl Default for QuarantineManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_quarantine() {
        let mut mgr = QuarantineManager::new();
        mgr.quarantine("suspicious", "spawn shell", None);
        assert!(mgr.is_quarantined("suspicious"));
        assert_eq!(mgr.quarantine_count(), 1);
    }

    #[test]
    fn test_release() {
        let mut mgr = QuarantineManager::new();
        mgr.quarantine("app", "test", None);
        assert!(mgr.release("app"));
        assert!(!mgr.is_quarantined("app"));
    }

    #[test]
    fn test_history() {
        let mut mgr = QuarantineManager::new();
        mgr.quarantine("app", "test", None);
        mgr.release("app");
        let history = mgr.history_for("app");
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_expiration() {
        let mut mgr = QuarantineManager::new();
        let past = Utc::now() - Duration::hours(1);
        mgr.quarantine("expiring", "test", Some(past));
        let released = mgr.process_expirations();
        assert_eq!(released.len(), 1);
        assert!(!mgr.is_quarantined("expiring"));
    }

    #[test]
    fn test_no_expiration_for_indefinite() {
        let mut mgr = QuarantineManager::new();
        mgr.quarantine("permanent", "test", None);
        let released = mgr.process_expirations();
        assert!(released.is_empty());
    }

    #[test]
    fn test_release_unknown() {
        let mut mgr = QuarantineManager::new();
        assert!(!mgr.release("unknown"));
    }

    #[test]
    fn test_list() {
        let mut mgr = QuarantineManager::new();
        mgr.quarantine("a", "r1", None);
        mgr.quarantine("b", "r2", None);
        assert_eq!(mgr.list().len(), 2);
    }
}
