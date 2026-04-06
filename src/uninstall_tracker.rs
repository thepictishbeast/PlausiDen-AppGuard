//! Uninstall tracker — monitor application removal and flag unexpected losses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An uninstall event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallEvent {
    pub app_id: String,
    pub app_name: String,
    pub version: String,
    pub uninstalled_at: DateTime<Utc>,
    pub uninstalled_by: UninstallSource,
    pub user_initiated: bool,
    pub cleanup_level: CleanupLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UninstallSource {
    PackageManager,
    AppStore,
    Manual,
    Scripted,
    SystemUpdate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupLevel {
    /// Only binaries removed.
    Partial,
    /// Binaries and config removed.
    Standard,
    /// Everything including user data.
    Full,
}

/// Flag raised by the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallFlag {
    pub app_id: String,
    pub flag_type: FlagType,
    pub confidence: f64,
    pub raised_at: DateTime<Utc>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagType {
    UnexpectedRemoval,
    CriticalAppRemoved,
    RapidBatchUninstall,
    NonUserInitiated,
    IncompleteCleanup,
}

/// Uninstall tracker.
pub struct UninstallTracker {
    events: Vec<UninstallEvent>,
    flags: Vec<UninstallFlag>,
    protected_apps: std::collections::HashSet<String>,
    history_limit: usize,
}

impl UninstallTracker {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            flags: Vec::new(),
            protected_apps: std::collections::HashSet::new(),
            history_limit: 5000,
        }
    }

    /// Mark an app as "protected" — removal flags as critical.
    pub fn protect(&mut self, app_id: &str) {
        self.protected_apps.insert(app_id.into());
    }

    /// Remove protection.
    pub fn unprotect(&mut self, app_id: &str) {
        self.protected_apps.remove(app_id);
    }

    /// Record an uninstall event. Returns any flags raised.
    pub fn record(&mut self, event: UninstallEvent) -> Vec<UninstallFlag> {
        let mut raised = Vec::new();
        let now = Utc::now();
        let app_id = event.app_id.clone();

        if self.protected_apps.contains(&app_id) {
            raised.push(UninstallFlag {
                app_id: app_id.clone(),
                flag_type: FlagType::CriticalAppRemoved,
                confidence: 0.95,
                raised_at: now,
                detail: format!("protected app {} was removed", event.app_name),
            });
        }

        if !event.user_initiated {
            raised.push(UninstallFlag {
                app_id: app_id.clone(),
                flag_type: FlagType::NonUserInitiated,
                confidence: 0.75,
                raised_at: now,
                detail: format!("uninstall not user-initiated, source {:?}", event.uninstalled_by),
            });
        }

        // Batch uninstall detection: >3 in the last 60s.
        let one_min_ago = now - chrono::Duration::seconds(60);
        let recent = self.events.iter().filter(|e| e.uninstalled_at > one_min_ago).count();
        if recent >= 3 {
            raised.push(UninstallFlag {
                app_id: app_id.clone(),
                flag_type: FlagType::RapidBatchUninstall,
                confidence: 0.8,
                raised_at: now,
                detail: format!("{}+ uninstalls in 60s", recent + 1),
            });
        }

        // Incomplete cleanup.
        if event.cleanup_level == CleanupLevel::Partial {
            raised.push(UninstallFlag {
                app_id: app_id.clone(),
                flag_type: FlagType::IncompleteCleanup,
                confidence: 0.6,
                raised_at: now,
                detail: format!("only partial cleanup for {}", event.app_name),
            });
        }

        self.events.push(event);
        if self.events.len() > self.history_limit {
            self.events.remove(0);
        }
        self.flags.extend(raised.clone());
        raised
    }

    /// All recorded uninstalls.
    pub fn events(&self) -> &[UninstallEvent] {
        &self.events
    }

    /// All recorded flags.
    pub fn flags(&self) -> &[UninstallFlag] {
        &self.flags
    }

    /// Flags by type.
    pub fn flags_by_type(&self, t: &FlagType) -> Vec<&UninstallFlag> {
        self.flags.iter().filter(|f| &f.flag_type == t).collect()
    }

    /// Uninstall counts by source.
    pub fn source_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for e in &self.events {
            *map.entry(format!("{:?}", e.uninstalled_by)).or_insert(0) += 1;
        }
        map
    }

    /// Recent uninstalls within last N seconds.
    pub fn recent(&self, secs: i64) -> Vec<&UninstallEvent> {
        let cutoff = Utc::now() - chrono::Duration::seconds(secs);
        self.events.iter().filter(|e| e.uninstalled_at > cutoff).collect()
    }

    pub fn total_uninstalls(&self) -> usize { self.events.len() }
    pub fn protected_count(&self) -> usize { self.protected_apps.len() }
}

impl Default for UninstallTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(app: &str) -> UninstallEvent {
        UninstallEvent {
            app_id: app.into(),
            app_name: format!("App {}", app),
            version: "1.0".into(),
            uninstalled_at: Utc::now(),
            uninstalled_by: UninstallSource::PackageManager,
            user_initiated: true,
            cleanup_level: CleanupLevel::Standard,
        }
    }

    #[test]
    fn test_basic_record() {
        let mut t = UninstallTracker::new();
        t.record(event("firefox"));
        assert_eq!(t.total_uninstalls(), 1);
    }

    #[test]
    fn test_protected_app_flagged() {
        let mut t = UninstallTracker::new();
        t.protect("sentinel");
        let flags = t.record(event("sentinel"));
        assert!(flags.iter().any(|f| f.flag_type == FlagType::CriticalAppRemoved));
    }

    #[test]
    fn test_non_user_initiated_flagged() {
        let mut t = UninstallTracker::new();
        let mut e = event("firefox");
        e.user_initiated = false;
        let flags = t.record(e);
        assert!(flags.iter().any(|f| f.flag_type == FlagType::NonUserInitiated));
    }

    #[test]
    fn test_rapid_batch_detected() {
        let mut t = UninstallTracker::new();
        t.record(event("a"));
        t.record(event("b"));
        t.record(event("c"));
        let flags = t.record(event("d"));
        assert!(flags.iter().any(|f| f.flag_type == FlagType::RapidBatchUninstall));
    }

    #[test]
    fn test_incomplete_cleanup_flagged() {
        let mut t = UninstallTracker::new();
        let mut e = event("firefox");
        e.cleanup_level = CleanupLevel::Partial;
        let flags = t.record(e);
        assert!(flags.iter().any(|f| f.flag_type == FlagType::IncompleteCleanup));
    }

    #[test]
    fn test_source_counts() {
        let mut t = UninstallTracker::new();
        t.record(event("a"));
        let mut e = event("b");
        e.uninstalled_by = UninstallSource::Manual;
        t.record(e);
        let counts = t.source_counts();
        assert_eq!(*counts.get("PackageManager").unwrap(), 1);
        assert_eq!(*counts.get("Manual").unwrap(), 1);
    }

    #[test]
    fn test_unprotect() {
        let mut t = UninstallTracker::new();
        t.protect("a");
        t.unprotect("a");
        let flags = t.record(event("a"));
        assert!(!flags.iter().any(|f| f.flag_type == FlagType::CriticalAppRemoved));
    }

    #[test]
    fn test_recent_events() {
        let mut t = UninstallTracker::new();
        t.record(event("a"));
        assert_eq!(t.recent(60).len(), 1);
    }

    #[test]
    fn test_flags_by_type() {
        let mut t = UninstallTracker::new();
        t.protect("a");
        t.record(event("a"));
        assert_eq!(t.flags_by_type(&FlagType::CriticalAppRemoved).len(), 1);
    }
}
