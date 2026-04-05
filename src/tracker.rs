//! App usage tracking — monitors which apps are actively used.

use chrono::{DateTime, Utc};
#[cfg(test)]
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Usage data for a single application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUsage {
    /// Application identifier (package name on Android, binary path on desktop).
    pub app_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Total time the app has been in foreground (seconds).
    pub foreground_time_secs: u64,
    /// Number of times launched.
    pub launch_count: u64,
    /// Last time the app was used.
    pub last_used: DateTime<Utc>,
    /// First time the app was recorded.
    pub first_seen: DateTime<Utc>,
    /// Installed size in bytes.
    pub installed_size_bytes: u64,
    /// Data/cache size in bytes.
    pub data_size_bytes: u64,
    /// Whether this app has been archived (data preserved, APK/binary removed).
    pub archived: bool,
}

impl AppUsage {
    /// Days since last use.
    pub fn days_since_last_use(&self) -> i64 {
        (Utc::now() - self.last_used).num_days()
    }

    /// Is the app considered unused? (default: 90 days)
    pub fn is_unused(&self, threshold_days: i64) -> bool {
        self.days_since_last_use() > threshold_days
    }

    /// Total space consumed (installed + data).
    pub fn total_size(&self) -> u64 {
        self.installed_size_bytes + self.data_size_bytes
    }

    /// Usage frequency (launches per day since first seen).
    pub fn usage_frequency(&self) -> f64 {
        let days = (Utc::now() - self.first_seen).num_days().max(1) as f64;
        self.launch_count as f64 / days
    }
}

/// Tracks usage across all applications.
pub struct UsageTracker {
    apps: HashMap<String, AppUsage>,
    /// Days of inactivity before suggesting archival.
    archive_threshold_days: i64,
}

impl UsageTracker {
    /// Create a new tracker.
    pub fn new(archive_threshold_days: i64) -> Self {
        Self {
            apps: HashMap::new(),
            archive_threshold_days,
        }
    }

    /// Record an app launch.
    pub fn record_launch(&mut self, app_id: &str, display_name: &str) {
        let now = Utc::now();
        let entry = self.apps.entry(app_id.to_string()).or_insert(AppUsage {
            app_id: app_id.to_string(),
            display_name: display_name.to_string(),
            foreground_time_secs: 0,
            launch_count: 0,
            last_used: now,
            first_seen: now,
            installed_size_bytes: 0,
            data_size_bytes: 0,
            archived: false,
        });
        entry.launch_count += 1;
        entry.last_used = now;
    }

    /// Record foreground time for an app.
    pub fn record_foreground_time(&mut self, app_id: &str, seconds: u64) {
        if let Some(entry) = self.apps.get_mut(app_id) {
            entry.foreground_time_secs += seconds;
            entry.last_used = Utc::now();
        }
    }

    /// Update size information for an app.
    pub fn update_size(&mut self, app_id: &str, installed: u64, data: u64) {
        if let Some(entry) = self.apps.get_mut(app_id) {
            entry.installed_size_bytes = installed;
            entry.data_size_bytes = data;
        }
    }

    /// Get all apps that are candidates for archival.
    pub fn archive_candidates(&self) -> Vec<&AppUsage> {
        let mut candidates: Vec<_> = self.apps.values()
            .filter(|a| a.is_unused(self.archive_threshold_days) && !a.archived)
            .collect();
        // Sort by total size descending — biggest space savings first
        candidates.sort_by(|a, b| b.total_size().cmp(&a.total_size()));
        candidates
    }

    /// Get total reclaimable space from archive candidates.
    pub fn reclaimable_space(&self) -> u64 {
        self.archive_candidates()
            .iter()
            .map(|a| a.installed_size_bytes) // Only binary size, keep data
            .sum()
    }

    /// Mark an app as archived.
    pub fn mark_archived(&mut self, app_id: &str) -> bool {
        if let Some(entry) = self.apps.get_mut(app_id) {
            entry.archived = true;
            true
        } else {
            false
        }
    }

    /// Get usage data for a specific app.
    pub fn get_app(&self, app_id: &str) -> Option<&AppUsage> {
        self.apps.get(app_id)
    }

    /// Get all tracked apps.
    pub fn all_apps(&self) -> Vec<&AppUsage> {
        self.apps.values().collect()
    }

    /// Number of tracked apps.
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }

    /// Get apps sorted by last used (most recent first).
    pub fn apps_by_recency(&self) -> Vec<&AppUsage> {
        let mut apps: Vec<_> = self.apps.values().collect();
        apps.sort_by(|a, b| b.last_used.cmp(&a.last_used));
        apps
    }

    /// Insert a pre-built [`AppUsage`] directly (useful for testing/import).
    pub fn insert_raw(&mut self, app_id: String, usage: AppUsage) {
        self.apps.insert(app_id, usage);
    }

    /// Get apps sorted by usage frequency (most used first).
    pub fn apps_by_frequency(&self) -> Vec<&AppUsage> {
        let mut apps: Vec<_> = self.apps.values().collect();
        apps.sort_by(|a, b| b.usage_frequency().partial_cmp(&a.usage_frequency()).unwrap_or(std::cmp::Ordering::Equal));
        apps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_launch() {
        let mut tracker = UsageTracker::new(90);
        tracker.record_launch("com.example.app", "Example App");
        tracker.record_launch("com.example.app", "Example App");

        let app = tracker.get_app("com.example.app").unwrap();
        assert_eq!(app.launch_count, 2);
        assert_eq!(app.display_name, "Example App");
    }

    #[test]
    fn test_archive_candidates() {
        let mut tracker = UsageTracker::new(90);
        tracker.record_launch("com.used.app", "Used App");

        // Manually set an old app
        tracker.apps.insert("com.old.app".to_string(), AppUsage {
            app_id: "com.old.app".to_string(),
            display_name: "Old App".to_string(),
            foreground_time_secs: 10,
            launch_count: 1,
            last_used: Utc::now() - Duration::days(180),
            first_seen: Utc::now() - Duration::days(365),
            installed_size_bytes: 50_000_000,
            data_size_bytes: 10_000_000,
            archived: false,
        });

        let candidates = tracker.archive_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].app_id, "com.old.app");
    }

    #[test]
    fn test_reclaimable_space() {
        let mut tracker = UsageTracker::new(30);
        tracker.apps.insert("old1".to_string(), AppUsage {
            app_id: "old1".to_string(),
            display_name: "Old 1".to_string(),
            foreground_time_secs: 0,
            launch_count: 0,
            last_used: Utc::now() - Duration::days(60),
            first_seen: Utc::now() - Duration::days(90),
            installed_size_bytes: 100_000,
            data_size_bytes: 50_000,
            archived: false,
        });

        assert_eq!(tracker.reclaimable_space(), 100_000); // Only binary, not data
    }

    #[test]
    fn test_mark_archived() {
        let mut tracker = UsageTracker::new(90);
        tracker.record_launch("com.test", "Test");
        assert!(tracker.mark_archived("com.test"));
        assert!(tracker.get_app("com.test").unwrap().archived);
    }

    #[test]
    fn test_archived_excluded_from_candidates() {
        let mut tracker = UsageTracker::new(1);
        tracker.apps.insert("archived".to_string(), AppUsage {
            app_id: "archived".to_string(),
            display_name: "Archived".to_string(),
            foreground_time_secs: 0,
            launch_count: 0,
            last_used: Utc::now() - Duration::days(30),
            first_seen: Utc::now() - Duration::days(60),
            installed_size_bytes: 100,
            data_size_bytes: 0,
            archived: true,
        });

        assert!(tracker.archive_candidates().is_empty());
    }

    #[test]
    fn test_usage_frequency() {
        let mut tracker = UsageTracker::new(90);
        tracker.apps.insert("daily".to_string(), AppUsage {
            app_id: "daily".to_string(),
            display_name: "Daily App".to_string(),
            foreground_time_secs: 3600,
            launch_count: 30,
            last_used: Utc::now(),
            first_seen: Utc::now() - Duration::days(30),
            installed_size_bytes: 0,
            data_size_bytes: 0,
            archived: false,
        });

        let app = tracker.get_app("daily").unwrap();
        assert!((app.usage_frequency() - 1.0).abs() < 0.1, "should be ~1 launch/day");
    }
}
