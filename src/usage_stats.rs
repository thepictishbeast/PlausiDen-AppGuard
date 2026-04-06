//! Usage statistics — aggregated app usage analytics.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-app usage record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStats {
    pub total_launches: u64,
    pub total_runtime_secs: u64,
    pub last_launched: Option<DateTime<Utc>>,
    pub days_active: u32,
    pub avg_session_secs: u64,
    pub peak_memory_bytes: u64,
}

/// Usage statistics aggregator.
pub struct UsageStats {
    apps: HashMap<String, AppStats>,
    /// Time window for "active" classification.
    active_window_days: i64,
}

impl UsageStats {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            active_window_days: 30,
        }
    }

    /// Record an app launch.
    pub fn record_launch(&mut self, app_id: &str) {
        let stats = self.apps.entry(app_id.into()).or_default();
        stats.total_launches += 1;
        stats.last_launched = Some(Utc::now());
    }

    /// Record runtime for an app.
    pub fn record_runtime(&mut self, app_id: &str, seconds: u64) {
        let stats = self.apps.entry(app_id.into()).or_default();
        stats.total_runtime_secs += seconds;
        if stats.total_launches > 0 {
            stats.avg_session_secs = stats.total_runtime_secs / stats.total_launches;
        }
    }

    /// Record peak memory.
    pub fn record_memory(&mut self, app_id: &str, bytes: u64) {
        let stats = self.apps.entry(app_id.into()).or_default();
        if bytes > stats.peak_memory_bytes {
            stats.peak_memory_bytes = bytes;
        }
    }

    /// Get apps by usage frequency.
    pub fn most_used(&self, n: usize) -> Vec<(String, u64)> {
        let mut sorted: Vec<_> = self.apps.iter()
            .map(|(id, s)| (id.clone(), s.total_launches))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Get apps by total runtime.
    pub fn longest_used(&self, n: usize) -> Vec<(String, u64)> {
        let mut sorted: Vec<_> = self.apps.iter()
            .map(|(id, s)| (id.clone(), s.total_runtime_secs))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Get apps not used recently (candidates for archival).
    pub fn unused_apps(&self) -> Vec<&str> {
        let cutoff = Utc::now() - Duration::days(self.active_window_days);
        self.apps.iter()
            .filter(|(_, s)| s.last_launched.map(|l| l < cutoff).unwrap_or(true))
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Get currently active apps (used within the window).
    pub fn active_apps(&self) -> Vec<&str> {
        let cutoff = Utc::now() - Duration::days(self.active_window_days);
        self.apps.iter()
            .filter(|(_, s)| s.last_launched.map(|l| l >= cutoff).unwrap_or(false))
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Get stats for a specific app.
    pub fn get(&self, app_id: &str) -> Option<&AppStats> {
        self.apps.get(app_id)
    }

    /// Total tracked apps.
    pub fn count(&self) -> usize { self.apps.len() }

    /// Set the active window in days.
    pub fn set_active_window(&mut self, days: i64) {
        self.active_window_days = days;
    }
}

impl Default for UsageStats {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_launch() {
        let mut stats = UsageStats::new();
        stats.record_launch("firefox");
        stats.record_launch("firefox");
        assert_eq!(stats.get("firefox").unwrap().total_launches, 2);
    }

    #[test]
    fn test_record_runtime() {
        let mut stats = UsageStats::new();
        stats.record_launch("firefox");
        stats.record_runtime("firefox", 3600);
        assert_eq!(stats.get("firefox").unwrap().total_runtime_secs, 3600);
        assert_eq!(stats.get("firefox").unwrap().avg_session_secs, 3600);
    }

    #[test]
    fn test_most_used() {
        let mut stats = UsageStats::new();
        for _ in 0..10 { stats.record_launch("a"); }
        for _ in 0..3 { stats.record_launch("b"); }
        let top = stats.most_used(2);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_longest_used() {
        let mut stats = UsageStats::new();
        stats.record_launch("a");
        stats.record_runtime("a", 7200);
        stats.record_launch("b");
        stats.record_runtime("b", 1000);
        let top = stats.longest_used(1);
        assert_eq!(top[0].0, "a");
    }

    #[test]
    fn test_record_memory_peak() {
        let mut stats = UsageStats::new();
        stats.record_launch("firefox");
        stats.record_memory("firefox", 1_000_000_000);
        stats.record_memory("firefox", 500_000_000); // Lower — shouldn't update.
        assert_eq!(stats.get("firefox").unwrap().peak_memory_bytes, 1_000_000_000);
    }

    #[test]
    fn test_unused_apps() {
        let mut stats = UsageStats::new();
        stats.record_launch("recent");
        // Manually set "old" to have an old launch time.
        stats.apps.insert("old".into(), AppStats {
            total_launches: 1,
            last_launched: Some(Utc::now() - Duration::days(60)),
            ..Default::default()
        });
        let unused = stats.unused_apps();
        assert!(unused.contains(&"old"));
        assert!(!unused.contains(&"recent"));
    }

    #[test]
    fn test_active_apps() {
        let mut stats = UsageStats::new();
        stats.record_launch("recent");
        let active = stats.active_apps();
        assert!(active.contains(&"recent"));
    }

    #[test]
    fn test_set_window() {
        let mut stats = UsageStats::new();
        stats.set_active_window(7);
        assert_eq!(stats.active_window_days, 7);
    }
}
