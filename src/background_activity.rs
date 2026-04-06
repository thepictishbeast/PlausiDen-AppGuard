//! Background activity tracker — monitor what apps do when no user is present.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A background activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundEvent {
    pub app_id: String,
    pub activity: ActivityType,
    pub timestamp: DateTime<Utc>,
    pub bytes_used: u64,
    pub cpu_seconds: f64,
    pub user_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivityType {
    NetworkRequest,
    FileWrite,
    FileRead,
    LocationQuery,
    MicrophoneAccess,
    CameraAccess,
    ClipboardRead,
    NotificationPosted,
    SystemCall,
    DatabaseQuery,
}

impl ActivityType {
    pub fn is_sensitive(&self) -> bool {
        matches!(self,
            ActivityType::LocationQuery
                | ActivityType::MicrophoneAccess
                | ActivityType::CameraAccess
                | ActivityType::ClipboardRead
        )
    }
}

/// Per-app background activity summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBackgroundStats {
    pub app_id: String,
    pub total_events: u64,
    pub network_bytes: u64,
    pub cpu_seconds: f64,
    pub sensitive_count: u64,
    pub by_activity: HashMap<String, u64>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Background activity tracker.
pub struct BackgroundActivity {
    events: Vec<BackgroundEvent>,
    stats: HashMap<String, AppBackgroundStats>,
    history_limit: usize,
}

impl BackgroundActivity {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            stats: HashMap::new(),
            history_limit: 10_000,
        }
    }

    /// Record a background event.
    pub fn observe(&mut self, event: BackgroundEvent) {
        let app_id = event.app_id.clone();
        let stats = self.stats.entry(app_id.clone())
            .or_insert_with(|| AppBackgroundStats {
                app_id,
                total_events: 0,
                network_bytes: 0,
                cpu_seconds: 0.0,
                sensitive_count: 0,
                by_activity: HashMap::new(),
                first_seen: event.timestamp,
                last_seen: event.timestamp,
            });
        if !event.user_present {
            stats.total_events += 1;
            stats.last_seen = event.timestamp;
            if event.timestamp < stats.first_seen {
                stats.first_seen = event.timestamp;
            }
            if event.activity == ActivityType::NetworkRequest {
                stats.network_bytes += event.bytes_used;
            }
            stats.cpu_seconds += event.cpu_seconds;
            if event.activity.is_sensitive() {
                stats.sensitive_count += 1;
            }
            *stats.by_activity.entry(format!("{:?}", event.activity)).or_insert(0) += 1;
        }
        self.events.push(event);
        if self.events.len() > self.history_limit {
            self.events.remove(0);
        }
    }

    /// Stats for an app.
    pub fn stats_for(&self, app_id: &str) -> Option<&AppBackgroundStats> {
        self.stats.get(app_id)
    }

    /// Top apps by background CPU usage.
    pub fn top_cpu_users(&self, n: usize) -> Vec<&AppBackgroundStats> {
        let mut sorted: Vec<&AppBackgroundStats> = self.stats.values().collect();
        sorted.sort_by(|a, b| b.cpu_seconds.partial_cmp(&a.cpu_seconds).unwrap());
        sorted.truncate(n);
        sorted
    }

    /// Top apps by background network usage.
    pub fn top_network_users(&self, n: usize) -> Vec<&AppBackgroundStats> {
        let mut sorted: Vec<&AppBackgroundStats> = self.stats.values().collect();
        sorted.sort_by(|a, b| b.network_bytes.cmp(&a.network_bytes));
        sorted.truncate(n);
        sorted
    }

    /// Apps with sensitive background access.
    pub fn sensitive_offenders(&self, min: u64) -> Vec<&AppBackgroundStats> {
        self.stats.values().filter(|s| s.sensitive_count >= min).collect()
    }

    /// All events for an app while user wasn't present.
    pub fn background_events_for(&self, app_id: &str) -> Vec<&BackgroundEvent> {
        self.events.iter()
            .filter(|e| e.app_id == app_id && !e.user_present)
            .collect()
    }

    /// Total apps tracked.
    pub fn app_count(&self) -> usize {
        self.stats.len()
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for BackgroundActivity {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(app: &str, activity: ActivityType, user_present: bool) -> BackgroundEvent {
        BackgroundEvent {
            app_id: app.into(),
            activity,
            timestamp: Utc::now(),
            bytes_used: 1000,
            cpu_seconds: 0.5,
            user_present,
        }
    }

    #[test]
    fn test_observe_background_event() {
        let mut t = BackgroundActivity::new();
        t.observe(event("app", ActivityType::NetworkRequest, false));
        assert_eq!(t.stats_for("app").unwrap().total_events, 1);
    }

    #[test]
    fn test_user_present_not_counted() {
        let mut t = BackgroundActivity::new();
        t.observe(event("app", ActivityType::NetworkRequest, true));
        assert!(t.stats_for("app").is_none()
            || t.stats_for("app").unwrap().total_events == 0);
    }

    #[test]
    fn test_sensitive_detection() {
        assert!(ActivityType::CameraAccess.is_sensitive());
        assert!(ActivityType::MicrophoneAccess.is_sensitive());
        assert!(!ActivityType::FileRead.is_sensitive());
    }

    #[test]
    fn test_sensitive_count_tracked() {
        let mut t = BackgroundActivity::new();
        t.observe(event("snoop", ActivityType::CameraAccess, false));
        t.observe(event("snoop", ActivityType::MicrophoneAccess, false));
        t.observe(event("snoop", ActivityType::NetworkRequest, false));
        assert_eq!(t.stats_for("snoop").unwrap().sensitive_count, 2);
    }

    #[test]
    fn test_top_cpu_users() {
        let mut t = BackgroundActivity::new();
        let mut hot = event("hot", ActivityType::SystemCall, false);
        hot.cpu_seconds = 100.0;
        t.observe(hot);
        let mut cold = event("cold", ActivityType::SystemCall, false);
        cold.cpu_seconds = 1.0;
        t.observe(cold);
        let top = t.top_cpu_users(1);
        assert_eq!(top[0].app_id, "hot");
    }

    #[test]
    fn test_top_network_users() {
        let mut t = BackgroundActivity::new();
        let mut hungry = event("hungry", ActivityType::NetworkRequest, false);
        hungry.bytes_used = 1_000_000;
        t.observe(hungry);
        let mut sip = event("sip", ActivityType::NetworkRequest, false);
        sip.bytes_used = 100;
        t.observe(sip);
        let top = t.top_network_users(1);
        assert_eq!(top[0].app_id, "hungry");
    }

    #[test]
    fn test_sensitive_offenders() {
        let mut t = BackgroundActivity::new();
        for _ in 0..5 {
            t.observe(event("creeper", ActivityType::CameraAccess, false));
        }
        t.observe(event("normal", ActivityType::FileRead, false));
        let offenders = t.sensitive_offenders(3);
        assert_eq!(offenders.len(), 1);
        assert_eq!(offenders[0].app_id, "creeper");
    }

    #[test]
    fn test_background_events_for() {
        let mut t = BackgroundActivity::new();
        t.observe(event("app", ActivityType::NetworkRequest, false));
        t.observe(event("app", ActivityType::NetworkRequest, true));
        assert_eq!(t.background_events_for("app").len(), 1);
    }

    #[test]
    fn test_by_activity_breakdown() {
        let mut t = BackgroundActivity::new();
        t.observe(event("app", ActivityType::NetworkRequest, false));
        t.observe(event("app", ActivityType::FileWrite, false));
        let stats = t.stats_for("app").unwrap();
        assert_eq!(stats.by_activity.len(), 2);
    }
}
