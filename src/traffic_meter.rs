//! Traffic meter — per-app bandwidth tracking with daily/monthly totals.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A traffic sample in bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub app_id: String,
    pub timestamp: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub interface: String,
}

/// Per-app traffic totals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTraffic {
    pub app_id: String,
    pub total_sent: u64,
    pub total_received: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub daily: HashMap<String, (u64, u64)>, // YYYY-MM-DD → (sent, received)
    pub monthly: HashMap<String, (u64, u64)>, // YYYY-MM → (sent, received)
}

impl AppTraffic {
    pub fn total_bytes(&self) -> u64 {
        self.total_sent + self.total_received
    }

    pub fn today_bytes(&self) -> (u64, u64) {
        let key = Utc::now().format("%Y-%m-%d").to_string();
        self.daily.get(&key).copied().unwrap_or((0, 0))
    }

    pub fn this_month_bytes(&self) -> (u64, u64) {
        let key = Utc::now().format("%Y-%m").to_string();
        self.monthly.get(&key).copied().unwrap_or((0, 0))
    }
}

/// Traffic meter.
pub struct TrafficMeter {
    apps: HashMap<String, AppTraffic>,
    total_samples: u64,
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self { apps: HashMap::new(), total_samples: 0 }
    }

    /// Record a traffic sample.
    pub fn record(&mut self, sample: TrafficSample) {
        let day_key = sample.timestamp.format("%Y-%m-%d").to_string();
        let month_key = sample.timestamp.format("%Y-%m").to_string();

        let app = self.apps.entry(sample.app_id.clone())
            .or_insert_with(|| AppTraffic {
                app_id: sample.app_id.clone(),
                total_sent: 0,
                total_received: 0,
                first_seen: sample.timestamp,
                last_seen: sample.timestamp,
                daily: HashMap::new(),
                monthly: HashMap::new(),
            });

        app.total_sent += sample.bytes_sent;
        app.total_received += sample.bytes_received;
        if sample.timestamp > app.last_seen { app.last_seen = sample.timestamp; }
        if sample.timestamp < app.first_seen { app.first_seen = sample.timestamp; }

        let daily = app.daily.entry(day_key).or_insert((0, 0));
        daily.0 += sample.bytes_sent;
        daily.1 += sample.bytes_received;

        let monthly = app.monthly.entry(month_key).or_insert((0, 0));
        monthly.0 += sample.bytes_sent;
        monthly.1 += sample.bytes_received;

        self.total_samples += 1;
    }

    /// Get traffic for a specific app.
    pub fn get(&self, app_id: &str) -> Option<&AppTraffic> {
        self.apps.get(app_id)
    }

    /// Top N apps by total bytes.
    pub fn top_apps(&self, n: usize) -> Vec<&AppTraffic> {
        let mut ranked: Vec<&AppTraffic> = self.apps.values().collect();
        ranked.sort_by(|a, b| b.total_bytes().cmp(&a.total_bytes()));
        ranked.truncate(n);
        ranked
    }

    /// Traffic today across all apps.
    pub fn total_today(&self) -> (u64, u64) {
        let mut sent = 0;
        let mut recv = 0;
        for app in self.apps.values() {
            let (s, r) = app.today_bytes();
            sent += s;
            recv += r;
        }
        (sent, recv)
    }

    /// Traffic this month across all apps.
    pub fn total_this_month(&self) -> (u64, u64) {
        let mut sent = 0;
        let mut recv = 0;
        for app in self.apps.values() {
            let (s, r) = app.this_month_bytes();
            sent += s;
            recv += r;
        }
        (sent, recv)
    }

    /// Apps that exceed a daily bandwidth threshold.
    pub fn daily_over(&self, threshold_bytes: u64) -> Vec<&AppTraffic> {
        self.apps.values()
            .filter(|a| {
                let (s, r) = a.today_bytes();
                s + r > threshold_bytes
            })
            .collect()
    }

    /// Apps that exceed a monthly bandwidth threshold.
    pub fn monthly_over(&self, threshold_bytes: u64) -> Vec<&AppTraffic> {
        self.apps.values()
            .filter(|a| {
                let (s, r) = a.this_month_bytes();
                s + r > threshold_bytes
            })
            .collect()
    }

    /// Format bytes in human-readable form.
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;
        const TB: u64 = 1024 * GB;
        if bytes >= TB { format!("{:.2} TB", bytes as f64 / TB as f64) }
        else if bytes >= GB { format!("{:.2} GB", bytes as f64 / GB as f64) }
        else if bytes >= MB { format!("{:.2} MB", bytes as f64 / MB as f64) }
        else if bytes >= KB { format!("{:.2} KB", bytes as f64 / KB as f64) }
        else { format!("{} B", bytes) }
    }

    pub fn app_count(&self) -> usize { self.apps.len() }
    pub fn total_samples(&self) -> u64 { self.total_samples }
}

impl Default for TrafficMeter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(app: &str, sent: u64, recv: u64) -> TrafficSample {
        TrafficSample {
            app_id: app.into(),
            timestamp: Utc::now(),
            bytes_sent: sent,
            bytes_received: recv,
            interface: "wlan0".into(),
        }
    }

    #[test]
    fn test_record_basic() {
        let mut m = TrafficMeter::new();
        m.record(sample("firefox", 100, 200));
        let t = m.get("firefox").unwrap();
        assert_eq!(t.total_sent, 100);
        assert_eq!(t.total_received, 200);
    }

    #[test]
    fn test_multiple_samples() {
        let mut m = TrafficMeter::new();
        m.record(sample("firefox", 100, 200));
        m.record(sample("firefox", 50, 75));
        let t = m.get("firefox").unwrap();
        assert_eq!(t.total_sent, 150);
        assert_eq!(t.total_received, 275);
    }

    #[test]
    fn test_top_apps() {
        let mut m = TrafficMeter::new();
        m.record(sample("heavy", 1000, 1000));
        m.record(sample("light", 10, 10));
        let top = m.top_apps(2);
        assert_eq!(top[0].app_id, "heavy");
    }

    #[test]
    fn test_today_total() {
        let mut m = TrafficMeter::new();
        m.record(sample("a", 100, 50));
        m.record(sample("b", 200, 100));
        let (sent, recv) = m.total_today();
        assert_eq!(sent, 300);
        assert_eq!(recv, 150);
    }

    #[test]
    fn test_daily_over_threshold() {
        let mut m = TrafficMeter::new();
        m.record(sample("heavy", 10_000_000, 0));
        m.record(sample("light", 100, 100));
        assert_eq!(m.daily_over(1_000_000).len(), 1);
    }

    #[test]
    fn test_monthly_over_threshold() {
        let mut m = TrafficMeter::new();
        m.record(sample("heavy", 100_000_000, 0));
        assert_eq!(m.monthly_over(10_000_000).len(), 1);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(TrafficMeter::format_bytes(500), "500 B");
        assert_eq!(TrafficMeter::format_bytes(2048), "2.00 KB");
        assert!(TrafficMeter::format_bytes(5_000_000).ends_with("MB"));
        assert!(TrafficMeter::format_bytes(5_000_000_000).ends_with("GB"));
    }

    #[test]
    fn test_today_bytes_per_app() {
        let mut m = TrafficMeter::new();
        m.record(sample("a", 100, 50));
        let (s, r) = m.get("a").unwrap().today_bytes();
        assert_eq!(s, 100);
        assert_eq!(r, 50);
    }

    #[test]
    fn test_total_samples_count() {
        let mut m = TrafficMeter::new();
        m.record(sample("a", 10, 10));
        m.record(sample("b", 10, 10));
        assert_eq!(m.total_samples(), 2);
    }

    #[test]
    fn test_total_bytes() {
        let mut m = TrafficMeter::new();
        m.record(sample("a", 100, 200));
        assert_eq!(m.get("a").unwrap().total_bytes(), 300);
    }
}
