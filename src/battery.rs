//! Battery impact tracking — which apps drain the most power.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryImpact {
    pub app_id: String,
    pub cpu_time_ms: u64,
    pub wake_locks: u32,
    pub network_bytes: u64,
    pub gps_usage_secs: u64,
    pub estimated_mah: f64,
}

impl BatteryImpact {
    pub fn drain_score(&self) -> f64 {
        let cpu = self.cpu_time_ms as f64 / 1000.0 * 0.3;
        let wake = self.wake_locks as f64 * 0.2;
        let net = (self.network_bytes as f64 / 1_000_000.0) * 0.2;
        let gps = self.gps_usage_secs as f64 * 0.3;
        (cpu + wake + net + gps).min(100.0)
    }
}

pub struct BatteryTracker {
    impacts: HashMap<String, BatteryImpact>,
}

impl BatteryTracker {
    pub fn new() -> Self { Self { impacts: HashMap::new() } }

    pub fn record_cpu(&mut self, app_id: &str, ms: u64) {
        self.impacts.entry(app_id.into()).or_insert(BatteryImpact { app_id: app_id.into(), cpu_time_ms: 0, wake_locks: 0, network_bytes: 0, gps_usage_secs: 0, estimated_mah: 0.0 }).cpu_time_ms += ms;
    }

    pub fn record_wake_lock(&mut self, app_id: &str) {
        self.impacts.entry(app_id.into()).or_insert(BatteryImpact { app_id: app_id.into(), cpu_time_ms: 0, wake_locks: 0, network_bytes: 0, gps_usage_secs: 0, estimated_mah: 0.0 }).wake_locks += 1;
    }

    pub fn top_drainers(&self, count: usize) -> Vec<&BatteryImpact> {
        let mut impacts: Vec<_> = self.impacts.values().collect();
        impacts.sort_by(|a, b| b.drain_score().partial_cmp(&a.drain_score()).unwrap_or(std::cmp::Ordering::Equal));
        impacts.truncate(count);
        impacts
    }

    pub fn app_count(&self) -> usize { self.impacts.len() }
}

impl Default for BatteryTracker { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drain_score() {
        let impact = BatteryImpact { app_id: "test".into(), cpu_time_ms: 10000, wake_locks: 5, network_bytes: 5_000_000, gps_usage_secs: 60, estimated_mah: 0.0 };
        assert!(impact.drain_score() > 0.0);
    }

    #[test]
    fn test_top_drainers() {
        let mut tracker = BatteryTracker::new();
        for _ in 0..100 { tracker.record_cpu("heavy", 100); }
        tracker.record_cpu("light", 10);
        let top = tracker.top_drainers(1);
        assert_eq!(top[0].app_id, "heavy");
    }

    #[test]
    fn test_wake_locks() {
        let mut tracker = BatteryTracker::new();
        for _ in 0..5 { tracker.record_wake_lock("app"); }
        assert_eq!(tracker.impacts.get("app").unwrap().wake_locks, 5);
    }
}
