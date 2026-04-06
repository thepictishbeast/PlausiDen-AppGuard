//! Alert system — notifications for permission violations and suspicious activity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity { Info, Warning, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub app_id: String,
    pub message: String,
    pub acknowledged: bool,
}

pub struct AlertManager {
    alerts: VecDeque<Alert>,
    max_alerts: usize,
}

impl AlertManager {
    pub fn new(max_alerts: usize) -> Self { Self { alerts: VecDeque::new(), max_alerts } }

    pub fn raise(&mut self, severity: AlertSeverity, app_id: &str, message: &str) {
        self.alerts.push_back(Alert { timestamp: Utc::now(), severity, app_id: app_id.into(), message: message.into(), acknowledged: false });
        while self.alerts.len() > self.max_alerts { self.alerts.pop_front(); }
    }

    pub fn acknowledge(&mut self, index: usize) { if let Some(a) = self.alerts.get_mut(index) { a.acknowledged = true; } }
    pub fn unacknowledged(&self) -> Vec<&Alert> { self.alerts.iter().filter(|a| !a.acknowledged).collect() }
    pub fn by_severity(&self, min: AlertSeverity) -> Vec<&Alert> { self.alerts.iter().filter(|a| a.severity >= min).collect() }
    pub fn by_app(&self, app_id: &str) -> Vec<&Alert> { self.alerts.iter().filter(|a| a.app_id == app_id).collect() }
    pub fn count(&self) -> usize { self.alerts.len() }
    pub fn clear(&mut self) { self.alerts.clear(); }
}

impl Default for AlertManager { fn default() -> Self { Self::new(500) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raise_and_query() {
        let mut mgr = AlertManager::new(100);
        mgr.raise(AlertSeverity::Warning, "spy", "background camera");
        mgr.raise(AlertSeverity::Info, "safe", "normal usage");
        assert_eq!(mgr.count(), 2);
        assert_eq!(mgr.by_severity(AlertSeverity::Warning).len(), 1);
    }

    #[test]
    fn test_acknowledge() {
        let mut mgr = AlertManager::new(100);
        mgr.raise(AlertSeverity::Critical, "app", "issue");
        assert_eq!(mgr.unacknowledged().len(), 1);
        mgr.acknowledge(0);
        assert_eq!(mgr.unacknowledged().len(), 0);
    }

    #[test]
    fn test_eviction() {
        let mut mgr = AlertManager::new(3);
        for i in 0..5 { mgr.raise(AlertSeverity::Info, &format!("app{i}"), "msg"); }
        assert_eq!(mgr.count(), 3);
    }
}
