//! Network audit — tracks which apps connect to which destinations.
//!
//! Complements permission auditing with actual network behavior analysis.
//! An app may have NetworkAccess permission but connecting to a known
//! malware C2 server is still suspicious.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A network connection made by an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConnection {
    pub app_id: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub dest_domain: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
}

/// Network behavior profile for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppNetworkProfile {
    pub app_id: String,
    /// All unique destinations this app has connected to.
    pub destinations: HashMap<String, u64>, // dest → connection count
    /// Total bytes sent by this app.
    pub total_bytes_sent: u64,
    /// Total bytes received.
    pub total_bytes_received: u64,
    /// Total connections made.
    pub total_connections: u64,
    /// Unique destination count.
    pub unique_destinations: usize,
}

/// Network auditor — builds profiles of app network behavior.
pub struct NetworkAuditor {
    connections: Vec<AppConnection>,
    /// Known-suspicious destinations.
    suspicious_destinations: Vec<String>,
}

impl NetworkAuditor {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            suspicious_destinations: vec![
                "malware-c2.example.com".into(), // LEAK-JUSTIFIED: RFC 2606 example.com is the right host for placeholder suspicious-destination entries
                "phishing.evil.com".into(),
                "cryptominer-pool.xyz".into(),
            ],
        }
    }

    /// Record a network connection.
    pub fn record(&mut self, conn: AppConnection) {
        self.connections.push(conn);
    }

    /// Build a network profile for an app.
    pub fn profile(&self, app_id: &str) -> AppNetworkProfile {
        let app_conns: Vec<_> = self.connections.iter()
            .filter(|c| c.app_id == app_id)
            .collect();

        let mut destinations: HashMap<String, u64> = HashMap::new();
        let mut total_sent = 0u64;
        let mut total_recv = 0u64;

        for conn in &app_conns {
            let dest = conn.dest_domain.as_deref().unwrap_or(&conn.dest_ip);
            *destinations.entry(dest.to_string()).or_default() += 1;
            total_sent += conn.bytes_sent;
            total_recv += conn.bytes_received;
        }

        let unique = destinations.len();

        AppNetworkProfile {
            app_id: app_id.to_string(),
            destinations,
            total_bytes_sent: total_sent,
            total_bytes_received: total_recv,
            total_connections: app_conns.len() as u64,
            unique_destinations: unique,
        }
    }

    /// Check if any app connections go to suspicious destinations.
    pub fn check_suspicious(&self, app_id: &str) -> Vec<&AppConnection> {
        self.connections.iter()
            .filter(|c| c.app_id == app_id)
            .filter(|c| {
                let dest = c.dest_domain.as_deref().unwrap_or(&c.dest_ip);
                self.suspicious_destinations.iter().any(|s| dest.contains(s))
            })
            .collect()
    }

    /// Apps with the most network activity.
    pub fn top_talkers(&self, count: usize) -> Vec<(String, u64)> {
        let mut by_app: HashMap<String, u64> = HashMap::new();
        for conn in &self.connections {
            *by_app.entry(conn.app_id.clone()).or_default() += conn.bytes_sent + conn.bytes_received;
        }
        let mut sorted: Vec<_> = by_app.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(count);
        sorted
    }

    /// Total connections recorded.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for NetworkAuditor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(app: &str, dest: &str, port: u16) -> AppConnection {
        AppConnection {
            app_id: app.into(), dest_ip: "1.2.3.4".into(), dest_port: port,
            dest_domain: Some(dest.into()), bytes_sent: 1000, bytes_received: 5000,
            timestamp: Utc::now(), protocol: "tcp".into(),
        }
    }

    #[test]
    fn test_record_and_profile() {
        let mut auditor = NetworkAuditor::new();
        auditor.record(make_conn("firefox", "google.com", 443));
        auditor.record(make_conn("firefox", "github.com", 443));
        auditor.record(make_conn("firefox", "google.com", 443));

        let profile = auditor.profile("firefox");
        assert_eq!(profile.total_connections, 3);
        assert_eq!(profile.unique_destinations, 2);
    }

    #[test]
    fn test_suspicious_detection() {
        let mut auditor = NetworkAuditor::new();
        auditor.record(make_conn("malware", "malware-c2.example.com", 443));
        auditor.record(make_conn("firefox", "google.com", 443));

        let suspicious = auditor.check_suspicious("malware");
        assert_eq!(suspicious.len(), 1);

        let clean = auditor.check_suspicious("firefox");
        assert!(clean.is_empty());
    }

    #[test]
    fn test_top_talkers() {
        let mut auditor = NetworkAuditor::new();
        for _ in 0..10 { auditor.record(make_conn("heavy", "cdn.com", 443)); }
        for _ in 0..2 { auditor.record(make_conn("light", "api.com", 443)); }

        let top = auditor.top_talkers(1);
        assert_eq!(top[0].0, "heavy");
    }

    #[test]
    fn test_empty_profile() {
        let auditor = NetworkAuditor::new();
        let profile = auditor.profile("nonexistent");
        assert_eq!(profile.total_connections, 0);
        assert_eq!(profile.unique_destinations, 0);
    }
}
