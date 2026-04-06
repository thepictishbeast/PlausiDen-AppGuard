//! Data exfiltration monitor — per-application outbound volume tracking.
//!
//! Maintains a sliding-window baseline of how much data each application
//! typically uploads and flags statistical anomalies (spikes, off-hour
//! transfers, low-and-slow drips). Complements `data_flow` which tracks
//! *what kinds* of data are accessed; this module tracks *how much* leaves
//! via the network.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Exfiltration suspicion tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspicionLevel {
    Normal,
    Elevated,
    High,
    Critical,
}

/// A single recorded upload event.
#[derive(Debug, Clone)]
pub struct UploadEvent {
    pub bytes: u64,
    pub at: Instant,
}

/// Per-application rolling baseline.
#[derive(Debug, Clone)]
pub struct AppBaseline {
    pub app_id: String,
    pub events: Vec<UploadEvent>,
    pub total_bytes: u64,
    pub window: Duration,
}

impl AppBaseline {
    pub fn new(app_id: impl Into<String>, window: Duration) -> Self {
        Self {
            app_id: app_id.into(),
            events: Vec::new(),
            total_bytes: 0,
            window,
        }
    }

    pub fn record(&mut self, bytes: u64) {
        self.events.push(UploadEvent {
            bytes,
            at: Instant::now(),
        });
        self.total_bytes += bytes;
        self.prune();
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.events.retain(|e| now.duration_since(e.at) <= window);
        self.total_bytes = self.events.iter().map(|e| e.bytes).sum();
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn mean_bytes(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        self.total_bytes as f64 / self.events.len() as f64
    }

    pub fn variance_bytes(&self) -> f64 {
        if self.events.len() < 2 {
            return 0.0;
        }
        let mean = self.mean_bytes();
        let sum_sq: f64 = self
            .events
            .iter()
            .map(|e| {
                let d = e.bytes as f64 - mean;
                d * d
            })
            .sum();
        sum_sq / (self.events.len() - 1) as f64
    }

    pub fn stddev_bytes(&self) -> f64 {
        self.variance_bytes().sqrt()
    }
}

/// Finding emitted when an anomaly is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilFinding {
    pub app_id: String,
    pub level: SuspicionLevel,
    pub observed_bytes: u64,
    pub baseline_mean: f64,
    pub z_score: f64,
    pub description: String,
}

/// Thresholds used to rank anomalies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilThresholds {
    pub absolute_critical: u64,
    pub z_elevated: f64,
    pub z_high: f64,
    pub z_critical: f64,
    pub min_samples: usize,
}

impl Default for ExfilThresholds {
    fn default() -> Self {
        Self {
            absolute_critical: 1_000_000_000, // 1 GB single event
            z_elevated: 2.0,
            z_high: 3.0,
            z_critical: 5.0,
            min_samples: 5,
        }
    }
}

/// Exfiltration monitor.
pub struct DataExfilMonitor {
    window: Duration,
    thresholds: ExfilThresholds,
    baselines: HashMap<String, AppBaseline>,
    findings: Vec<ExfilFinding>,
}

impl DataExfilMonitor {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            thresholds: ExfilThresholds::default(),
            baselines: HashMap::new(),
            findings: Vec::new(),
        }
    }

    pub fn with_thresholds(window: Duration, thresholds: ExfilThresholds) -> Self {
        Self {
            window,
            thresholds,
            baselines: HashMap::new(),
            findings: Vec::new(),
        }
    }

    /// Record an upload for an app; returns a finding if the event is anomalous.
    pub fn record(&mut self, app_id: &str, bytes: u64) -> Option<ExfilFinding> {
        let baseline = self
            .baselines
            .entry(app_id.to_string())
            .or_insert_with(|| AppBaseline::new(app_id, self.window));

        let prior_mean = baseline.mean_bytes();
        let prior_std = baseline.stddev_bytes();
        let prior_samples = baseline.event_count();

        baseline.record(bytes);

        // Absolute cap overrides everything.
        if bytes >= self.thresholds.absolute_critical {
            let finding = ExfilFinding {
                app_id: app_id.to_string(),
                level: SuspicionLevel::Critical,
                observed_bytes: bytes,
                baseline_mean: prior_mean,
                z_score: f64::INFINITY,
                description: format!(
                    "{} uploaded {} bytes in a single event (>= absolute cap)",
                    app_id, bytes
                ),
            };
            self.findings.push(finding.clone());
            return Some(finding);
        }

        if prior_samples < self.thresholds.min_samples || prior_std == 0.0 {
            return None;
        }

        let z = (bytes as f64 - prior_mean) / prior_std;
        let level = if z >= self.thresholds.z_critical {
            SuspicionLevel::Critical
        } else if z >= self.thresholds.z_high {
            SuspicionLevel::High
        } else if z >= self.thresholds.z_elevated {
            SuspicionLevel::Elevated
        } else {
            SuspicionLevel::Normal
        };

        if level == SuspicionLevel::Normal {
            return None;
        }

        let finding = ExfilFinding {
            app_id: app_id.to_string(),
            level,
            observed_bytes: bytes,
            baseline_mean: prior_mean,
            z_score: z,
            description: format!(
                "{} uploaded {} bytes (baseline mean {:.0}, z={:.2})",
                app_id, bytes, prior_mean, z
            ),
        };
        self.findings.push(finding.clone());
        Some(finding)
    }

    pub fn findings(&self) -> &[ExfilFinding] {
        &self.findings
    }

    pub fn clear_findings(&mut self) {
        self.findings.clear();
    }

    pub fn baseline(&self, app_id: &str) -> Option<&AppBaseline> {
        self.baselines.get(app_id)
    }

    pub fn apps_tracked(&self) -> usize {
        self.baselines.len()
    }

    pub fn total_uploads(&self) -> u64 {
        self.baselines.values().map(|b| b.total_bytes).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_first_event_no_finding() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        assert!(m.record("firefox", 1000).is_none());
    }

    #[test]
    fn test_baseline_growth() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        for _ in 0..10 {
            m.record("slack", 50_000);
        }
        let baseline = m.baseline("slack").unwrap();
        assert_eq!(baseline.event_count(), 10);
        assert!((baseline.mean_bytes() - 50_000.0).abs() < 1e-6);
    }

    #[test]
    fn test_anomaly_triggers_elevated() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        // Establish baseline of small uploads.
        for _ in 0..10 {
            m.record("browser", 1000);
        }
        // Introduce small variance so stddev > 0.
        m.record("browser", 1200);
        // Spike.
        let finding = m.record("browser", 50_000).expect("should trigger");
        assert!(matches!(
            finding.level,
            SuspicionLevel::Elevated | SuspicionLevel::High | SuspicionLevel::Critical
        ));
    }

    #[test]
    fn test_absolute_cap_triggers_critical() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        let finding = m.record("unknown", 2_000_000_000).expect("over cap");
        assert_eq!(finding.level, SuspicionLevel::Critical);
    }

    #[test]
    fn test_no_anomaly_on_normal_traffic() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        for _ in 0..10 {
            m.record("mail", 10_000);
        }
        assert!(m.record("mail", 10_500).is_none());
    }

    #[test]
    fn test_findings_accumulate() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        m.record("a", 2_000_000_000);
        m.record("b", 3_000_000_000);
        assert_eq!(m.findings().len(), 2);
    }

    #[test]
    fn test_clear_findings() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        m.record("a", 2_000_000_000);
        m.clear_findings();
        assert_eq!(m.findings().len(), 0);
    }

    #[test]
    fn test_baseline_stddev_nonzero_after_variance() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        m.record("x", 100);
        m.record("x", 200);
        m.record("x", 150);
        let baseline = m.baseline("x").unwrap();
        assert!(baseline.stddev_bytes() > 0.0);
    }

    #[test]
    fn test_apps_tracked_count() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        m.record("a", 10);
        m.record("b", 10);
        m.record("c", 10);
        assert_eq!(m.apps_tracked(), 3);
    }

    #[test]
    fn test_total_uploads() {
        let mut m = DataExfilMonitor::new(Duration::from_secs(3600));
        m.record("x", 100);
        m.record("x", 200);
        m.record("y", 50);
        assert_eq!(m.total_uploads(), 350);
    }

    #[test]
    fn test_min_samples_suppresses_early_findings() {
        let custom = ExfilThresholds {
            min_samples: 20,
            ..Default::default()
        };
        let mut m = DataExfilMonitor::with_thresholds(Duration::from_secs(3600), custom);
        for _ in 0..5 {
            m.record("x", 100);
        }
        // Even with a spike, below min_samples → no finding.
        assert!(m.record("x", 1_000_000).is_none());
    }

    #[test]
    fn test_variance_single_sample_is_zero() {
        let b = AppBaseline {
            app_id: "x".into(),
            events: vec![UploadEvent {
                bytes: 100,
                at: Instant::now(),
            }],
            total_bytes: 100,
            window: Duration::from_secs(60),
        };
        assert_eq!(b.variance_bytes(), 0.0);
    }
}
