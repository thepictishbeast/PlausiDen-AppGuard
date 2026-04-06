//! Resource monitor — track per-app resource consumption.
//!
//! Monitors CPU, memory, disk I/O, and network I/O per application
//! to identify resource hogs and enforce limits.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resource usage snapshot for an application.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub network_sent_bytes: u64,
    pub network_recv_bytes: u64,
    pub open_files: u32,
    pub thread_count: u32,
}

/// Resource limits for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_cpu_percent: f64,
    pub max_memory_bytes: u64,
    pub max_disk_write_bytes_per_sec: u64,
    pub max_network_bytes_per_sec: u64,
    pub max_open_files: u32,
    pub max_threads: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: 80.0,
            max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
            max_disk_write_bytes_per_sec: 100 * 1024 * 1024, // 100 MB/s
            max_network_bytes_per_sec: 50 * 1024 * 1024, // 50 MB/s
            max_open_files: 1024,
            max_threads: 100,
        }
    }
}

/// A limit violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitViolation {
    pub app_id: String,
    pub resource: String,
    pub current: f64,
    pub limit: f64,
    pub timestamp: DateTime<Utc>,
}

/// Per-app resource tracker.
pub struct ResourceMonitor {
    usage: HashMap<String, ResourceUsage>,
    limits: HashMap<String, ResourceLimits>,
    default_limits: ResourceLimits,
    violations: Vec<LimitViolation>,
    max_violations: usize,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            usage: HashMap::new(),
            limits: HashMap::new(),
            default_limits: ResourceLimits::default(),
            violations: Vec::new(),
            max_violations: 500,
        }
    }

    /// Set limits for a specific app.
    pub fn set_limits(&mut self, app_id: &str, limits: ResourceLimits) {
        self.limits.insert(app_id.into(), limits);
    }

    /// Update resource usage for an app.
    pub fn update(&mut self, app_id: &str, usage: ResourceUsage) -> Vec<LimitViolation> {
        let limits = self.limits.get(app_id).unwrap_or(&self.default_limits);
        let mut violations = Vec::new();

        if usage.cpu_percent > limits.max_cpu_percent {
            violations.push(LimitViolation {
                app_id: app_id.into(),
                resource: "cpu".into(),
                current: usage.cpu_percent,
                limit: limits.max_cpu_percent,
                timestamp: Utc::now(),
            });
        }
        if usage.memory_bytes > limits.max_memory_bytes {
            violations.push(LimitViolation {
                app_id: app_id.into(),
                resource: "memory".into(),
                current: usage.memory_bytes as f64,
                limit: limits.max_memory_bytes as f64,
                timestamp: Utc::now(),
            });
        }
        if usage.open_files > limits.max_open_files {
            violations.push(LimitViolation {
                app_id: app_id.into(),
                resource: "open_files".into(),
                current: usage.open_files as f64,
                limit: limits.max_open_files as f64,
                timestamp: Utc::now(),
            });
        }
        if usage.thread_count > limits.max_threads {
            violations.push(LimitViolation {
                app_id: app_id.into(),
                resource: "threads".into(),
                current: usage.thread_count as f64,
                limit: limits.max_threads as f64,
                timestamp: Utc::now(),
            });
        }

        self.violations.extend(violations.clone());
        while self.violations.len() > self.max_violations {
            self.violations.remove(0);
        }

        self.usage.insert(app_id.into(), usage);
        violations
    }

    /// Get current usage for an app.
    pub fn get_usage(&self, app_id: &str) -> Option<&ResourceUsage> {
        self.usage.get(app_id)
    }

    /// Get top CPU consumers.
    pub fn top_cpu(&self, n: usize) -> Vec<(&str, f64)> {
        let mut sorted: Vec<_> = self.usage.iter()
            .map(|(id, u)| (id.as_str(), u.cpu_percent))
            .collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }

    /// Get top memory consumers.
    pub fn top_memory(&self, n: usize) -> Vec<(&str, u64)> {
        let mut sorted: Vec<_> = self.usage.iter()
            .map(|(id, u)| (id.as_str(), u.memory_bytes))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Total violations recorded.
    pub fn violation_count(&self) -> usize { self.violations.len() }
    /// Number of tracked apps.
    pub fn tracked_apps(&self) -> usize { self.usage.len() }
}

impl Default for ResourceMonitor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_usage_no_violations() {
        let mut mon = ResourceMonitor::new();
        let usage = ResourceUsage { cpu_percent: 30.0, memory_bytes: 500_000_000, ..Default::default() };
        let violations = mon.update("app", usage);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_cpu_violation() {
        let mut mon = ResourceMonitor::new();
        let usage = ResourceUsage { cpu_percent: 95.0, ..Default::default() };
        let violations = mon.update("app", usage);
        assert!(violations.iter().any(|v| v.resource == "cpu"));
    }

    #[test]
    fn test_memory_violation() {
        let mut mon = ResourceMonitor::new();
        let usage = ResourceUsage { memory_bytes: 3_000_000_000, ..Default::default() };
        let violations = mon.update("app", usage);
        assert!(violations.iter().any(|v| v.resource == "memory"));
    }

    #[test]
    fn test_custom_limits() {
        let mut mon = ResourceMonitor::new();
        mon.set_limits("strict_app", ResourceLimits { max_cpu_percent: 10.0, ..Default::default() });
        let usage = ResourceUsage { cpu_percent: 15.0, ..Default::default() };
        let violations = mon.update("strict_app", usage);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_top_cpu() {
        let mut mon = ResourceMonitor::new();
        mon.update("heavy", ResourceUsage { cpu_percent: 90.0, ..Default::default() });
        mon.update("light", ResourceUsage { cpu_percent: 5.0, ..Default::default() });
        let top = mon.top_cpu(1);
        assert_eq!(top[0].0, "heavy");
    }

    #[test]
    fn test_top_memory() {
        let mut mon = ResourceMonitor::new();
        mon.update("big", ResourceUsage { memory_bytes: 2_000_000_000, ..Default::default() });
        mon.update("small", ResourceUsage { memory_bytes: 100_000_000, ..Default::default() });
        let top = mon.top_memory(1);
        assert_eq!(top[0].0, "big");
    }

    #[test]
    fn test_thread_violation() {
        let mut mon = ResourceMonitor::new();
        let usage = ResourceUsage { thread_count: 200, ..Default::default() };
        let violations = mon.update("threaded", usage);
        assert!(violations.iter().any(|v| v.resource == "threads"));
    }

    #[test]
    fn test_tracked_apps() {
        let mut mon = ResourceMonitor::new();
        mon.update("a", ResourceUsage::default());
        mon.update("b", ResourceUsage::default());
        assert_eq!(mon.tracked_apps(), 2);
    }
}
