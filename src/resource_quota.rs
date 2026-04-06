//! Resource quota — per-app CPU, memory, I/O, and network caps.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resource quota for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    pub app_id: String,
    pub max_cpu_percent: Option<f64>,
    pub max_memory_mb: Option<u64>,
    pub max_disk_read_mbps: Option<f64>,
    pub max_disk_write_mbps: Option<f64>,
    pub max_network_kbps: Option<u64>,
    pub max_open_files: Option<u32>,
    pub max_threads: Option<u32>,
    pub enforcement: EnforcementMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementMode {
    Monitor,  // only track violations
    Throttle, // slow down the process
    Kill,     // terminate if exceeded
}

/// A usage sample for an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSample {
    pub app_id: String,
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_read_mbps: f64,
    pub disk_write_mbps: f64,
    pub network_kbps: u64,
    pub open_files: u32,
    pub threads: u32,
}

/// A quota violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaViolation {
    pub app_id: String,
    pub resource: Resource,
    pub limit: f64,
    pub actual: f64,
    pub timestamp: DateTime<Utc>,
    pub action_taken: EnforcementMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    Cpu,
    Memory,
    DiskRead,
    DiskWrite,
    Network,
    OpenFiles,
    Threads,
}

/// Resource quota manager.
pub struct ResourceQuotaManager {
    quotas: HashMap<String, Quota>,
    violations: Vec<QuotaViolation>,
    history_limit: usize,
}

impl ResourceQuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: HashMap::new(),
            violations: Vec::new(),
            history_limit: 5000,
        }
    }

    /// Set a quota for an app.
    pub fn set_quota(&mut self, quota: Quota) {
        self.quotas.insert(quota.app_id.clone(), quota);
    }

    /// Remove a quota.
    pub fn remove_quota(&mut self, app_id: &str) -> bool {
        self.quotas.remove(app_id).is_some()
    }

    /// Get quota for an app.
    pub fn get_quota(&self, app_id: &str) -> Option<&Quota> {
        self.quotas.get(app_id)
    }

    /// Check a usage sample against the quota and record violations.
    pub fn check(&mut self, sample: &UsageSample) -> Vec<QuotaViolation> {
        let quota = match self.quotas.get(&sample.app_id) {
            Some(q) => q.clone(),
            None => return Vec::new(),
        };

        let mut violations = Vec::new();
        let mut push_violation = |resource: Resource, limit: f64, actual: f64| {
            violations.push(QuotaViolation {
                app_id: sample.app_id.clone(),
                resource,
                limit,
                actual,
                timestamp: sample.timestamp,
                action_taken: quota.enforcement.clone(),
            });
        };

        if let Some(max) = quota.max_cpu_percent {
            if sample.cpu_percent > max {
                push_violation(Resource::Cpu, max, sample.cpu_percent);
            }
        }
        if let Some(max) = quota.max_memory_mb {
            if sample.memory_mb > max {
                push_violation(Resource::Memory, max as f64, sample.memory_mb as f64);
            }
        }
        if let Some(max) = quota.max_disk_read_mbps {
            if sample.disk_read_mbps > max {
                push_violation(Resource::DiskRead, max, sample.disk_read_mbps);
            }
        }
        if let Some(max) = quota.max_disk_write_mbps {
            if sample.disk_write_mbps > max {
                push_violation(Resource::DiskWrite, max, sample.disk_write_mbps);
            }
        }
        if let Some(max) = quota.max_network_kbps {
            if sample.network_kbps > max {
                push_violation(Resource::Network, max as f64, sample.network_kbps as f64);
            }
        }
        if let Some(max) = quota.max_open_files {
            if sample.open_files > max {
                push_violation(Resource::OpenFiles, max as f64, sample.open_files as f64);
            }
        }
        if let Some(max) = quota.max_threads {
            if sample.threads > max {
                push_violation(Resource::Threads, max as f64, sample.threads as f64);
            }
        }

        self.violations.extend(violations.clone());
        if self.violations.len() > self.history_limit {
            let excess = self.violations.len() - self.history_limit;
            self.violations.drain(0..excess);
        }

        violations
    }

    /// Violations for a specific app.
    pub fn violations_for(&self, app_id: &str) -> Vec<&QuotaViolation> {
        self.violations.iter().filter(|v| v.app_id == app_id).collect()
    }

    /// Violations of a specific resource type.
    pub fn violations_by_resource(&self, resource: &Resource) -> Vec<&QuotaViolation> {
        self.violations.iter().filter(|v| &v.resource == resource).collect()
    }

    /// Top violators.
    pub fn top_violators(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violations {
            *counts.entry(v.app_id.clone()).or_insert(0) += 1;
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    /// Apps with any quota set.
    pub fn quota_count(&self) -> usize {
        self.quotas.len()
    }

    /// Total violation count.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

impl Default for ResourceQuotaManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(app: &str, cpu: f64, mem: u64) -> UsageSample {
        UsageSample {
            app_id: app.into(),
            timestamp: Utc::now(),
            cpu_percent: cpu,
            memory_mb: mem,
            disk_read_mbps: 0.0,
            disk_write_mbps: 0.0,
            network_kbps: 0,
            open_files: 0,
            threads: 0,
        }
    }

    fn quota(app: &str, cpu: f64, mem: u64) -> Quota {
        Quota {
            app_id: app.into(),
            max_cpu_percent: Some(cpu),
            max_memory_mb: Some(mem),
            max_disk_read_mbps: None,
            max_disk_write_mbps: None,
            max_network_kbps: None,
            max_open_files: None,
            max_threads: None,
            enforcement: EnforcementMode::Monitor,
        }
    }

    #[test]
    fn test_no_violation_under_limit() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 80.0, 1000));
        let v = m.check(&sample("app", 50.0, 500));
        assert!(v.is_empty());
    }

    #[test]
    fn test_cpu_violation() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 50.0, 1000));
        let v = m.check(&sample("app", 80.0, 500));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].resource, Resource::Cpu);
    }

    #[test]
    fn test_memory_violation() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 100.0, 500));
        let v = m.check(&sample("app", 50.0, 1000));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].resource, Resource::Memory);
    }

    #[test]
    fn test_no_quota_no_check() {
        let mut m = ResourceQuotaManager::new();
        let v = m.check(&sample("untracked", 99.0, 99999));
        assert!(v.is_empty());
    }

    #[test]
    fn test_multiple_violations() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 50.0, 500));
        let v = m.check(&sample("app", 80.0, 1000));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_violations_for_app() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("a", 50.0, 500));
        m.set_quota(quota("b", 50.0, 500));
        m.check(&sample("a", 80.0, 500));
        m.check(&sample("b", 80.0, 500));
        assert_eq!(m.violations_for("a").len(), 1);
    }

    #[test]
    fn test_top_violators() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("heavy", 10.0, 100));
        m.set_quota(quota("light", 10.0, 100));
        for _ in 0..5 { m.check(&sample("heavy", 50.0, 50)); }
        m.check(&sample("light", 50.0, 50));
        let top = m.top_violators(2);
        assert_eq!(top[0].0, "heavy");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_remove_quota() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 50.0, 500));
        assert!(m.remove_quota("app"));
        assert_eq!(m.quota_count(), 0);
    }

    #[test]
    fn test_violations_by_resource() {
        let mut m = ResourceQuotaManager::new();
        m.set_quota(quota("app", 50.0, 500));
        m.check(&sample("app", 80.0, 1000));
        assert_eq!(m.violations_by_resource(&Resource::Cpu).len(), 1);
        assert_eq!(m.violations_by_resource(&Resource::Memory).len(), 1);
    }
}
