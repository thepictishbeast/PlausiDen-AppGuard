//! Permission audit — full audit of app permission grants and usage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Audit record for an app permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub app_id: String,
    pub permission: String,
    pub granted: bool,
    pub granted_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub use_count: u64,
    pub justification: Option<String>,
}

/// Audit report for all permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub total_apps: usize,
    pub total_permissions: usize,
    pub granted_count: usize,
    pub unused_grants: Vec<AuditRecord>,
    pub overprivileged_apps: Vec<String>,
    pub critical_grants: Vec<AuditRecord>,
}

/// Permission audit engine.
pub struct PermissionAuditor {
    records: HashMap<String, Vec<AuditRecord>>,
    /// Permissions considered high-risk.
    critical_perms: Vec<&'static str>,
}

impl PermissionAuditor {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            critical_perms: vec![
                "camera", "microphone", "location", "contacts",
                "screen_capture", "keyboard_input", "accessibility",
                "all_files_access", "device_admin", "bluetooth_scan",
            ],
        }
    }

    /// Record a permission grant.
    pub fn record_grant(&mut self, app_id: &str, permission: &str, justification: Option<String>) {
        let record = AuditRecord {
            app_id: app_id.into(),
            permission: permission.into(),
            granted: true,
            granted_at: Some(Utc::now()),
            last_used: None,
            use_count: 0,
            justification,
        };
        self.records.entry(app_id.into()).or_default().push(record);
    }

    /// Record a permission use.
    pub fn record_use(&mut self, app_id: &str, permission: &str) {
        if let Some(records) = self.records.get_mut(app_id) {
            for r in records.iter_mut() {
                if r.permission == permission && r.granted {
                    r.last_used = Some(Utc::now());
                    r.use_count += 1;
                    return;
                }
            }
        }
    }

    /// Revoke a permission.
    pub fn revoke(&mut self, app_id: &str, permission: &str) -> bool {
        if let Some(records) = self.records.get_mut(app_id) {
            for r in records.iter_mut() {
                if r.permission == permission {
                    r.granted = false;
                    return true;
                }
            }
        }
        false
    }

    /// Generate a full audit report.
    pub fn report(&self) -> AuditReport {
        let mut granted_count = 0;
        let mut unused_grants = Vec::new();
        let mut critical_grants = Vec::new();
        let mut total_perms = 0;
        let mut overprivileged = Vec::new();

        for (app_id, records) in &self.records {
            total_perms += records.len();
            let mut critical_for_app = 0;

            for record in records {
                if record.granted {
                    granted_count += 1;
                    if record.use_count == 0 {
                        unused_grants.push(record.clone());
                    }
                    if self.critical_perms.contains(&record.permission.as_str()) {
                        critical_grants.push(record.clone());
                        critical_for_app += 1;
                    }
                }
            }

            if critical_for_app >= 3 {
                overprivileged.push(app_id.clone());
            }
        }

        AuditReport {
            total_apps: self.records.len(),
            total_permissions: total_perms,
            granted_count,
            unused_grants,
            overprivileged_apps: overprivileged,
            critical_grants,
        }
    }

    /// Get records for a specific app.
    pub fn for_app(&self, app_id: &str) -> Option<&Vec<AuditRecord>> {
        self.records.get(app_id)
    }

    /// Apps with the most permissions.
    pub fn most_permissioned(&self, n: usize) -> Vec<(String, usize)> {
        let mut sorted: Vec<_> = self.records.iter()
            .map(|(id, recs)| (id.clone(), recs.iter().filter(|r| r.granted).count()))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    pub fn app_count(&self) -> usize { self.records.len() }
}

impl Default for PermissionAuditor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_grant() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("firefox", "network", None);
        assert_eq!(auditor.app_count(), 1);
    }

    #[test]
    fn test_record_use() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("firefox", "network", None);
        auditor.record_use("firefox", "network");
        let records = auditor.for_app("firefox").unwrap();
        assert_eq!(records[0].use_count, 1);
        assert!(records[0].last_used.is_some());
    }

    #[test]
    fn test_unused_grants() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("app1", "camera", None);
        auditor.record_grant("app2", "network", None);
        auditor.record_use("app2", "network");
        let report = auditor.report();
        assert_eq!(report.unused_grants.len(), 1);
    }

    #[test]
    fn test_critical_grants() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("spy", "camera", None);
        auditor.record_grant("spy", "microphone", None);
        let report = auditor.report();
        assert_eq!(report.critical_grants.len(), 2);
    }

    #[test]
    fn test_overprivileged() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("greedy", "camera", None);
        auditor.record_grant("greedy", "microphone", None);
        auditor.record_grant("greedy", "location", None);
        let report = auditor.report();
        assert!(report.overprivileged_apps.contains(&"greedy".to_string()));
    }

    #[test]
    fn test_revoke() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("app", "camera", None);
        assert!(auditor.revoke("app", "camera"));
        let records = auditor.for_app("app").unwrap();
        assert!(!records[0].granted);
    }

    #[test]
    fn test_most_permissioned() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("a", "p1", None);
        auditor.record_grant("a", "p2", None);
        auditor.record_grant("b", "p1", None);
        let top = auditor.most_permissioned(1);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_report_counts() {
        let mut auditor = PermissionAuditor::new();
        auditor.record_grant("a", "p1", None);
        auditor.record_grant("a", "p2", None);
        auditor.record_grant("b", "p1", None);
        let report = auditor.report();
        assert_eq!(report.total_apps, 2);
        assert_eq!(report.granted_count, 3);
    }
}
