//! Permission auditing — tracks what permissions each app uses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// System permission categories.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    Camera,
    Microphone,
    Location,
    Contacts,
    Calendar,
    Storage,
    Phone,
    Sms,
    Notifications,
    BackgroundActivity,
    NetworkAccess,
    Bluetooth,
    Usb,
    Accessibility,
    DeviceAdmin,
    SystemAlert,
    InstallApps,
    /// Platform-specific permission not in the standard list.
    Custom(String),
}

/// Record of a permission being used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAccess {
    pub permission: Permission,
    pub app_id: String,
    pub accessed_at: DateTime<Utc>,
    /// Was the user actively using the app when it accessed this permission?
    pub foreground: bool,
}

/// Audit result for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAudit {
    pub app_id: String,
    pub granted_permissions: Vec<Permission>,
    pub used_permissions: Vec<Permission>,
    /// Permissions granted but never used (candidates for revocation).
    pub unused_permissions: Vec<Permission>,
    /// Permissions used in background (suspicious).
    pub background_accesses: Vec<PermissionAccess>,
    /// Risk score (0.0 to 1.0) based on permission profile.
    pub risk_score: f64,
}

/// Permission auditor.
pub struct PermissionAuditor {
    /// All recorded permission accesses.
    accesses: Vec<PermissionAccess>,
    /// Granted permissions per app.
    granted: HashMap<String, Vec<Permission>>,
}

impl PermissionAuditor {
    pub fn new() -> Self {
        Self {
            accesses: Vec::new(),
            granted: HashMap::new(),
        }
    }

    /// Register an app's granted permissions.
    pub fn register_app(&mut self, app_id: &str, permissions: Vec<Permission>) {
        self.granted.insert(app_id.to_string(), permissions);
    }

    /// Record a permission access event.
    pub fn record_access(&mut self, access: PermissionAccess) {
        self.accesses.push(access);
    }

    /// Audit a specific app.
    pub fn audit_app(&self, app_id: &str) -> PermissionAudit {
        let granted = self.granted.get(app_id).cloned().unwrap_or_default();

        let used: Vec<Permission> = self.accesses
            .iter()
            .filter(|a| a.app_id == app_id)
            .map(|a| a.permission.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let unused: Vec<Permission> = granted
            .iter()
            .filter(|p| !used.contains(p))
            .cloned()
            .collect();

        let background: Vec<PermissionAccess> = self.accesses
            .iter()
            .filter(|a| a.app_id == app_id && !a.foreground)
            .cloned()
            .collect();

        let risk_score = calculate_risk(&granted, &background);

        PermissionAudit {
            app_id: app_id.to_string(),
            granted_permissions: granted,
            used_permissions: used,
            unused_permissions: unused,
            background_accesses: background,
            risk_score,
        }
    }
}

impl Default for PermissionAuditor {
    fn default() -> Self { Self::new() }
}

/// Calculate risk score based on permission profile.
fn calculate_risk(granted: &[Permission], background_accesses: &[PermissionAccess]) -> f64 {
    let mut score = 0.0;

    // High-risk permissions
    for perm in granted {
        score += match perm {
            Permission::Camera => 0.15,
            Permission::Microphone => 0.15,
            Permission::Location => 0.12,
            Permission::Contacts => 0.1,
            Permission::DeviceAdmin => 0.2,
            Permission::Accessibility => 0.18,
            Permission::InstallApps => 0.15,
            Permission::Storage => 0.08,
            Permission::BackgroundActivity => 0.05,
            _ => 0.02,
        };
    }

    // Background access is especially suspicious
    score += background_accesses.len() as f64 * 0.05;

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_audit() {
        let mut auditor = PermissionAuditor::new();
        auditor.register_app("com.example", vec![
            Permission::Camera,
            Permission::Location,
            Permission::Storage,
        ]);

        // App only uses camera
        auditor.record_access(PermissionAccess {
            permission: Permission::Camera,
            app_id: "com.example".to_string(),
            accessed_at: Utc::now(),
            foreground: true,
        });

        let audit = auditor.audit_app("com.example");
        assert_eq!(audit.granted_permissions.len(), 3);
        assert_eq!(audit.used_permissions.len(), 1);
        assert_eq!(audit.unused_permissions.len(), 2); // Location + Storage unused
    }

    #[test]
    fn test_background_access_flagged() {
        let mut auditor = PermissionAuditor::new();
        auditor.register_app("com.spy", vec![Permission::Microphone]);

        auditor.record_access(PermissionAccess {
            permission: Permission::Microphone,
            app_id: "com.spy".to_string(),
            accessed_at: Utc::now(),
            foreground: false, // Background!
        });

        let audit = auditor.audit_app("com.spy");
        assert_eq!(audit.background_accesses.len(), 1);
        assert!(audit.risk_score > 0.1);
    }

    #[test]
    fn test_high_risk_permissions() {
        let mut auditor = PermissionAuditor::new();
        auditor.register_app("com.risky", vec![
            Permission::Camera,
            Permission::Microphone,
            Permission::Location,
            Permission::DeviceAdmin,
            Permission::Accessibility,
        ]);

        let audit = auditor.audit_app("com.risky");
        assert!(audit.risk_score > 0.5, "many dangerous permissions should score high: {}", audit.risk_score);
    }

    #[test]
    fn test_benign_app() {
        let mut auditor = PermissionAuditor::new();
        auditor.register_app("com.safe", vec![Permission::Notifications]);

        let audit = auditor.audit_app("com.safe");
        assert!(audit.risk_score < 0.1);
    }
}
