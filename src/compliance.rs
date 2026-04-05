//! Compliance checker — verifies apps meet privacy/security policies.

use crate::permissions::Permission;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub name: String,
    pub description: String,
    pub severity: ComplianceSeverity,
    pub check: ComplianceCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ComplianceSeverity { Info, Warning, Violation, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceCheck {
    NoBackgroundCamera,
    NoBackgroundMicrophone,
    NoBackgroundLocation,
    MaxPermissions(usize),
    RequireNetworkPolicy,
    NoAutostartWithoutApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub app_id: String,
    pub rule_name: String,
    pub severity: ComplianceSeverity,
    pub details: String,
}

pub struct ComplianceChecker {
    rules: Vec<ComplianceRule>,
}

impl ComplianceChecker {
    pub fn new() -> Self { Self { rules: default_rules() } }

    pub fn check_app(&self, app_id: &str, permissions: &[Permission], has_bg_access: bool, has_autostart: bool) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();
        for rule in &self.rules {
            match &rule.check {
                ComplianceCheck::NoBackgroundCamera => {
                    if has_bg_access && permissions.contains(&Permission::Camera) {
                        violations.push(ComplianceViolation { app_id: app_id.into(), rule_name: rule.name.clone(), severity: rule.severity, details: "Camera used in background".into() });
                    }
                }
                ComplianceCheck::NoBackgroundMicrophone => {
                    if has_bg_access && permissions.contains(&Permission::Microphone) {
                        violations.push(ComplianceViolation { app_id: app_id.into(), rule_name: rule.name.clone(), severity: rule.severity, details: "Microphone used in background".into() });
                    }
                }
                ComplianceCheck::NoBackgroundLocation => {
                    if has_bg_access && permissions.contains(&Permission::Location) {
                        violations.push(ComplianceViolation { app_id: app_id.into(), rule_name: rule.name.clone(), severity: rule.severity, details: "Location accessed in background".into() });
                    }
                }
                ComplianceCheck::MaxPermissions(max) => {
                    if permissions.len() > *max {
                        violations.push(ComplianceViolation { app_id: app_id.into(), rule_name: rule.name.clone(), severity: rule.severity, details: format!("{} permissions (max: {max})", permissions.len()) });
                    }
                }
                ComplianceCheck::NoAutostartWithoutApproval => {
                    if has_autostart {
                        violations.push(ComplianceViolation { app_id: app_id.into(), rule_name: rule.name.clone(), severity: rule.severity, details: "Autostart without explicit approval".into() });
                    }
                }
                _ => {}
            }
        }
        violations
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

impl Default for ComplianceChecker { fn default() -> Self { Self::new() } }

fn default_rules() -> Vec<ComplianceRule> {
    vec![
        ComplianceRule { name: "no-bg-camera".into(), description: "No background camera access".into(), severity: ComplianceSeverity::Critical, check: ComplianceCheck::NoBackgroundCamera },
        ComplianceRule { name: "no-bg-mic".into(), description: "No background microphone access".into(), severity: ComplianceSeverity::Critical, check: ComplianceCheck::NoBackgroundMicrophone },
        ComplianceRule { name: "no-bg-location".into(), description: "No background location access".into(), severity: ComplianceSeverity::Violation, check: ComplianceCheck::NoBackgroundLocation },
        ComplianceRule { name: "max-permissions".into(), description: "Max 10 permissions per app".into(), severity: ComplianceSeverity::Warning, check: ComplianceCheck::MaxPermissions(10) },
        ComplianceRule { name: "no-unapproved-autostart".into(), description: "No autostart without approval".into(), severity: ComplianceSeverity::Warning, check: ComplianceCheck::NoAutostartWithoutApproval },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bg_camera_violation() {
        let checker = ComplianceChecker::new();
        let v = checker.check_app("spy", &[Permission::Camera], true, false);
        assert!(!v.is_empty());
        assert_eq!(v[0].severity, ComplianceSeverity::Critical);
    }

    #[test]
    fn test_clean_app() {
        let checker = ComplianceChecker::new();
        let v = checker.check_app("safe", &[Permission::Storage], false, false);
        assert!(v.is_empty());
    }

    #[test]
    fn test_too_many_permissions() {
        let checker = ComplianceChecker::new();
        let perms: Vec<Permission> = vec![Permission::Camera, Permission::Microphone, Permission::Location, Permission::Contacts, Permission::Calendar, Permission::Storage, Permission::Phone, Permission::Sms, Permission::Notifications, Permission::BackgroundActivity, Permission::NetworkAccess];
        let v = checker.check_app("greedy", &perms, false, false);
        assert!(v.iter().any(|x| x.rule_name == "max-permissions"));
    }

    #[test]
    fn test_autostart_violation() {
        let checker = ComplianceChecker::new();
        let v = checker.check_app("startup", &[], false, true);
        assert!(!v.is_empty());
    }
}
