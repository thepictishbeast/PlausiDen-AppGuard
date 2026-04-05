//! Data access policy — defines what apps are allowed to access.

use crate::permissions::Permission;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy defining what an app is allowed to access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPolicy {
    pub app_id: String,
    pub allowed_permissions: Vec<Permission>,
    pub denied_permissions: Vec<Permission>,
    pub max_background_minutes: u32,
    pub network_allowed: bool,
    pub can_autostart: bool,
}

/// Policy engine — evaluates access requests against policies.
pub struct PolicyEngine {
    policies: HashMap<String, AppPolicy>,
    default_deny: bool,
}

impl PolicyEngine {
    pub fn new(default_deny: bool) -> Self {
        Self { policies: HashMap::new(), default_deny }
    }

    pub fn add_policy(&mut self, policy: AppPolicy) {
        self.policies.insert(policy.app_id.clone(), policy);
    }

    pub fn check_permission(&self, app_id: &str, permission: &Permission) -> PolicyDecision {
        if let Some(policy) = self.policies.get(app_id) {
            if policy.denied_permissions.contains(permission) { return PolicyDecision::Denied("explicitly denied".into()); }
            if policy.allowed_permissions.contains(permission) { return PolicyDecision::Allowed; }
        }
        if self.default_deny { PolicyDecision::Denied("default deny".into()) } else { PolicyDecision::Allowed }
    }

    pub fn check_network(&self, app_id: &str) -> PolicyDecision {
        if let Some(policy) = self.policies.get(app_id) {
            if policy.network_allowed { PolicyDecision::Allowed } else { PolicyDecision::Denied("network blocked by policy".into()) }
        } else if self.default_deny { PolicyDecision::Denied("default deny".into()) } else { PolicyDecision::Allowed }
    }

    pub fn policy_count(&self) -> usize { self.policies.len() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision { Allowed, Denied(String) }

impl Default for PolicyEngine { fn default() -> Self { Self::new(false) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explicit_allow() {
        let mut engine = PolicyEngine::new(true);
        engine.add_policy(AppPolicy { app_id: "com.test".into(), allowed_permissions: vec![Permission::Camera], denied_permissions: vec![], max_background_minutes: 10, network_allowed: true, can_autostart: false });
        assert_eq!(engine.check_permission("com.test", &Permission::Camera), PolicyDecision::Allowed);
    }

    #[test]
    fn test_explicit_deny() {
        let mut engine = PolicyEngine::new(false);
        engine.add_policy(AppPolicy { app_id: "com.spy".into(), allowed_permissions: vec![], denied_permissions: vec![Permission::Microphone], max_background_minutes: 0, network_allowed: false, can_autostart: false });
        assert!(matches!(engine.check_permission("com.spy", &Permission::Microphone), PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_default_deny() {
        let engine = PolicyEngine::new(true);
        assert!(matches!(engine.check_permission("unknown", &Permission::Location), PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_default_allow() {
        let engine = PolicyEngine::new(false);
        assert_eq!(engine.check_permission("unknown", &Permission::Storage), PolicyDecision::Allowed);
    }

    #[test]
    fn test_network_policy() {
        let mut engine = PolicyEngine::new(true);
        engine.add_policy(AppPolicy { app_id: "browser".into(), allowed_permissions: vec![], denied_permissions: vec![], max_background_minutes: 0, network_allowed: true, can_autostart: false });
        assert_eq!(engine.check_network("browser"), PolicyDecision::Allowed);
        assert!(matches!(engine.check_network("unknown"), PolicyDecision::Denied(_)));
    }
}
