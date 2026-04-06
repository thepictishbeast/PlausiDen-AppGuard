//! Policy engine — declarative app behavior policies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A behavior policy for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPolicy {
    pub app_id: String,
    pub allow_network: bool,
    pub allowed_domains: Vec<String>,
    pub allow_filesystem: bool,
    pub allowed_paths: Vec<String>,
    pub allow_ipc: bool,
    pub allow_camera: bool,
    pub allow_microphone: bool,
    pub allow_location: bool,
    pub allow_clipboard: bool,
    pub allow_notifications: bool,
    pub allow_autostart: bool,
}

impl AppPolicy {
    pub fn permissive(app_id: &str) -> Self {
        Self {
            app_id: app_id.into(),
            allow_network: true,
            allowed_domains: Vec::new(),
            allow_filesystem: true,
            allowed_paths: Vec::new(),
            allow_ipc: true,
            allow_camera: true,
            allow_microphone: true,
            allow_location: true,
            allow_clipboard: true,
            allow_notifications: true,
            allow_autostart: true,
        }
    }

    pub fn restrictive(app_id: &str) -> Self {
        Self {
            app_id: app_id.into(),
            allow_network: false,
            allowed_domains: Vec::new(),
            allow_filesystem: false,
            allowed_paths: Vec::new(),
            allow_ipc: false,
            allow_camera: false,
            allow_microphone: false,
            allow_location: false,
            allow_clipboard: false,
            allow_notifications: false,
            allow_autostart: false,
        }
    }

    /// Check if a domain is allowed for network access.
    pub fn check_domain(&self, domain: &str) -> bool {
        if !self.allow_network { return false; }
        if self.allowed_domains.is_empty() { return true; }
        self.allowed_domains.iter().any(|d| {
            if let Some(suffix) = d.strip_prefix("*.") {
                domain == suffix || domain.ends_with(&format!(".{suffix}"))
            } else {
                domain == d
            }
        })
    }

    /// Check if a path is allowed for filesystem access.
    pub fn check_path(&self, path: &str) -> bool {
        if !self.allow_filesystem { return false; }
        if self.allowed_paths.is_empty() { return true; }
        self.allowed_paths.iter().any(|p| path.starts_with(p))
    }
}

/// A policy violation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub app_id: String,
    pub permission: String,
    pub resource: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Policy enforcement engine.
pub struct PolicyEngine {
    policies: HashMap<String, AppPolicy>,
    violations: Vec<PolicyViolation>,
    /// Default policy for unknown apps.
    default_policy: AppPolicy,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            violations: Vec::new(),
            default_policy: AppPolicy::permissive("default"),
        }
    }

    /// Set a policy for an app.
    pub fn set_policy(&mut self, policy: AppPolicy) {
        self.policies.insert(policy.app_id.clone(), policy);
    }

    /// Get the policy for an app (or default).
    pub fn policy_for(&self, app_id: &str) -> &AppPolicy {
        self.policies.get(app_id).unwrap_or(&self.default_policy)
    }

    /// Check if an app can access a domain.
    pub fn check_network(&mut self, app_id: &str, domain: &str) -> bool {
        let allowed = self.policy_for(app_id).check_domain(domain);
        if !allowed {
            self.violations.push(PolicyViolation {
                app_id: app_id.into(),
                permission: "network".into(),
                resource: domain.into(),
                timestamp: chrono::Utc::now(),
            });
        }
        allowed
    }

    /// Check if an app can access a file path.
    pub fn check_path(&mut self, app_id: &str, path: &str) -> bool {
        let allowed = self.policy_for(app_id).check_path(path);
        if !allowed {
            self.violations.push(PolicyViolation {
                app_id: app_id.into(),
                permission: "filesystem".into(),
                resource: path.into(),
                timestamp: chrono::Utc::now(),
            });
        }
        allowed
    }

    /// Set a more restrictive default policy.
    pub fn set_default_restrictive(&mut self) {
        self.default_policy = AppPolicy::restrictive("default");
    }

    pub fn violation_count(&self) -> usize { self.violations.len() }
    pub fn policy_count(&self) -> usize { self.policies.len() }

    pub fn violations_for(&self, app_id: &str) -> Vec<&PolicyViolation> {
        self.violations.iter().filter(|v| v.app_id == app_id).collect()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permissive_allows_all() {
        let p = AppPolicy::permissive("app");
        assert!(p.check_domain("example.com"));
        assert!(p.check_path("/etc/passwd"));
    }

    #[test]
    fn test_restrictive_blocks_all() {
        let p = AppPolicy::restrictive("app");
        assert!(!p.check_domain("example.com"));
        assert!(!p.check_path("/etc/passwd"));
    }

    #[test]
    fn test_domain_whitelist() {
        let mut p = AppPolicy::permissive("app");
        p.allowed_domains = vec!["api.example.com".into(), "*.cdn.example.com".into()];
        assert!(p.check_domain("api.example.com"));
        assert!(p.check_domain("static.cdn.example.com"));
        assert!(!p.check_domain("evil.com"));
    }

    #[test]
    fn test_path_whitelist() {
        let mut p = AppPolicy::permissive("app");
        p.allowed_paths = vec!["/home/user/Documents".into()];
        assert!(p.check_path("/home/user/Documents/file.txt"));
        assert!(!p.check_path("/etc/shadow"));
    }

    #[test]
    fn test_policy_engine_set_get() {
        let mut engine = PolicyEngine::new();
        engine.set_policy(AppPolicy::restrictive("spy"));
        assert!(!engine.policy_for("spy").allow_network);
    }

    #[test]
    fn test_violation_recorded() {
        let mut engine = PolicyEngine::new();
        engine.set_policy(AppPolicy::restrictive("app"));
        assert!(!engine.check_network("app", "example.com"));
        assert_eq!(engine.violation_count(), 1);
    }

    #[test]
    fn test_violations_for_app() {
        let mut engine = PolicyEngine::new();
        engine.set_policy(AppPolicy::restrictive("a"));
        engine.set_policy(AppPolicy::restrictive("b"));
        engine.check_network("a", "x");
        engine.check_network("b", "y");
        engine.check_network("a", "z");
        assert_eq!(engine.violations_for("a").len(), 2);
        assert_eq!(engine.violations_for("b").len(), 1);
    }

    #[test]
    fn test_default_policy_used() {
        let mut engine = PolicyEngine::new();
        engine.set_default_restrictive();
        assert!(!engine.check_network("unknown", "example.com"));
    }
}
