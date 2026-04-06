//! App sandboxing — restrict what apps can access using Linux namespaces,
//! seccomp, and Bubblewrap-style isolation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Isolation level for sandboxed applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// No isolation — app runs with full access.
    None,
    /// Path-based restrictions only.
    Basic,
    /// Network + path restrictions.
    Standard,
    /// Full isolation: separate mount/PID/network namespace.
    Strict,
    /// Maximum: Strict + seccomp + no IPC + read-only root.
    Paranoid,
}

/// Sandbox profile defining what an application can and cannot do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub app_id: String,
    pub isolation_level: IsolationLevel,
    pub allowed_paths: HashSet<PathBuf>,
    pub denied_paths: HashSet<PathBuf>,
    pub readonly_paths: HashSet<PathBuf>,
    pub allowed_network: bool,
    pub allowed_ports: HashSet<u16>,
    pub allowed_ipc: bool,
    pub max_memory_mb: u64,
    pub max_cpu_percent: u32,
    pub max_file_descriptors: u32,
    pub max_processes: u32,
    pub allow_dbus: bool,
    pub allow_x11: bool,
    pub allow_wayland: bool,
    pub allow_audio: bool,
    pub allow_gpu: bool,
    pub environment_whitelist: HashSet<String>,
}

impl SandboxProfile {
    /// Create a restrictive sandbox — blocks most access.
    pub fn restrictive(app_id: &str) -> Self {
        Self {
            app_id: app_id.into(),
            isolation_level: IsolationLevel::Strict,
            allowed_paths: HashSet::from([
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/share"),
                PathBuf::from("/lib"),
            ]),
            denied_paths: HashSet::from([
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/gshadow"),
                PathBuf::from("/root"),
                PathBuf::from("/home"),
                PathBuf::from("/boot"),
                PathBuf::from("/proc/kcore"),
            ]),
            readonly_paths: HashSet::from([
                PathBuf::from("/etc"),
                PathBuf::from("/usr"),
            ]),
            allowed_network: false,
            allowed_ports: HashSet::new(),
            allowed_ipc: false,
            max_memory_mb: 256,
            max_cpu_percent: 25,
            max_file_descriptors: 256,
            max_processes: 10,
            allow_dbus: false,
            allow_x11: false,
            allow_wayland: false,
            allow_audio: false,
            allow_gpu: false,
            environment_whitelist: HashSet::from([
                "PATH".into(), "LANG".into(), "HOME".into(), "USER".into(),
            ]),
        }
    }

    /// Create a permissive sandbox — minimal restrictions.
    pub fn permissive(app_id: &str) -> Self {
        Self {
            app_id: app_id.into(),
            isolation_level: IsolationLevel::Basic,
            allowed_paths: HashSet::new(),
            denied_paths: HashSet::new(),
            readonly_paths: HashSet::new(),
            allowed_network: true,
            allowed_ports: HashSet::new(),
            allowed_ipc: true,
            max_memory_mb: 4096,
            max_cpu_percent: 100,
            max_file_descriptors: 4096,
            max_processes: 100,
            allow_dbus: true,
            allow_x11: true,
            allow_wayland: true,
            allow_audio: true,
            allow_gpu: true,
            environment_whitelist: HashSet::new(),
        }
    }

    /// Generate Bubblewrap (bwrap) command-line arguments for this profile.
    pub fn to_bwrap_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // Unshare namespaces based on isolation level.
        match self.isolation_level {
            IsolationLevel::None | IsolationLevel::Basic => {}
            IsolationLevel::Standard => {
                args.push("--unshare-net".into());
            }
            IsolationLevel::Strict => {
                args.push("--unshare-pid".into());
                args.push("--unshare-net".into());
                args.push("--unshare-ipc".into());
            }
            IsolationLevel::Paranoid => {
                args.push("--unshare-all".into());
                args.push("--die-with-parent".into());
            }
        }

        // Mount bindings.
        for path in &self.readonly_paths {
            args.push("--ro-bind".into());
            args.push(path.to_string_lossy().into_owned());
            args.push(path.to_string_lossy().into_owned());
        }

        for path in &self.allowed_paths {
            args.push("--bind".into());
            args.push(path.to_string_lossy().into_owned());
            args.push(path.to_string_lossy().into_owned());
        }

        // /proc and /dev.
        args.push("--proc".into());
        args.push("/proc".into());
        args.push("--dev".into());
        args.push("/dev".into());

        // X11/Wayland.
        if self.allow_x11 {
            args.push("--bind".into());
            args.push("/tmp/.X11-unix".into());
            args.push("/tmp/.X11-unix".into());
        }

        if self.allow_wayland {
            if let Ok(display) = std::env::var("WAYLAND_DISPLAY") {
                let path = format!("/run/user/1000/{display}");
                args.push("--bind".into());
                args.push(path.clone());
                args.push(path);
            }
        }

        args
    }

    /// Check if a path is accessible under this profile.
    pub fn can_access(&self, path: &Path) -> bool {
        // Denied paths always block.
        if self.denied_paths.iter().any(|d| path.starts_with(d)) {
            return false;
        }
        // If allowed_paths is empty, everything not denied is allowed.
        if self.allowed_paths.is_empty() {
            return true;
        }
        // Otherwise, must be under an allowed or readonly path.
        self.allowed_paths.iter().any(|a| path.starts_with(a))
            || self.readonly_paths.iter().any(|r| path.starts_with(r))
    }

    /// Check if a path is read-only.
    pub fn is_readonly(&self, path: &Path) -> bool {
        self.readonly_paths.iter().any(|r| path.starts_with(r))
            && !self.allowed_paths.iter().any(|a| path.starts_with(a))
    }

    /// Check if a network port is allowed.
    pub fn can_use_port(&self, port: u16) -> bool {
        if !self.allowed_network {
            return false;
        }
        if self.allowed_ports.is_empty() {
            return true; // All ports allowed when no restriction set.
        }
        self.allowed_ports.contains(&port)
    }
}

/// A sandbox policy violation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxViolation {
    pub timestamp: DateTime<Utc>,
    pub app_id: String,
    pub violation_type: ViolationType,
    pub detail: String,
    pub blocked: bool,
}

/// Type of sandbox violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    PathAccessDenied,
    PathWriteDenied,
    NetworkAccessDenied,
    PortAccessDenied,
    IpcDenied,
    MemoryLimitExceeded,
    ProcessLimitExceeded,
    FdLimitExceeded,
}

/// Manages sandbox profiles and tracks violations.
pub struct SandboxManager {
    profiles: HashMap<String, SandboxProfile>,
    violations: VecDeque<SandboxViolation>,
    max_violations: usize,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            violations: VecDeque::new(),
            max_violations: 1000,
        }
    }

    pub fn add_profile(&mut self, profile: SandboxProfile) {
        self.profiles.insert(profile.app_id.clone(), profile);
    }

    pub fn remove_profile(&mut self, app_id: &str) -> bool {
        self.profiles.remove(app_id).is_some()
    }

    pub fn get_profile(&self, app_id: &str) -> Option<&SandboxProfile> {
        self.profiles.get(app_id)
    }

    /// Check and potentially log a file access.
    pub fn check_access(&mut self, app_id: &str, path: &Path) -> bool {
        let allowed = self
            .profiles
            .get(app_id)
            .map(|p| p.can_access(path))
            .unwrap_or(true);

        if !allowed {
            self.record_violation(SandboxViolation {
                timestamp: Utc::now(),
                app_id: app_id.into(),
                violation_type: ViolationType::PathAccessDenied,
                detail: format!("Blocked access to {}", path.display()),
                blocked: true,
            });
        }
        allowed
    }

    /// Check and potentially log a write attempt.
    pub fn check_write(&mut self, app_id: &str, path: &Path) -> bool {
        let profile = match self.profiles.get(app_id) {
            Some(p) => p,
            None => return true,
        };

        if !profile.can_access(path) || profile.is_readonly(path) {
            self.record_violation(SandboxViolation {
                timestamp: Utc::now(),
                app_id: app_id.into(),
                violation_type: ViolationType::PathWriteDenied,
                detail: format!("Blocked write to {}", path.display()),
                blocked: true,
            });
            return false;
        }
        true
    }

    /// Check network access.
    pub fn check_network(&mut self, app_id: &str, port: u16) -> bool {
        let allowed = self
            .profiles
            .get(app_id)
            .map(|p| p.can_use_port(port))
            .unwrap_or(true);

        if !allowed {
            self.record_violation(SandboxViolation {
                timestamp: Utc::now(),
                app_id: app_id.into(),
                violation_type: ViolationType::NetworkAccessDenied,
                detail: format!("Blocked network access on port {port}"),
                blocked: true,
            });
        }
        allowed
    }

    fn record_violation(&mut self, violation: SandboxViolation) {
        self.violations.push_back(violation);
        while self.violations.len() > self.max_violations {
            self.violations.pop_front();
        }
    }

    /// Get all violations for an app.
    pub fn violations_for(&self, app_id: &str) -> Vec<&SandboxViolation> {
        self.violations.iter().filter(|v| v.app_id == app_id).collect()
    }

    /// Get all recent violations.
    pub fn recent_violations(&self, n: usize) -> Vec<&SandboxViolation> {
        self.violations.iter().rev().take(n).collect()
    }

    /// Total violation count.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Get apps with the most violations.
    pub fn top_violators(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violations {
            *counts.entry(v.app_id.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restrictive_blocks_sensitive() {
        let profile = SandboxProfile::restrictive("app");
        assert!(!profile.can_access(Path::new("/etc/shadow")));
        assert!(!profile.can_access(Path::new("/root/.ssh")));
        assert!(!profile.can_access(Path::new("/home/user/docs")));
    }

    #[test]
    fn test_restrictive_allows_system_libs() {
        let profile = SandboxProfile::restrictive("app");
        assert!(profile.can_access(Path::new("/usr/lib/libssl.so")));
        assert!(profile.can_access(Path::new("/usr/share/fonts")));
    }

    #[test]
    fn test_permissive_allows_all() {
        let profile = SandboxProfile::permissive("app");
        assert!(profile.can_access(Path::new("/etc/passwd")));
        assert!(profile.allowed_network);
        assert!(profile.allow_dbus);
    }

    #[test]
    fn test_readonly_detection() {
        let profile = SandboxProfile::restrictive("app");
        assert!(profile.is_readonly(Path::new("/etc/hostname")));
        // /usr/lib is in both allowed and readonly — allowed takes precedence.
        assert!(!profile.is_readonly(Path::new("/usr/lib/libc.so")));
    }

    #[test]
    fn test_port_restrictions() {
        let mut profile = SandboxProfile::restrictive("app");
        profile.allowed_network = true;
        profile.allowed_ports.insert(443);
        profile.allowed_ports.insert(80);
        assert!(profile.can_use_port(443));
        assert!(profile.can_use_port(80));
        assert!(!profile.can_use_port(22));
    }

    #[test]
    fn test_network_disabled() {
        let profile = SandboxProfile::restrictive("app");
        assert!(!profile.can_use_port(443));
        assert!(!profile.can_use_port(80));
    }

    #[test]
    fn test_manager_violation_tracking() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("spy"));

        assert!(!mgr.check_access("spy", Path::new("/etc/shadow")));
        assert!(!mgr.check_access("spy", Path::new("/root/.ssh/id_rsa")));
        assert_eq!(mgr.violation_count(), 2);
        assert_eq!(mgr.violations_for("spy").len(), 2);
    }

    #[test]
    fn test_write_blocked_on_readonly() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("editor"));

        // /etc is readonly in restrictive profile.
        assert!(!mgr.check_write("editor", Path::new("/etc/hosts")));
        assert_eq!(mgr.violation_count(), 1);
    }

    #[test]
    fn test_unknown_app_allowed() {
        let mut mgr = SandboxManager::new();
        // No profile for "unknown" — should be allowed.
        assert!(mgr.check_access("unknown", Path::new("/etc/shadow")));
        assert_eq!(mgr.violation_count(), 0);
    }

    #[test]
    fn test_top_violators() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("bad_app"));
        mgr.add_profile(SandboxProfile::restrictive("worse_app"));

        mgr.check_access("bad_app", Path::new("/root/secret"));
        mgr.check_access("worse_app", Path::new("/root/a"));
        mgr.check_access("worse_app", Path::new("/root/b"));
        mgr.check_access("worse_app", Path::new("/root/c"));

        let top = mgr.top_violators(2);
        assert_eq!(top[0].0, "worse_app");
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_bwrap_args_strict() {
        let profile = SandboxProfile::restrictive("test");
        let args = profile.to_bwrap_args();
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"--proc".to_string()));
    }

    #[test]
    fn test_bwrap_args_paranoid() {
        let mut profile = SandboxProfile::restrictive("test");
        profile.isolation_level = IsolationLevel::Paranoid;
        let args = profile.to_bwrap_args();
        assert!(args.contains(&"--unshare-all".to_string()));
        assert!(args.contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn test_remove_profile() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("app"));
        assert_eq!(mgr.profile_count(), 1);
        assert!(mgr.remove_profile("app"));
        assert_eq!(mgr.profile_count(), 0);
        assert!(!mgr.remove_profile("nonexistent"));
    }

    #[test]
    fn test_network_violation_logged() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("app"));
        assert!(!mgr.check_network("app", 8080));
        assert_eq!(mgr.violation_count(), 1);
        let v = &mgr.recent_violations(1)[0];
        assert_eq!(v.violation_type, ViolationType::NetworkAccessDenied);
    }
}
