//! App sandboxing — restrict what apps can access.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub app_id: String,
    pub allowed_paths: HashSet<PathBuf>,
    pub denied_paths: HashSet<PathBuf>,
    pub allowed_network: bool,
    pub allowed_ipc: bool,
    pub max_memory_mb: u64,
    pub max_cpu_percent: u32,
}

impl SandboxProfile {
    pub fn restrictive(app_id: &str) -> Self {
        Self { app_id: app_id.into(), allowed_paths: HashSet::new(), denied_paths: HashSet::from(["/etc".into(), "/root".into(), "/home".into()]), allowed_network: false, allowed_ipc: false, max_memory_mb: 256, max_cpu_percent: 25 }
    }

    pub fn permissive(app_id: &str) -> Self {
        Self { app_id: app_id.into(), allowed_paths: HashSet::new(), denied_paths: HashSet::new(), allowed_network: true, allowed_ipc: true, max_memory_mb: 4096, max_cpu_percent: 100 }
    }

    pub fn can_access(&self, path: &std::path::Path) -> bool {
        if self.denied_paths.iter().any(|d| path.starts_with(d)) { return false; }
        if self.allowed_paths.is_empty() { return true; }
        self.allowed_paths.iter().any(|a| path.starts_with(a))
    }
}

pub struct SandboxManager {
    profiles: std::collections::HashMap<String, SandboxProfile>,
}

impl SandboxManager {
    pub fn new() -> Self { Self { profiles: std::collections::HashMap::new() } }
    pub fn add_profile(&mut self, profile: SandboxProfile) { self.profiles.insert(profile.app_id.clone(), profile); }
    pub fn get_profile(&self, app_id: &str) -> Option<&SandboxProfile> { self.profiles.get(app_id) }
    pub fn check_access(&self, app_id: &str, path: &std::path::Path) -> bool { self.profiles.get(app_id).map(|p| p.can_access(path)).unwrap_or(true) }
    pub fn profile_count(&self) -> usize { self.profiles.len() }
}

impl Default for SandboxManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_restrictive_blocks_etc() {
        let profile = SandboxProfile::restrictive("app");
        assert!(!profile.can_access(Path::new("/etc/passwd")));
        assert!(!profile.can_access(Path::new("/root/.ssh")));
    }

    #[test]
    fn test_permissive_allows_all() {
        let profile = SandboxProfile::permissive("app");
        assert!(profile.can_access(Path::new("/etc/passwd")));
        assert!(profile.allowed_network);
    }

    #[test]
    fn test_manager_check() {
        let mut mgr = SandboxManager::new();
        mgr.add_profile(SandboxProfile::restrictive("spy"));
        assert!(!mgr.check_access("spy", Path::new("/etc/shadow")));
        assert!(mgr.check_access("unknown", Path::new("/etc/shadow"))); // No profile = allowed
    }
}
