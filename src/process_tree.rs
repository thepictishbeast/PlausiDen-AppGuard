//! App process tree — track which processes belong to which app.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A running process associated with an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppProcess {
    pub pid: u32,
    pub app_id: String,
    pub exe_path: String,
    pub parent_pid: u32,
}

/// App process tree.
pub struct AppProcessTree {
    /// PID → AppProcess
    by_pid: HashMap<u32, AppProcess>,
    /// app_id → set of PIDs
    by_app: HashMap<String, HashSet<u32>>,
}

impl AppProcessTree {
    pub fn new() -> Self {
        Self {
            by_pid: HashMap::new(),
            by_app: HashMap::new(),
        }
    }

    /// Register a process belonging to an app.
    pub fn register(&mut self, process: AppProcess) {
        self.by_app.entry(process.app_id.clone()).or_default().insert(process.pid);
        self.by_pid.insert(process.pid, process);
    }

    /// Remove a process.
    pub fn unregister(&mut self, pid: u32) {
        if let Some(proc) = self.by_pid.remove(&pid) {
            if let Some(set) = self.by_app.get_mut(&proc.app_id) {
                set.remove(&pid);
            }
        }
    }

    /// Get all processes for an app.
    pub fn processes_for(&self, app_id: &str) -> Vec<&AppProcess> {
        self.by_app.get(app_id)
            .map(|pids| pids.iter().filter_map(|p| self.by_pid.get(p)).collect())
            .unwrap_or_default()
    }

    /// Find the app for a PID.
    pub fn app_for(&self, pid: u32) -> Option<&str> {
        self.by_pid.get(&pid).map(|p| p.app_id.as_str())
    }

    /// Get child processes of a parent.
    pub fn children_of(&self, ppid: u32) -> Vec<&AppProcess> {
        self.by_pid.values().filter(|p| p.parent_pid == ppid).collect()
    }

    /// Apps with the most processes.
    pub fn top_processes(&self, n: usize) -> Vec<(String, usize)> {
        let mut sorted: Vec<_> = self.by_app.iter()
            .map(|(id, set)| (id.clone(), set.len()))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    pub fn process_count(&self) -> usize { self.by_pid.len() }
    pub fn app_count(&self) -> usize { self.by_app.len() }
}

impl Default for AppProcessTree {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: u32, app: &str, ppid: u32) -> AppProcess {
        AppProcess {
            pid,
            app_id: app.into(),
            exe_path: format!("/usr/bin/{app}"),
            parent_pid: ppid,
        }
    }

    #[test]
    fn test_register() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        assert_eq!(tree.process_count(), 1);
        assert_eq!(tree.app_count(), 1);
    }

    #[test]
    fn test_processes_for_app() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        tree.register(make_proc(101, "firefox", 100));
        tree.register(make_proc(200, "vim", 1));
        assert_eq!(tree.processes_for("firefox").len(), 2);
        assert_eq!(tree.processes_for("vim").len(), 1);
    }

    #[test]
    fn test_app_for_pid() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        assert_eq!(tree.app_for(100), Some("firefox"));
        assert_eq!(tree.app_for(999), None);
    }

    #[test]
    fn test_children_of() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        tree.register(make_proc(101, "firefox", 100));
        tree.register(make_proc(102, "firefox", 100));
        assert_eq!(tree.children_of(100).len(), 2);
    }

    #[test]
    fn test_unregister() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        tree.unregister(100);
        assert_eq!(tree.process_count(), 0);
        assert!(tree.processes_for("firefox").is_empty());
    }

    #[test]
    fn test_top_processes() {
        let mut tree = AppProcessTree::new();
        for i in 1..=5 { tree.register(make_proc(i, "firefox", 1)); }
        for i in 6..=7 { tree.register(make_proc(i, "vim", 1)); }
        let top = tree.top_processes(1);
        assert_eq!(top[0].0, "firefox");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_no_duplicate() {
        let mut tree = AppProcessTree::new();
        tree.register(make_proc(100, "firefox", 1));
        tree.register(make_proc(100, "firefox", 1));
        assert_eq!(tree.process_count(), 1);
    }
}
