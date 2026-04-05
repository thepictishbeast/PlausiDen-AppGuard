//! Live process monitor — scans /proc to discover running apps and resource usage.
//!
//! Feeds into [`crate::tracker::UsageTracker`] to automatically detect which
//! applications are actually running rather than relying on manual launch
//! recording.

use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};

/// Suspicious base directories — processes running from these locations
/// often indicate malware persistence or exploitation.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/dev/mqueue",
    "/run/user",
];

/// A snapshot of a running process.
#[derive(Debug, Clone)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
    pub cpu_percent: f32,
    pub mem_rss_kb: u64,
    pub open_files: u32,
    pub network_connections: u32,
    pub started_at: DateTime<Utc>,
}

/// Scans `/proc` (or a test directory) to enumerate running processes and
/// their resource footprints.
pub struct ProcessMonitor {
    /// Root path for proc filesystem (default `/proc`, override for tests).
    proc_root: PathBuf,
}

impl ProcessMonitor {
    /// Create a monitor that reads from the real `/proc`.
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// Create a monitor that reads from a custom root (for testing).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: root.into(),
        }
    }

    // ── core scanning ──────────────────────────────────────────────

    /// Scan all running processes visible under `proc_root`.
    pub fn scan_running(&self) -> Vec<RunningProcess> {
        let mut procs = Vec::new();

        let entries = match fs::read_dir(&self.proc_root) {
            Ok(e) => e,
            Err(_) => return procs,
        };

        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(rp) = self.read_process(pid) {
                    procs.push(rp);
                }
            }
        }

        procs
    }

    /// Find all processes whose name contains `needle` (case-insensitive).
    pub fn find_by_name(&self, needle: &str) -> Vec<RunningProcess> {
        let lower = needle.to_lowercase();
        self.scan_running()
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Return processes using more than `threshold_mb` megabytes of RSS.
    pub fn resource_hogs(&self, threshold_mb: u64) -> Vec<RunningProcess> {
        let threshold_kb = threshold_mb * 1024;
        let mut hogs: Vec<_> = self
            .scan_running()
            .into_iter()
            .filter(|p| p.mem_rss_kb >= threshold_kb)
            .collect();
        hogs.sort_by(|a, b| b.mem_rss_kb.cmp(&a.mem_rss_kb));
        hogs
    }

    /// Return processes that have at least one open network connection.
    pub fn network_active(&self) -> Vec<RunningProcess> {
        self.scan_running()
            .into_iter()
            .filter(|p| p.network_connections > 0)
            .collect()
    }

    /// Return processes running from suspicious locations (e.g. `/tmp`,
    /// `/dev/shm`) which may indicate malware or exploitation.
    pub fn suspicious_processes(&self) -> Vec<RunningProcess> {
        self.scan_running()
            .into_iter()
            .filter(|p| {
                let exe = p.cmdline.split_whitespace().next().unwrap_or("");
                SUSPICIOUS_PATHS.iter().any(|sp| exe.starts_with(sp))
            })
            .collect()
    }

    // ── internal helpers ───────────────────────────────────────────

    fn read_process(&self, pid: u32) -> Option<RunningProcess> {
        let base = self.proc_root.join(pid.to_string());
        if !base.is_dir() {
            return None;
        }

        let comm = read_trimmed(&base.join("comm")).unwrap_or_default();
        if comm.is_empty() {
            return None;
        }

        let cmdline = read_cmdline(&base.join("cmdline"));
        let user = read_loginuid(&base.join("loginuid"));
        let (mem_rss_kb, started_at) = parse_stat_status(&base);
        let open_files = count_fds(&base.join("fd"));
        let network_connections = count_net_entries(&base.join("net/tcp"))
            + count_net_entries(&base.join("net/tcp6"));

        Some(RunningProcess {
            pid,
            name: comm,
            cmdline,
            user,
            cpu_percent: 0.0, // snapshot — would need two samples for delta
            mem_rss_kb,
            open_files,
            network_connections,
            started_at,
        })
    }
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ── file helpers ───────────────────────────────────────────────────

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_cmdline(path: &Path) -> String {
    fs::read(path)
        .ok()
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string()
        })
        .unwrap_or_default()
}

fn read_loginuid(path: &Path) -> String {
    read_trimmed(path).unwrap_or_else(|| "unknown".into())
}

fn parse_stat_status(base: &Path) -> (u64, DateTime<Utc>) {
    // VmRSS line in /proc/<pid>/status
    let rss = fs::read_to_string(base.join("status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
        })
        .unwrap_or(0);

    (rss, Utc::now())
}

fn count_fds(fd_dir: &Path) -> u32 {
    fs::read_dir(fd_dir)
        .map(|rd| rd.count() as u32)
        .unwrap_or(0)
}

fn count_net_entries(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .map(|s| {
            // First line is the header; every other non-empty line is a connection.
            s.lines().skip(1).filter(|l| !l.trim().is_empty()).count() as u32
        })
        .unwrap_or(0)
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use tempfile::TempDir;

    /// Build a fake /proc/<pid> tree inside a temp directory.
    fn mock_proc(
        root: &Path,
        pid: u32,
        comm: &str,
        cmdline_args: &[&str],
        rss_kb: u64,
        fd_count: u32,
        net_lines: u32,
    ) {
        let base = root.join(pid.to_string());
        fs::create_dir_all(base.join("fd")).unwrap();
        fs::create_dir_all(base.join("net")).unwrap();

        fs::write(base.join("comm"), format!("{comm}\n")).unwrap();

        // cmdline: null-separated
        let raw: Vec<u8> = cmdline_args
            .iter()
            .flat_map(|a| {
                let mut v = a.as_bytes().to_vec();
                v.push(0);
                v
            })
            .collect();
        fs::write(base.join("cmdline"), raw).unwrap();

        fs::write(base.join("loginuid"), "1000\n").unwrap();

        let status = format!(
            "Name:\t{comm}\nState:\tS (sleeping)\nVmRSS:\t{rss_kb} kB\nPPid:\t1\n"
        );
        fs::write(base.join("status"), status).unwrap();

        // fake file descriptors
        for i in 0..fd_count {
            fs::write(base.join("fd").join(i.to_string()), "").unwrap();
        }

        // fake net/tcp
        let mut net = String::from("  sl  local_address ...\n");
        for _ in 0..net_lines {
            net.push_str("   0: 0100007F:1F90 00000000:0000 0A ...\n");
        }
        fs::write(base.join("net/tcp"), &net).unwrap();
        fs::write(base.join("net/tcp6"), "  sl  local_address ...\n").unwrap();
    }

    #[test]
    fn test_scan_running_discovers_processes() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        mock_proc(root, 100, "firefox", &["/usr/bin/firefox"], 512_000, 30, 5);
        mock_proc(root, 200, "vim", &["/usr/bin/vim", "file.rs"], 8_000, 3, 0);

        let mon = ProcessMonitor::with_root(root);
        let procs = mon.scan_running();

        assert_eq!(procs.len(), 2);

        let names: HashSet<_> = procs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains("firefox"));
        assert!(names.contains("vim"));
    }

    #[test]
    fn test_find_by_name() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        mock_proc(root, 1, "firefox", &["/usr/bin/firefox"], 200_000, 5, 2);
        mock_proc(root, 2, "firefox-esr", &["/usr/bin/firefox-esr"], 180_000, 5, 1);
        mock_proc(root, 3, "bash", &["/usr/bin/bash"], 4_000, 2, 0);

        let mon = ProcessMonitor::with_root(root);
        let hits = mon.find_by_name("firefox");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_resource_hogs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // 500 MB hog
        mock_proc(root, 10, "chromium", &["/usr/bin/chromium"], 512_000, 50, 10);
        // 4 MB lightweight
        mock_proc(root, 11, "cat", &["/usr/bin/cat"], 4_000, 1, 0);

        let mon = ProcessMonitor::with_root(root);
        let hogs = mon.resource_hogs(100); // > 100 MB
        assert_eq!(hogs.len(), 1);
        assert_eq!(hogs[0].name, "chromium");
    }

    #[test]
    fn test_network_active() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        mock_proc(root, 20, "curl", &["/usr/bin/curl", "https://example.com"], 3_000, 4, 3);
        mock_proc(root, 21, "ls", &["/usr/bin/ls"], 1_000, 1, 0);

        let mon = ProcessMonitor::with_root(root);
        let active = mon.network_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "curl");
    }

    #[test]
    fn test_suspicious_processes() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Legit process
        mock_proc(root, 30, "systemd", &["/usr/lib/systemd/systemd"], 6_000, 10, 0);
        // Suspicious: binary in /tmp
        mock_proc(root, 31, "dropper", &["/tmp/.hidden/dropper", "--connect"], 2_000, 5, 2);
        // Suspicious: binary in /dev/shm
        mock_proc(root, 32, "miner", &["/dev/shm/xmrig"], 90_000, 3, 1);

        let mon = ProcessMonitor::with_root(root);
        let sus = mon.suspicious_processes();
        assert_eq!(sus.len(), 2);

        let names: HashSet<_> = sus.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains("dropper"));
        assert!(names.contains("miner"));
    }

    #[test]
    fn test_empty_proc_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let mon = ProcessMonitor::with_root(tmp.path());
        assert!(mon.scan_running().is_empty());
    }
}
