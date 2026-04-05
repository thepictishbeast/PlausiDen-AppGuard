//! Autostart entry management — detects and controls persistence mechanisms.
//!
//! Covers the three main Linux autostart vectors:
//! - **XDG autostart** (`~/.config/autostart/*.desktop`)
//! - **systemd user units** (`~/.config/systemd/user/*.service`)
//! - **user crontab** (`crontab -l`)
//!
//! This is security-relevant: malware commonly installs autostart entries
//! as a persistence mechanism.  The module can snapshot the current state
//! and detect newly-added entries between snapshots.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The mechanism through which an entry auto-starts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutostartKind {
    /// XDG `.desktop` file in `~/.config/autostart/`.
    XdgDesktop,
    /// systemd user unit in `~/.config/systemd/user/`.
    SystemdUser,
    /// Line in the user's crontab.
    Crontab,
}

/// A single autostart entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AutostartEntry {
    pub kind: AutostartKind,
    /// Human-readable identifier (filename, unit name, or cron line).
    pub identifier: String,
    /// Full path to the backing file, if applicable.
    pub path: Option<PathBuf>,
    /// Whether the entry is currently enabled.
    pub enabled: bool,
    /// The command/exec line.
    pub command: String,
}

/// Manages discovery and manipulation of autostart entries.
pub struct AutostartManager {
    /// Override for XDG autostart dir (default `~/.config/autostart`).
    xdg_autostart_dir: PathBuf,
    /// Override for systemd user dir (default `~/.config/systemd/user`).
    systemd_user_dir: PathBuf,
    /// Previous snapshot for diff-based detection.
    baseline: Option<HashSet<AutostartEntry>>,
}

impl AutostartManager {
    /// Create a manager using standard system paths.
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        Self {
            xdg_autostart_dir: PathBuf::from(format!("{home}/.config/autostart")),
            systemd_user_dir: PathBuf::from(format!("{home}/.config/systemd/user")),
            baseline: None,
        }
    }

    /// Create a manager with custom directories (for testing).
    pub fn with_dirs(xdg_dir: impl Into<PathBuf>, systemd_dir: impl Into<PathBuf>) -> Self {
        Self {
            xdg_autostart_dir: xdg_dir.into(),
            systemd_user_dir: systemd_dir.into(),
            baseline: None,
        }
    }

    // ── listing ────────────────────────────────────────────────────

    /// Enumerate all autostart entries from every supported source.
    pub fn list_all(&self) -> Vec<AutostartEntry> {
        let mut entries = Vec::new();
        entries.extend(self.list_xdg());
        entries.extend(self.list_systemd_user());
        entries.extend(self.list_crontab());
        entries
    }

    /// List XDG `.desktop` autostart entries.
    pub fn list_xdg(&self) -> Vec<AutostartEntry> {
        list_dir_entries(
            &self.xdg_autostart_dir,
            "desktop",
            AutostartKind::XdgDesktop,
            parse_desktop_exec,
            parse_desktop_enabled,
        )
    }

    /// List systemd user service units.
    pub fn list_systemd_user(&self) -> Vec<AutostartEntry> {
        list_dir_entries(
            &self.systemd_user_dir,
            "service",
            AutostartKind::SystemdUser,
            parse_unit_exec,
            parse_unit_enabled,
        )
    }

    /// List entries from the user's crontab.
    pub fn list_crontab(&self) -> Vec<AutostartEntry> {
        // In production this would call `crontab -l`; for testability we
        // return an empty list if that fails.
        let output = std::process::Command::new("crontab")
            .arg("-l")
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                parse_crontab_lines(&text)
            }
            _ => Vec::new(),
        }
    }

    // ── change detection ───────────────────────────────────────────

    /// Take a snapshot of the current autostart state as a baseline.
    pub fn snapshot_baseline(&mut self) {
        self.baseline = Some(self.list_all().into_iter().collect());
    }

    /// Return entries that are present now but were **not** in the baseline.
    pub fn detect_new_entries(&self) -> Vec<AutostartEntry> {
        let current: HashSet<_> = self.list_all().into_iter().collect();
        match &self.baseline {
            Some(base) => current.difference(base).cloned().collect(),
            None => current.into_iter().collect(), // no baseline = everything is "new"
        }
    }

    // ── enable / disable ───────────────────────────────────────────

    /// Disable an XDG autostart entry by setting `Hidden=true`.
    pub fn disable_xdg(&self, identifier: &str) -> Result<(), String> {
        let path = self.xdg_autostart_dir.join(identifier);
        toggle_desktop_hidden(&path, true)
    }

    /// Enable an XDG autostart entry by removing `Hidden=true`.
    pub fn enable_xdg(&self, identifier: &str) -> Result<(), String> {
        let path = self.xdg_autostart_dir.join(identifier);
        toggle_desktop_hidden(&path, false)
    }
}

impl Default for AutostartManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── internal helpers ───────────────────────────────────────────────

fn list_dir_entries(
    dir: &Path,
    extension: &str,
    kind: AutostartKind,
    exec_parser: fn(&str) -> String,
    enabled_parser: fn(&str) -> bool,
) -> Vec<AutostartEntry> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return out,
    };

    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(extension) {
            continue;
        }
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ident = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        out.push(AutostartEntry {
            kind: kind.clone(),
            identifier: ident,
            path: Some(path),
            enabled: enabled_parser(&contents),
            command: exec_parser(&contents),
        });
    }

    out
}

fn parse_desktop_exec(contents: &str) -> String {
    contents
        .lines()
        .find(|l| l.starts_with("Exec="))
        .map(|l| l.trim_start_matches("Exec=").to_string())
        .unwrap_or_default()
}

fn parse_desktop_enabled(contents: &str) -> bool {
    // `Hidden=true` means *disabled* in XDG spec.
    !contents.lines().any(|l| l.trim() == "Hidden=true")
}

fn parse_unit_exec(contents: &str) -> String {
    contents
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .map(|l| l.trim_start_matches("ExecStart=").to_string())
        .unwrap_or_default()
}

fn parse_unit_enabled(_contents: &str) -> bool {
    // Without checking symlinks in wants/default.target.wants we
    // assume enabled; a richer implementation would `systemctl
    // --user is-enabled`.
    true
}

fn parse_crontab_lines(text: &str) -> Vec<AutostartEntry> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| {
            let parts: Vec<&str> = l.splitn(6, ' ').collect();
            let cmd = if parts.len() == 6 {
                parts[5].to_string()
            } else {
                l.to_string()
            };
            AutostartEntry {
                kind: AutostartKind::Crontab,
                identifier: l.to_string(),
                path: None,
                enabled: true,
                command: cmd,
            }
        })
        .collect()
}

fn toggle_desktop_hidden(path: &Path, hide: bool) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let filtered: Vec<&str> = contents
        .lines()
        .filter(|l| l.trim() != "Hidden=true")
        .collect();

    let mut new_contents = filtered.join("\n");
    if hide {
        new_contents.push_str("\nHidden=true\n");
    } else {
        new_contents.push('\n');
    }

    fs::write(path, new_contents)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_desktop(dir: &Path, name: &str, exec: &str, hidden: bool) {
        let mut body = format!(
            "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\n"
        );
        if hidden {
            body.push_str("Hidden=true\n");
        }
        fs::write(dir.join(name), body).unwrap();
    }

    fn write_unit(dir: &Path, name: &str, exec: &str) {
        let body = format!(
            "[Unit]\nDescription=Test\n\n[Service]\nExecStart={exec}\n\n[Install]\nWantedBy=default.target\n"
        );
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn test_list_xdg_entries() {
        let tmp = TempDir::new().unwrap();
        let xdg = tmp.path().join("autostart");
        let sys = tmp.path().join("systemd");
        fs::create_dir_all(&xdg).unwrap();
        fs::create_dir_all(&sys).unwrap();

        write_desktop(&xdg, "steam.desktop", "/usr/bin/steam -silent", false);
        write_desktop(&xdg, "tracker.desktop", "/usr/lib/tracker-miner-fs", true);

        let mgr = AutostartManager::with_dirs(&xdg, &sys);
        let entries = mgr.list_xdg();

        assert_eq!(entries.len(), 2);

        let enabled: Vec<_> = entries.iter().filter(|e| e.enabled).collect();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].command, "/usr/bin/steam -silent");
    }

    #[test]
    fn test_list_systemd_units() {
        let tmp = TempDir::new().unwrap();
        let xdg = tmp.path().join("autostart");
        let sys = tmp.path().join("systemd");
        fs::create_dir_all(&xdg).unwrap();
        fs::create_dir_all(&sys).unwrap();

        write_unit(&sys, "backup.service", "/usr/local/bin/backup --daily");

        let mgr = AutostartManager::with_dirs(&xdg, &sys);
        let units = mgr.list_systemd_user();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].command, "/usr/local/bin/backup --daily");
        assert_eq!(units[0].kind, AutostartKind::SystemdUser);
    }

    #[test]
    fn test_detect_new_entries() {
        let tmp = TempDir::new().unwrap();
        let xdg = tmp.path().join("autostart");
        let sys = tmp.path().join("systemd");
        fs::create_dir_all(&xdg).unwrap();
        fs::create_dir_all(&sys).unwrap();

        write_desktop(&xdg, "known.desktop", "/usr/bin/known", false);

        let mut mgr = AutostartManager::with_dirs(&xdg, &sys);
        mgr.snapshot_baseline();

        // Simulate malware adding a new autostart entry
        write_desktop(&xdg, "backdoor.desktop", "/tmp/.x/payload", false);

        let new_entries = mgr.detect_new_entries();
        assert_eq!(new_entries.len(), 1);
        assert_eq!(new_entries[0].identifier, "backdoor.desktop");
    }

    #[test]
    fn test_disable_enable_xdg() {
        let tmp = TempDir::new().unwrap();
        let xdg = tmp.path().join("autostart");
        let sys = tmp.path().join("systemd");
        fs::create_dir_all(&xdg).unwrap();
        fs::create_dir_all(&sys).unwrap();

        write_desktop(&xdg, "app.desktop", "/usr/bin/app", false);

        let mgr = AutostartManager::with_dirs(&xdg, &sys);

        // Disable
        mgr.disable_xdg("app.desktop").unwrap();
        let entries = mgr.list_xdg();
        assert!(!entries[0].enabled, "should be disabled after disable_xdg");

        // Re-enable
        mgr.enable_xdg("app.desktop").unwrap();
        let entries = mgr.list_xdg();
        assert!(entries[0].enabled, "should be enabled after enable_xdg");
    }
}
