//! Sandbox evaluator — score application sandboxing effectiveness.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sandbox mechanism being used by an application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SandboxKind {
    None,
    Flatpak,
    Snap,
    AppImage,
    Firejail,
    Bubblewrap,
    Docker,
    AppArmor,
    Selinux,
    Seccomp,
    Namespaces,
}

/// Evaluated sandbox report for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    pub app_id: String,
    pub mechanisms: Vec<SandboxKind>,
    pub has_network: bool,
    pub has_filesystem_access: bool,
    pub has_device_access: bool,
    pub has_dbus_system: bool,
    pub score: u8, // 0-100
    pub grade: Grade,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A, // 85+
    B, // 70+
    C, // 55+
    D, // 40+
    F, // < 40
}

impl Grade {
    pub fn from_score(score: u8) -> Self {
        match score {
            85..=u8::MAX => Grade::A,
            70..=84 => Grade::B,
            55..=69 => Grade::C,
            40..=54 => Grade::D,
            _ => Grade::F,
        }
    }
}

/// Permissions an app has requested.
#[derive(Debug, Clone, Default)]
pub struct AppPermissions {
    pub network: bool,
    pub filesystem: bool,
    pub devices: bool,
    pub dbus_system: bool,
    pub x11_display: bool,
    pub pulseaudio: bool,
}

/// Sandbox evaluator.
pub struct SandboxEvaluator;

impl SandboxEvaluator {
    pub fn new() -> Self { Self }

    /// Evaluate an application's sandbox configuration.
    pub fn evaluate(
        &self,
        app_id: &str,
        mechanisms: &[SandboxKind],
        perms: &AppPermissions,
    ) -> SandboxReport {
        let mut score: i32 = 0;
        let mut warnings = Vec::new();

        // Base score from strongest mechanism.
        let base = mechanisms.iter()
            .map(|m| mechanism_base_score(m))
            .max()
            .unwrap_or(0);
        score += base;

        // Bonus for layered defenses.
        let unique: std::collections::HashSet<_> = mechanisms.iter().collect();
        if unique.len() >= 2 {
            score += 10;
        }
        if unique.len() >= 3 {
            score += 5;
        }

        // Penalties for overly broad permissions.
        if perms.network {
            score -= 5;
            warnings.push("network access granted".into());
        }
        if perms.filesystem {
            score -= 10;
            warnings.push("broad filesystem access granted".into());
        }
        if perms.devices {
            score -= 10;
            warnings.push("device access granted".into());
        }
        if perms.dbus_system {
            score -= 15;
            warnings.push("system dbus access granted (privilege risk)".into());
        }
        if perms.x11_display {
            score -= 5;
            warnings.push("X11 display allows keylogging of other windows".into());
        }

        // No sandbox at all.
        if mechanisms.is_empty() || mechanisms == [SandboxKind::None] {
            warnings.push("application runs without any sandbox".into());
        }

        let score = score.clamp(0, 100) as u8;

        SandboxReport {
            app_id: app_id.into(),
            mechanisms: mechanisms.to_vec(),
            has_network: perms.network,
            has_filesystem_access: perms.filesystem,
            has_device_access: perms.devices,
            has_dbus_system: perms.dbus_system,
            score,
            grade: Grade::from_score(score),
            warnings,
        }
    }

    /// Rank multiple applications by sandbox score (worst first).
    pub fn rank_worst(&self, reports: &[SandboxReport]) -> Vec<String> {
        let mut sorted: Vec<_> = reports.iter().collect();
        sorted.sort_by_key(|r| r.score);
        sorted.into_iter().map(|r| r.app_id.clone()).collect()
    }

    /// Count reports by grade.
    pub fn grade_distribution(&self, reports: &[SandboxReport]) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for r in reports {
            *map.entry(format!("{:?}", r.grade)).or_insert(0) += 1;
        }
        map
    }
}

impl Default for SandboxEvaluator {
    fn default() -> Self { Self::new() }
}

fn mechanism_base_score(kind: &SandboxKind) -> i32 {
    match kind {
        SandboxKind::None => 0,
        SandboxKind::AppImage => 10, // no real sandbox
        SandboxKind::AppArmor => 40,
        SandboxKind::Selinux => 45,
        SandboxKind::Seccomp => 30,
        SandboxKind::Namespaces => 40,
        SandboxKind::Firejail => 55,
        SandboxKind::Snap => 65,
        SandboxKind::Flatpak => 70,
        SandboxKind::Bubblewrap => 75,
        SandboxKind::Docker => 60,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_sandbox() {
        let ev = SandboxEvaluator::new();
        let report = ev.evaluate("firefox", &[], &AppPermissions::default());
        assert_eq!(report.grade, Grade::F);
        assert!(report.warnings.iter().any(|w| w.contains("without any sandbox")));
    }

    #[test]
    fn test_flatpak_basic() {
        let ev = SandboxEvaluator::new();
        let report = ev.evaluate("app", &[SandboxKind::Flatpak], &AppPermissions::default());
        assert_eq!(report.grade, Grade::B);
    }

    #[test]
    fn test_layered_defense_bonus() {
        let ev = SandboxEvaluator::new();
        let single = ev.evaluate("a", &[SandboxKind::Flatpak], &AppPermissions::default());
        let layered = ev.evaluate("b",
            &[SandboxKind::Flatpak, SandboxKind::Seccomp, SandboxKind::AppArmor],
            &AppPermissions::default());
        assert!(layered.score > single.score);
    }

    #[test]
    fn test_permission_penalties() {
        let ev = SandboxEvaluator::new();
        let safe = ev.evaluate("a", &[SandboxKind::Flatpak], &AppPermissions::default());
        let risky = ev.evaluate("b", &[SandboxKind::Flatpak], &AppPermissions {
            network: true,
            filesystem: true,
            devices: true,
            dbus_system: true,
            x11_display: false,
            pulseaudio: false,
        });
        assert!(risky.score < safe.score);
        assert!(risky.warnings.len() >= 4);
    }

    #[test]
    fn test_grade_from_score() {
        assert_eq!(Grade::from_score(90), Grade::A);
        assert_eq!(Grade::from_score(75), Grade::B);
        assert_eq!(Grade::from_score(60), Grade::C);
        assert_eq!(Grade::from_score(45), Grade::D);
        assert_eq!(Grade::from_score(20), Grade::F);
    }

    #[test]
    fn test_rank_worst() {
        let ev = SandboxEvaluator::new();
        let reports = vec![
            ev.evaluate("good", &[SandboxKind::Bubblewrap], &AppPermissions::default()),
            ev.evaluate("bad", &[], &AppPermissions::default()),
            ev.evaluate("mid", &[SandboxKind::Snap], &AppPermissions::default()),
        ];
        let ranked = ev.rank_worst(&reports);
        assert_eq!(ranked[0], "bad");
    }

    #[test]
    fn test_grade_distribution() {
        let ev = SandboxEvaluator::new();
        let reports = vec![
            ev.evaluate("a", &[SandboxKind::Bubblewrap, SandboxKind::Seccomp], &AppPermissions::default()),
            ev.evaluate("b", &[], &AppPermissions::default()),
        ];
        let dist = ev.grade_distribution(&reports);
        assert!(dist.values().sum::<usize>() == 2);
    }

    #[test]
    fn test_dbus_warning() {
        let ev = SandboxEvaluator::new();
        let report = ev.evaluate("app", &[SandboxKind::Flatpak], &AppPermissions {
            dbus_system: true,
            ..Default::default()
        });
        assert!(report.warnings.iter().any(|w| w.contains("dbus")));
    }
}
