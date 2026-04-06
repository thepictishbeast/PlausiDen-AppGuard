//! Risk scoring — composite app risk assessment.

use serde::{Deserialize, Serialize};

/// Risk factors for an application.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskFactors {
    pub permission_count: u32,
    pub critical_permissions: u32,
    pub network_access: bool,
    pub background_capable: bool,
    pub autostart: bool,
    pub system_paths_accessed: u32,
    pub external_network_destinations: u32,
    pub clipboard_access: bool,
    pub screen_capture: bool,
    pub keyboard_input: bool,
    pub root_required: bool,
    pub unknown_publisher: bool,
}

/// Risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Risk assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub app_id: String,
    pub score: u32, // 0-100
    pub level: RiskLevel,
    pub factors: RiskFactors,
    pub explanation: Vec<String>,
}

/// Risk scorer.
pub struct RiskScorer;

impl RiskScorer {
    pub fn new() -> Self { Self }

    /// Compute risk score from factors.
    pub fn score(&self, app_id: &str, factors: RiskFactors) -> RiskAssessment {
        let mut score = 0u32;
        let mut explanation = Vec::new();

        // Permission factors.
        score += factors.permission_count.min(20);
        if factors.permission_count > 10 {
            explanation.push(format!("High permission count: {}", factors.permission_count));
        }

        score += factors.critical_permissions * 10;
        if factors.critical_permissions > 0 {
            explanation.push(format!("{} critical permissions", factors.critical_permissions));
        }

        // Network exposure.
        if factors.network_access {
            score += 5;
        }
        if factors.external_network_destinations > 10 {
            score += 10;
            explanation.push(format!("{} external destinations", factors.external_network_destinations));
        }

        // Background activity.
        if factors.background_capable {
            score += 5;
        }
        if factors.autostart {
            score += 10;
            explanation.push("Autostart enabled".into());
        }

        // System access.
        score += (factors.system_paths_accessed * 2).min(20);
        if factors.system_paths_accessed > 5 {
            explanation.push(format!("{} system paths accessed", factors.system_paths_accessed));
        }

        // Sensitive capabilities.
        if factors.clipboard_access {
            score += 5;
        }
        if factors.screen_capture {
            score += 15;
            explanation.push("Screen capture capability".into());
        }
        if factors.keyboard_input {
            score += 15;
            explanation.push("Keyboard input access".into());
        }

        // Privilege.
        if factors.root_required {
            score += 20;
            explanation.push("Requires root privileges".into());
        }
        if factors.unknown_publisher {
            score += 10;
            explanation.push("Unknown publisher".into());
        }

        let score = score.min(100);
        let level = if score >= 75 { RiskLevel::Critical }
        else if score >= 50 { RiskLevel::High }
        else if score >= 25 { RiskLevel::Medium }
        else { RiskLevel::Low };

        RiskAssessment {
            app_id: app_id.into(),
            score,
            level,
            factors,
            explanation,
        }
    }
}

impl Default for RiskScorer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_risk_clean_app() {
        let scorer = RiskScorer::new();
        let factors = RiskFactors {
            permission_count: 2,
            ..Default::default()
        };
        let assessment = scorer.score("clean", factors);
        assert_eq!(assessment.level, RiskLevel::Low);
    }

    #[test]
    fn test_critical_risk_root_app() {
        let scorer = RiskScorer::new();
        let factors = RiskFactors {
            permission_count: 15,
            critical_permissions: 5,
            network_access: true,
            external_network_destinations: 20,
            screen_capture: true,
            keyboard_input: true,
            root_required: true,
            ..Default::default()
        };
        let assessment = scorer.score("malware", factors);
        assert_eq!(assessment.level, RiskLevel::Critical);
        assert!(assessment.score >= 75);
    }

    #[test]
    fn test_medium_risk_normal_app() {
        let scorer = RiskScorer::new();
        let factors = RiskFactors {
            permission_count: 8,
            critical_permissions: 1,
            network_access: true,
            background_capable: true,
            autostart: true,
            ..Default::default()
        };
        let assessment = scorer.score("normal", factors);
        assert!(assessment.level >= RiskLevel::Medium);
    }

    #[test]
    fn test_explanation_generated() {
        let scorer = RiskScorer::new();
        let factors = RiskFactors {
            critical_permissions: 3,
            screen_capture: true,
            ..Default::default()
        };
        let assessment = scorer.score("app", factors);
        assert!(!assessment.explanation.is_empty());
    }

    #[test]
    fn test_score_capped_at_100() {
        let scorer = RiskScorer::new();
        let factors = RiskFactors {
            permission_count: 100,
            critical_permissions: 100,
            network_access: true,
            background_capable: true,
            autostart: true,
            system_paths_accessed: 100,
            external_network_destinations: 100,
            clipboard_access: true,
            screen_capture: true,
            keyboard_input: true,
            root_required: true,
            unknown_publisher: true,
        };
        let assessment = scorer.score("evil", factors);
        assert_eq!(assessment.score, 100);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }
}
