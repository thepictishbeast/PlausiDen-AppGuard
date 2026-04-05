//! Data export and reporting -- generates comprehensive reports from all
//! AppGuard subsystems (usage tracking, permission auditing, network audit).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::network_audit::NetworkAuditor;
use crate::permissions::{Permission, PermissionAuditor};
use crate::tracker::UsageTracker;

// ── summary structs ───────────────────────────────────────────────────

/// Risk summary for a single application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRiskSummary {
    pub app_id: String,
    pub display_name: String,
    pub risk_score: f64,
    pub high_risk_permissions: Vec<String>,
    pub background_access_count: usize,
    pub suspicious_connections: usize,
}

/// Summary of an unused / archive-candidate application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedAppSummary {
    pub app_id: String,
    pub display_name: String,
    pub days_inactive: i64,
    pub reclaimable_bytes: u64,
}

/// A permission violation (granted but never exercised, or background use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionViolation {
    pub app_id: String,
    pub permission: String,
    pub kind: ViolationKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViolationKind {
    /// Permission granted but never used -- candidate for revocation.
    UnusedGrant,
    /// Permission exercised while app was in background.
    BackgroundAccess,
}

/// A suspicious or anomalous network event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnomaly {
    pub app_id: String,
    pub destination: String,
    pub reason: String,
}

// ── full report ───────────────────────────────────────────────────────

/// Comprehensive report compiled from all AppGuard data sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGuardReport {
    pub generated_at: DateTime<Utc>,
    pub total_apps: u32,
    pub high_risk_apps: Vec<AppRiskSummary>,
    pub unused_apps: Vec<UnusedAppSummary>,
    pub permission_violations: Vec<PermissionViolation>,
    pub network_anomalies: Vec<NetworkAnomaly>,
    pub reclaimable_space_bytes: u64,
    pub recommendations: Vec<String>,
}

// ── reporter ──────────────────────────────────────────────────────────

/// Compiles [`AppGuardReport`]s from the various AppGuard subsystems.
pub struct AppGuardReporter;

impl AppGuardReporter {
    /// Compile a full report from all data sources.
    pub fn generate_report(
        tracker: &UsageTracker,
        auditor: &PermissionAuditor,
        network: &NetworkAuditor,
    ) -> AppGuardReport {
        let all_apps = tracker.all_apps();
        let total_apps = all_apps.len() as u32;

        // -- high-risk apps (risk_score > 0.3) --
        let mut high_risk_apps = Vec::new();
        for app in &all_apps {
            let audit = auditor.audit_app(&app.app_id);
            let suspicious = network.check_suspicious(&app.app_id);

            if audit.risk_score > 0.3 || !suspicious.is_empty() {
                let hr_perms: Vec<String> = audit
                    .granted_permissions
                    .iter()
                    .filter(|p| is_high_risk_permission(p))
                    .map(format_permission)
                    .collect();

                high_risk_apps.push(AppRiskSummary {
                    app_id: app.app_id.clone(),
                    display_name: app.display_name.clone(),
                    risk_score: audit.risk_score,
                    high_risk_permissions: hr_perms,
                    background_access_count: audit.background_accesses.len(),
                    suspicious_connections: suspicious.len(),
                });
            }
        }
        high_risk_apps.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // -- unused / archive candidates --
        let unused_apps: Vec<UnusedAppSummary> = tracker
            .archive_candidates()
            .iter()
            .map(|a| UnusedAppSummary {
                app_id: a.app_id.clone(),
                display_name: a.display_name.clone(),
                days_inactive: a.days_since_last_use(),
                reclaimable_bytes: a.installed_size_bytes,
            })
            .collect();

        // -- permission violations --
        let mut permission_violations = Vec::new();
        for app in &all_apps {
            let audit = auditor.audit_app(&app.app_id);
            for perm in &audit.unused_permissions {
                permission_violations.push(PermissionViolation {
                    app_id: app.app_id.clone(),
                    permission: format_permission(perm),
                    kind: ViolationKind::UnusedGrant,
                });
            }
            for access in &audit.background_accesses {
                permission_violations.push(PermissionViolation {
                    app_id: app.app_id.clone(),
                    permission: format_permission(&access.permission),
                    kind: ViolationKind::BackgroundAccess,
                });
            }
        }

        // -- network anomalies --
        let mut network_anomalies = Vec::new();
        for app in &all_apps {
            for conn in network.check_suspicious(&app.app_id) {
                let dest = conn
                    .dest_domain
                    .as_deref()
                    .unwrap_or(&conn.dest_ip)
                    .to_string();
                network_anomalies.push(NetworkAnomaly {
                    app_id: app.app_id.clone(),
                    destination: dest,
                    reason: "Connection to known-suspicious destination".into(),
                });
            }
        }

        let reclaimable_space_bytes = tracker.reclaimable_space();

        // -- recommendations --
        let recommendations =
            build_recommendations(&high_risk_apps, &unused_apps, &permission_violations, &network_anomalies, reclaimable_space_bytes);

        AppGuardReport {
            generated_at: Utc::now(),
            total_apps,
            high_risk_apps,
            unused_apps,
            permission_violations,
            network_anomalies,
            reclaimable_space_bytes,
            recommendations,
        }
    }
}

impl AppGuardReport {
    /// Render the report as human-readable text.
    pub fn render_text(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "=== PlausiDen AppGuard Report ===\nGenerated: {}\nTotal apps tracked: {}\n\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.total_apps,
        ));

        // High-risk apps
        out.push_str(&format!(
            "--- High-Risk Applications ({}) ---\n",
            self.high_risk_apps.len()
        ));
        for app in &self.high_risk_apps {
            out.push_str(&format!(
                "  [{:.0}%] {} ({})\n",
                app.risk_score * 100.0,
                app.display_name,
                app.app_id,
            ));
            if !app.high_risk_permissions.is_empty() {
                out.push_str(&format!(
                    "        Permissions: {}\n",
                    app.high_risk_permissions.join(", ")
                ));
            }
            if app.background_access_count > 0 {
                out.push_str(&format!(
                    "        Background accesses: {}\n",
                    app.background_access_count
                ));
            }
            if app.suspicious_connections > 0 {
                out.push_str(&format!(
                    "        Suspicious connections: {}\n",
                    app.suspicious_connections
                ));
            }
        }
        out.push('\n');

        // Unused apps
        out.push_str(&format!(
            "--- Unused Applications ({}) ---\n",
            self.unused_apps.len()
        ));
        for app in &self.unused_apps {
            out.push_str(&format!(
                "  {} ({}) -- {} days inactive, {} reclaimable\n",
                app.display_name,
                app.app_id,
                app.days_inactive,
                format_bytes(app.reclaimable_bytes),
            ));
        }
        out.push('\n');

        // Permission violations
        out.push_str(&format!(
            "--- Permission Violations ({}) ---\n",
            self.permission_violations.len()
        ));
        for v in &self.permission_violations {
            let kind_str = match v.kind {
                ViolationKind::UnusedGrant => "unused grant",
                ViolationKind::BackgroundAccess => "background access",
            };
            out.push_str(&format!(
                "  {} -- {} ({})\n",
                v.app_id, v.permission, kind_str
            ));
        }
        out.push('\n');

        // Network anomalies
        out.push_str(&format!(
            "--- Network Anomalies ({}) ---\n",
            self.network_anomalies.len()
        ));
        for a in &self.network_anomalies {
            out.push_str(&format!(
                "  {} -> {} ({})\n",
                a.app_id, a.destination, a.reason
            ));
        }
        out.push('\n');

        // Reclaimable space
        out.push_str(&format!(
            "Reclaimable space: {}\n\n",
            format_bytes(self.reclaimable_space_bytes)
        ));

        // Recommendations
        out.push_str(&format!(
            "--- Recommendations ({}) ---\n",
            self.recommendations.len()
        ));
        for (i, rec) in self.recommendations.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", i + 1, rec));
        }

        out
    }

    /// Render the report as JSON (suitable for API export or machine consumption).
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render a standalone HTML report with inline CSS (no external dependencies).
    pub fn render_html(&self) -> String {
        let mut html = String::new();

        html.push_str(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PlausiDen AppGuard Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.6; }
  h1 { color: #58a6ff; margin-bottom: 0.3rem; }
  .meta { color: #8b949e; margin-bottom: 2rem; }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; margin-bottom: 1.5rem; }
  h2 { color: #58a6ff; font-size: 1.1rem; margin-bottom: 0.8rem; border-bottom: 1px solid #21262d; padding-bottom: 0.4rem; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; color: #8b949e; font-weight: 600; padding: 0.4rem 0.6rem; border-bottom: 1px solid #30363d; }
  td { padding: 0.4rem 0.6rem; border-bottom: 1px solid #21262d; }
  .risk-high { color: #f85149; font-weight: bold; }
  .risk-med  { color: #d29922; font-weight: bold; }
  .risk-low  { color: #3fb950; }
  .badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 12px; font-size: 0.8rem; }
  .badge-warn { background: #d292221a; color: #d29922; border: 1px solid #d2992244; }
  .badge-danger { background: #f851491a; color: #f85149; border: 1px solid #f8514944; }
  .badge-info { background: #58a6ff1a; color: #58a6ff; border: 1px solid #58a6ff44; }
  ol.recs { padding-left: 1.5rem; }
  ol.recs li { margin-bottom: 0.4rem; }
  .stat { display: inline-block; background: #21262d; border-radius: 6px; padding: 0.6rem 1rem; margin: 0.3rem; text-align: center; }
  .stat .num { font-size: 1.5rem; font-weight: bold; color: #58a6ff; display: block; }
  .stat .label { font-size: 0.8rem; color: #8b949e; }
  .empty { color: #484f58; font-style: italic; }
</style>
</head>
<body>
"#,
        );

        // Header
        html.push_str(&format!(
            "<h1>PlausiDen AppGuard Report</h1>\n<p class=\"meta\">Generated: {}</p>\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));

        // Stats bar
        html.push_str("<div>\n");
        html.push_str(&format!(
            "  <span class=\"stat\"><span class=\"num\">{}</span><span class=\"label\">Apps Tracked</span></span>\n",
            self.total_apps
        ));
        html.push_str(&format!(
            "  <span class=\"stat\"><span class=\"num\">{}</span><span class=\"label\">High Risk</span></span>\n",
            self.high_risk_apps.len()
        ));
        html.push_str(&format!(
            "  <span class=\"stat\"><span class=\"num\">{}</span><span class=\"label\">Unused</span></span>\n",
            self.unused_apps.len()
        ));
        html.push_str(&format!(
            "  <span class=\"stat\"><span class=\"num\">{}</span><span class=\"label\">Violations</span></span>\n",
            self.permission_violations.len()
        ));
        html.push_str(&format!(
            "  <span class=\"stat\"><span class=\"num\">{}</span><span class=\"label\">Reclaimable</span></span>\n",
            format_bytes(self.reclaimable_space_bytes)
        ));
        html.push_str("</div>\n\n");

        // High-risk apps section
        html.push_str("<section id=\"high-risk\">\n<h2>High-Risk Applications</h2>\n");
        if self.high_risk_apps.is_empty() {
            html.push_str("<p class=\"empty\">No high-risk applications detected.</p>\n");
        } else {
            html.push_str("<table><tr><th>App</th><th>Risk</th><th>Permissions</th><th>Background</th><th>Suspicious</th></tr>\n");
            for app in &self.high_risk_apps {
                let risk_class = if app.risk_score > 0.7 {
                    "risk-high"
                } else if app.risk_score > 0.4 {
                    "risk-med"
                } else {
                    "risk-low"
                };
                html.push_str(&format!(
                    "<tr><td>{}<br><small>{}</small></td><td class=\"{}\">{:.0}%</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape_html(&app.display_name),
                    escape_html(&app.app_id),
                    risk_class,
                    app.risk_score * 100.0,
                    app.high_risk_permissions.iter().map(|p| escape_html(p)).collect::<Vec<_>>().join(", "),
                    app.background_access_count,
                    app.suspicious_connections,
                ));
            }
            html.push_str("</table>\n");
        }
        html.push_str("</section>\n\n");

        // Unused apps section
        html.push_str("<section id=\"unused\">\n<h2>Unused Applications</h2>\n");
        if self.unused_apps.is_empty() {
            html.push_str("<p class=\"empty\">No unused applications detected.</p>\n");
        } else {
            html.push_str(
                "<table><tr><th>App</th><th>Days Inactive</th><th>Reclaimable</th></tr>\n",
            );
            for app in &self.unused_apps {
                html.push_str(&format!(
                    "<tr><td>{}<br><small>{}</small></td><td>{}</td><td>{}</td></tr>\n",
                    escape_html(&app.display_name),
                    escape_html(&app.app_id),
                    app.days_inactive,
                    format_bytes(app.reclaimable_bytes),
                ));
            }
            html.push_str("</table>\n");
        }
        html.push_str("</section>\n\n");

        // Permission violations section
        html.push_str("<section id=\"violations\">\n<h2>Permission Violations</h2>\n");
        if self.permission_violations.is_empty() {
            html.push_str("<p class=\"empty\">No permission violations detected.</p>\n");
        } else {
            html.push_str("<table><tr><th>App</th><th>Permission</th><th>Kind</th></tr>\n");
            for v in &self.permission_violations {
                let (badge_class, label) = match v.kind {
                    ViolationKind::UnusedGrant => ("badge-warn", "unused grant"),
                    ViolationKind::BackgroundAccess => ("badge-danger", "background access"),
                };
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>\n",
                    escape_html(&v.app_id),
                    escape_html(&v.permission),
                    badge_class,
                    label,
                ));
            }
            html.push_str("</table>\n");
        }
        html.push_str("</section>\n\n");

        // Network anomalies section
        html.push_str("<section id=\"network\">\n<h2>Network Anomalies</h2>\n");
        if self.network_anomalies.is_empty() {
            html.push_str("<p class=\"empty\">No network anomalies detected.</p>\n");
        } else {
            html.push_str("<table><tr><th>App</th><th>Destination</th><th>Reason</th></tr>\n");
            for a in &self.network_anomalies {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape_html(&a.app_id),
                    escape_html(&a.destination),
                    escape_html(&a.reason),
                ));
            }
            html.push_str("</table>\n");
        }
        html.push_str("</section>\n\n");

        // Recommendations section
        html.push_str("<section id=\"recommendations\">\n<h2>Recommendations</h2>\n");
        if self.recommendations.is_empty() {
            html.push_str("<p class=\"empty\">No recommendations at this time.</p>\n");
        } else {
            html.push_str("<ol class=\"recs\">\n");
            for rec in &self.recommendations {
                html.push_str(&format!("  <li>{}</li>\n", escape_html(rec)));
            }
            html.push_str("</ol>\n");
        }
        html.push_str("</section>\n\n");

        html.push_str("</body>\n</html>\n");
        html
    }

    /// Return the top prioritized action items from the report.
    pub fn top_recommendations(&self) -> Vec<&str> {
        // Already sorted by priority in build_recommendations; return all.
        self.recommendations.iter().map(|s| s.as_str()).collect()
    }
}

// ── helpers ───────────────────────────────────────────────────────────

fn is_high_risk_permission(p: &Permission) -> bool {
    matches!(
        p,
        Permission::Camera
            | Permission::Microphone
            | Permission::Location
            | Permission::DeviceAdmin
            | Permission::Accessibility
            | Permission::InstallApps
    )
}

fn format_permission(p: &Permission) -> String {
    match p {
        Permission::Custom(name) => format!("Custom({})", name),
        other => format!("{:?}", other),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Build prioritized recommendations (highest-priority first).
fn build_recommendations(
    high_risk: &[AppRiskSummary],
    unused: &[UnusedAppSummary],
    violations: &[PermissionViolation],
    anomalies: &[NetworkAnomaly],
    reclaimable: u64,
) -> Vec<String> {
    let mut recs = Vec::new();

    // Network anomalies are the most urgent.
    for a in anomalies {
        recs.push(format!(
            "URGENT: Investigate {} -- it connected to suspicious destination {}",
            a.app_id, a.destination
        ));
    }

    // High-risk apps with background access.
    for app in high_risk {
        if app.background_access_count > 0 {
            recs.push(format!(
                "Review background activity for {} (risk {:.0}%, {} background accesses)",
                app.display_name,
                app.risk_score * 100.0,
                app.background_access_count,
            ));
        }
    }

    // High-risk apps by score.
    for app in high_risk {
        if app.risk_score > 0.5 && app.background_access_count == 0 {
            recs.push(format!(
                "Audit permissions for {} -- risk score {:.0}% with permissions: {}",
                app.display_name,
                app.risk_score * 100.0,
                app.high_risk_permissions.join(", "),
            ));
        }
    }

    // Unused-grant violations.
    let unused_grant_count = violations
        .iter()
        .filter(|v| v.kind == ViolationKind::UnusedGrant)
        .count();
    if unused_grant_count > 0 {
        recs.push(format!(
            "Revoke {} unused permission grant(s) to reduce attack surface",
            unused_grant_count
        ));
    }

    // Reclaimable space.
    if reclaimable > 0 {
        recs.push(format!(
            "Archive {} unused app(s) to reclaim {}",
            unused.len(),
            format_bytes(reclaimable),
        ));
    }

    recs
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_audit::{AppConnection, NetworkAuditor};
    use crate::permissions::{Permission, PermissionAccess, PermissionAuditor};
    use crate::tracker::UsageTracker;
    use chrono::Duration;

    /// Build a test scenario with risky, unused, and clean apps.
    fn test_fixtures() -> (UsageTracker, PermissionAuditor, NetworkAuditor) {
        let mut tracker = UsageTracker::new(30);
        let mut perm_auditor = PermissionAuditor::new();
        let mut net_auditor = NetworkAuditor::new();

        // -- risky app: many dangerous permissions + background mic access --
        tracker.record_launch("com.risky.app", "Risky App");
        perm_auditor.register_app(
            "com.risky.app",
            vec![
                Permission::Camera,
                Permission::Microphone,
                Permission::Location,
                Permission::DeviceAdmin,
                Permission::Accessibility,
            ],
        );
        perm_auditor.record_access(PermissionAccess {
            permission: Permission::Microphone,
            app_id: "com.risky.app".into(),
            accessed_at: Utc::now(),
            foreground: false, // background!
        });

        // suspicious network connection
        net_auditor.record(AppConnection {
            app_id: "com.risky.app".into(),
            dest_ip: "6.6.6.6".into(),
            dest_port: 443,
            dest_domain: Some("malware-c2.example.com".into()),
            bytes_sent: 2000,
            bytes_received: 8000,
            timestamp: Utc::now(),
            protocol: "tcp".into(),
        });

        // -- unused app: not launched in 60 days --
        let (id, usage) = make_old_app(
            "com.old.app",
            "Old App",
            Utc::now() - Duration::days(60),
            50_000_000,
        );
        tracker.insert_raw(id, usage);

        // -- clean app: benign permissions, no issues --
        tracker.record_launch("com.clean.app", "Clean App");
        perm_auditor.register_app("com.clean.app", vec![Permission::Notifications]);

        (tracker, perm_auditor, net_auditor)
    }

    /// Build a pre-populated `AppUsage` tuple suitable for `insert_raw`.
    fn make_old_app(
        app_id: &str,
        display_name: &str,
        last_used: DateTime<Utc>,
        installed_size: u64,
    ) -> (String, crate::tracker::AppUsage) {
        (
            app_id.to_string(),
            crate::tracker::AppUsage {
                app_id: app_id.to_string(),
                display_name: display_name.to_string(),
                foreground_time_secs: 10,
                launch_count: 1,
                last_used,
                first_seen: last_used - Duration::days(30),
                installed_size_bytes: installed_size,
                data_size_bytes: 5_000_000,
                archived: false,
            },
        )
    }

    // ── tests ────────────────────────────────────────────────────

    #[test]
    fn test_generate_report_populates_all_fields() {
        let (tracker, auditor, network) = test_fixtures();
        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);

        assert_eq!(report.total_apps, 3);
        assert!(!report.high_risk_apps.is_empty(), "should flag risky app");
        assert!(!report.unused_apps.is_empty(), "should find unused app");
        assert!(
            !report.permission_violations.is_empty(),
            "should detect violations"
        );
        assert!(
            !report.network_anomalies.is_empty(),
            "should detect anomaly"
        );
        assert!(report.reclaimable_space_bytes > 0);
    }

    #[test]
    fn test_json_roundtrip() {
        let (tracker, auditor, network) = test_fixtures();
        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);

        let json = report.render_json().expect("JSON serialization failed");
        let deserialized: AppGuardReport =
            serde_json::from_str(&json).expect("JSON deserialization failed");

        assert_eq!(deserialized.total_apps, report.total_apps);
        assert_eq!(
            deserialized.high_risk_apps.len(),
            report.high_risk_apps.len()
        );
        assert_eq!(deserialized.unused_apps.len(), report.unused_apps.len());
        assert_eq!(
            deserialized.network_anomalies.len(),
            report.network_anomalies.len()
        );
        assert_eq!(
            deserialized.recommendations.len(),
            report.recommendations.len()
        );
    }

    #[test]
    fn test_recommendations_not_empty_for_risky_apps() {
        let (tracker, auditor, network) = test_fixtures();
        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);

        assert!(
            !report.recommendations.is_empty(),
            "risky scenario must produce recommendations"
        );

        // Should have an URGENT recommendation for the suspicious connection.
        let has_urgent = report
            .recommendations
            .iter()
            .any(|r| r.starts_with("URGENT"));
        assert!(has_urgent, "suspicious connection should trigger URGENT rec");

        // top_recommendations should return the same items.
        assert_eq!(
            report.top_recommendations().len(),
            report.recommendations.len()
        );
    }

    #[test]
    fn test_html_contains_required_sections() {
        let (tracker, auditor, network) = test_fixtures();
        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);
        let html = report.render_html();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("id=\"high-risk\""));
        assert!(html.contains("id=\"unused\""));
        assert!(html.contains("id=\"violations\""));
        assert!(html.contains("id=\"network\""));
        assert!(html.contains("id=\"recommendations\""));
        assert!(html.contains("<style>"));
        // Should contain the risky app name.
        assert!(html.contains("Risky App"));
    }

    #[test]
    fn test_text_report_formatting() {
        let (tracker, auditor, network) = test_fixtures();
        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);
        let text = report.render_text();

        assert!(text.contains("=== PlausiDen AppGuard Report ==="));
        assert!(text.contains("High-Risk Applications"));
        assert!(text.contains("Unused Applications"));
        assert!(text.contains("Permission Violations"));
        assert!(text.contains("Network Anomalies"));
        assert!(text.contains("Recommendations"));
        assert!(text.contains("Risky App"));
        assert!(text.contains("Old App"));
    }

    #[test]
    fn test_empty_scenario_no_panic() {
        let tracker = UsageTracker::new(90);
        let auditor = PermissionAuditor::new();
        let network = NetworkAuditor::new();

        let report = AppGuardReporter::generate_report(&tracker, &auditor, &network);
        assert_eq!(report.total_apps, 0);
        assert!(report.high_risk_apps.is_empty());
        assert!(report.recommendations.is_empty());

        // All renderers should succeed on empty data.
        let _ = report.render_text();
        let _ = report.render_json().unwrap();
        let _ = report.render_html();
    }
}
