//! Data flow tracking — monitors where app data goes and enforces policies.
//!
//! Tracks per-app file access, network connections, clipboard and screen access.
//! Policy engine with default-deny mode. Analytics for data exfiltration risk
//! scoring and suspicious flow detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core event types
// ---------------------------------------------------------------------------

/// A file access event recorded for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    pub app_id: String,
    pub path: String,
    pub access_kind: FileAccessKind,
    pub size_bytes: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileAccessKind {
    Read,
    Write,
}

/// A network connection event recorded for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub app_id: String,
    pub destination: String,
    pub port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: DateTime<Utc>,
}

/// Clipboard access by an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEvent {
    pub app_id: String,
    pub access_kind: ClipboardAccessKind,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClipboardAccessKind {
    Read,
    Write,
}

/// Screen capture / recording by an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenEvent {
    pub app_id: String,
    pub capture_kind: ScreenCaptureKind,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScreenCaptureKind {
    Screenshot,
    Recording,
}

// ---------------------------------------------------------------------------
// Legacy compat types (kept for downstream consumers)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEvent {
    pub app_id: String,
    pub data_type: DataType,
    pub destination: FlowDestination,
    pub bytes: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType {
    Contacts,
    Photos,
    Location,
    Messages,
    Files,
    Clipboard,
    Keystrokes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowDestination {
    LocalFile(String),
    Network(String),
    Clipboard,
    SystemService(String),
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A rule governing which data flows are permitted for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPolicy {
    /// Application identifier the policy applies to.
    pub app_id: String,
    /// File path globs the app is allowed to read.
    pub allowed_read_globs: Vec<String>,
    /// File path globs the app is allowed to write.
    pub allowed_write_globs: Vec<String>,
    /// Host patterns the app may connect to (simple glob, e.g. `*.example.com`).
    pub allowed_hosts: Vec<String>,
    /// Whether clipboard access is permitted.
    pub clipboard_allowed: bool,
    /// Whether screen capture / recording is permitted.
    pub screen_capture_allowed: bool,
}

/// Top-level policy set with optional default-deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    /// Per-app policies keyed by `app_id`.
    pub policies: HashMap<String, DataFlowPolicy>,
    /// When true, any app without an explicit policy is denied everything.
    pub default_deny: bool,
}

impl PolicySet {
    pub fn new(default_deny: bool) -> Self {
        Self {
            policies: HashMap::new(),
            default_deny,
        }
    }

    pub fn add_policy(&mut self, policy: DataFlowPolicy) {
        self.policies.insert(policy.app_id.clone(), policy);
    }
}

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// Severity of a policy violation, driven by data sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Records a single policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowViolation {
    pub app_id: String,
    pub action: String,
    pub resource: String,
    pub severity: ViolationSeverity,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Glob matching (minimal, avoids extra dependency)
// ---------------------------------------------------------------------------

/// Basic glob matcher supporting `*` (any chars) and `?` (single char).
fn glob_matches(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let val: Vec<char> = value.chars().collect();
    glob_match_inner(&pat, &val)
}

fn glob_match_inner(pat: &[char], val: &[char]) -> bool {
    match (pat.first(), val.first()) {
        (None, None) => true,
        (Some(&'*'), _) => {
            // '*' matches zero or more characters
            glob_match_inner(&pat[1..], val)
                || (!val.is_empty() && glob_match_inner(pat, &val[1..]))
        }
        (Some(&'?'), Some(_)) => glob_match_inner(&pat[1..], &val[1..]),
        (Some(&pc), Some(&vc)) if pc == vc => glob_match_inner(&pat[1..], &val[1..]),
        _ => false,
    }
}

/// Determine severity from a file path.
fn severity_for_path(path: &str) -> ViolationSeverity {
    if path.starts_with("/etc/")
        || path.starts_with("/sys/")
        || path.starts_with("/proc/")
        || path.contains("/shadow")
        || path.contains("/passwd")
        || path.contains("/.ssh/")
    {
        ViolationSeverity::Critical
    } else if path.starts_with("/home/") || path.starts_with("/Users/") {
        ViolationSeverity::High
    } else if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
        ViolationSeverity::Low
    } else {
        ViolationSeverity::Medium
    }
}

// ---------------------------------------------------------------------------
// DataFlowTracker
// ---------------------------------------------------------------------------

/// Full data-flow tracker: records events, enforces policies, produces analytics.
pub struct DataFlowTracker {
    /// Legacy event stream (kept for backward compat).
    events: Vec<DataFlowEvent>,
    max_events: usize,

    // Granular per-category event stores
    file_events: Vec<FileAccessEvent>,
    network_events: Vec<NetworkEvent>,
    clipboard_events: Vec<ClipboardEvent>,
    screen_events: Vec<ScreenEvent>,

    /// Policy set (if any).
    policy_set: Option<PolicySet>,

    /// Recorded violations.
    violations: Vec<DataFlowViolation>,
}

impl DataFlowTracker {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Vec::new(),
            max_events,
            file_events: Vec::new(),
            network_events: Vec::new(),
            clipboard_events: Vec::new(),
            screen_events: Vec::new(),
            policy_set: None,
            violations: Vec::new(),
        }
    }

    /// Attach a policy set for enforcement.
    pub fn set_policies(&mut self, ps: PolicySet) {
        self.policy_set = Some(ps);
    }

    // -----------------------------------------------------------------------
    // Recording helpers
    // -----------------------------------------------------------------------

    /// Record a legacy `DataFlowEvent` (backward-compatible entry point).
    pub fn record(&mut self, event: DataFlowEvent) {
        self.events.push(event);
        if self.events.len() > self.max_events {
            self.events.drain(..self.max_events / 2);
        }
    }

    /// Record a file access and check policy.
    pub fn record_file_access(&mut self, evt: FileAccessEvent) {
        if let Some(violation) = self.check_file_policy(&evt) {
            self.violations.push(violation);
        }
        self.file_events.push(evt);
    }

    /// Record a network event and check policy.
    pub fn record_network(&mut self, evt: NetworkEvent) {
        if let Some(violation) = self.check_network_policy(&evt) {
            self.violations.push(violation);
        }
        self.network_events.push(evt);
    }

    /// Record a clipboard event and check policy.
    pub fn record_clipboard(&mut self, evt: ClipboardEvent) {
        if let Some(violation) = self.check_clipboard_policy(&evt) {
            self.violations.push(violation);
        }
        self.clipboard_events.push(evt);
    }

    /// Record a screen capture event and check policy.
    pub fn record_screen(&mut self, evt: ScreenEvent) {
        if let Some(violation) = self.check_screen_policy(&evt) {
            self.violations.push(violation);
        }
        self.screen_events.push(evt);
    }

    // -----------------------------------------------------------------------
    // Policy checks (return a violation when the action is not permitted)
    // -----------------------------------------------------------------------

    fn check_file_policy(&self, evt: &FileAccessEvent) -> Option<DataFlowViolation> {
        let ps = self.policy_set.as_ref()?;
        let action = match evt.access_kind {
            FileAccessKind::Read => "file_read",
            FileAccessKind::Write => "file_write",
        };
        match ps.policies.get(&evt.app_id) {
            Some(pol) => {
                let globs = match evt.access_kind {
                    FileAccessKind::Read => &pol.allowed_read_globs,
                    FileAccessKind::Write => &pol.allowed_write_globs,
                };
                let allowed = globs.iter().any(|g| glob_matches(g, &evt.path));
                if allowed {
                    None
                } else {
                    Some(DataFlowViolation {
                        app_id: evt.app_id.clone(),
                        action: action.into(),
                        resource: evt.path.clone(),
                        severity: severity_for_path(&evt.path),
                        timestamp: evt.timestamp,
                    })
                }
            }
            None if ps.default_deny => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: action.into(),
                resource: evt.path.clone(),
                severity: severity_for_path(&evt.path),
                timestamp: evt.timestamp,
            }),
            None => None,
        }
    }

    fn check_network_policy(&self, evt: &NetworkEvent) -> Option<DataFlowViolation> {
        let ps = self.policy_set.as_ref()?;
        match ps.policies.get(&evt.app_id) {
            Some(pol) => {
                let allowed = pol
                    .allowed_hosts
                    .iter()
                    .any(|h| glob_matches(h, &evt.destination));
                if allowed {
                    None
                } else {
                    Some(DataFlowViolation {
                        app_id: evt.app_id.clone(),
                        action: "network_connect".into(),
                        resource: format!("{}:{}", evt.destination, evt.port),
                        severity: ViolationSeverity::High,
                        timestamp: evt.timestamp,
                    })
                }
            }
            None if ps.default_deny => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: "network_connect".into(),
                resource: format!("{}:{}", evt.destination, evt.port),
                severity: ViolationSeverity::High,
                timestamp: evt.timestamp,
            }),
            None => None,
        }
    }

    fn check_clipboard_policy(&self, evt: &ClipboardEvent) -> Option<DataFlowViolation> {
        let ps = self.policy_set.as_ref()?;
        match ps.policies.get(&evt.app_id) {
            Some(pol) if !pol.clipboard_allowed => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: "clipboard_access".into(),
                resource: "clipboard".into(),
                severity: ViolationSeverity::Medium,
                timestamp: evt.timestamp,
            }),
            None if ps.default_deny => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: "clipboard_access".into(),
                resource: "clipboard".into(),
                severity: ViolationSeverity::Medium,
                timestamp: evt.timestamp,
            }),
            _ => None,
        }
    }

    fn check_screen_policy(&self, evt: &ScreenEvent) -> Option<DataFlowViolation> {
        let ps = self.policy_set.as_ref()?;
        match ps.policies.get(&evt.app_id) {
            Some(pol) if !pol.screen_capture_allowed => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: "screen_capture".into(),
                resource: format!("{:?}", evt.capture_kind),
                severity: ViolationSeverity::High,
                timestamp: evt.timestamp,
            }),
            None if ps.default_deny => Some(DataFlowViolation {
                app_id: evt.app_id.clone(),
                action: "screen_capture".into(),
                resource: format!("{:?}", evt.capture_kind),
                severity: ViolationSeverity::High,
                timestamp: evt.timestamp,
            }),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Query helpers (legacy + granular)
    // -----------------------------------------------------------------------

    pub fn flows_by_app(&self, app_id: &str) -> Vec<&DataFlowEvent> {
        self.events.iter().filter(|e| e.app_id == app_id).collect()
    }

    pub fn network_flows(&self) -> Vec<&DataFlowEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e.destination, FlowDestination::Network(_)))
            .collect()
    }

    pub fn total_bytes_by_app(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for e in &self.events {
            *map.entry(e.app_id.clone()).or_default() += e.bytes;
        }
        map
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn file_events_for(&self, app_id: &str) -> Vec<&FileAccessEvent> {
        self.file_events
            .iter()
            .filter(|e| e.app_id == app_id)
            .collect()
    }

    pub fn network_events_for(&self, app_id: &str) -> Vec<&NetworkEvent> {
        self.network_events
            .iter()
            .filter(|e| e.app_id == app_id)
            .collect()
    }

    pub fn clipboard_events_for(&self, app_id: &str) -> Vec<&ClipboardEvent> {
        self.clipboard_events
            .iter()
            .filter(|e| e.app_id == app_id)
            .collect()
    }

    pub fn screen_events_for(&self, app_id: &str) -> Vec<&ScreenEvent> {
        self.screen_events
            .iter()
            .filter(|e| e.app_id == app_id)
            .collect()
    }

    pub fn violations(&self) -> &[DataFlowViolation] {
        &self.violations
    }

    // -----------------------------------------------------------------------
    // Analytics
    // -----------------------------------------------------------------------

    /// Return the top `n` apps by total bytes sent over the network, descending.
    pub fn top_senders(&self, n: usize) -> Vec<(String, u64)> {
        let mut totals: HashMap<String, u64> = HashMap::new();
        for evt in &self.network_events {
            *totals.entry(evt.app_id.clone()).or_default() += evt.bytes_sent;
        }
        let mut ranked: Vec<(String, u64)> = totals.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    /// Apps that read sensitive file paths AND have outgoing network connections.
    pub fn suspicious_flows(&self) -> Vec<DataFlowViolation> {
        let sensitive_prefixes: &[&str] = &[
            "/etc/", "/home/", "/Users/", "/proc/", "/sys/",
        ];

        // Collect apps that read sensitive paths.
        let mut sensitive_readers: HashMap<String, Vec<String>> = HashMap::new();
        for fe in &self.file_events {
            if fe.access_kind == FileAccessKind::Read
                && sensitive_prefixes.iter().any(|p| fe.path.starts_with(p))
            {
                sensitive_readers
                    .entry(fe.app_id.clone())
                    .or_default()
                    .push(fe.path.clone());
            }
        }

        // Intersect with apps that have network connections.
        let networked_apps: std::collections::HashSet<&str> = self
            .network_events
            .iter()
            .map(|ne| ne.app_id.as_str())
            .collect();

        let mut results = Vec::new();
        for (app_id, paths) in &sensitive_readers {
            if networked_apps.contains(app_id.as_str()) {
                for path in paths {
                    results.push(DataFlowViolation {
                        app_id: app_id.clone(),
                        action: "suspicious_flow".into(),
                        resource: path.clone(),
                        severity: severity_for_path(path),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
        results
    }

    /// Exfiltration risk score for an app: 0.0 (safe) to 1.0 (extreme risk).
    ///
    /// Heuristic factors:
    /// - Volume of outbound bytes (more = higher)
    /// - Number of distinct remote hosts
    /// - Reads of sensitive files
    /// - Clipboard / screen access
    /// - Existing policy violations
    pub fn data_exfiltration_risk(&self, app: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Factor 1: outbound bytes (log scale, cap contribution at 0.3)
        let total_sent: u64 = self
            .network_events
            .iter()
            .filter(|e| e.app_id == app)
            .map(|e| e.bytes_sent)
            .sum();
        if total_sent > 0 {
            // log10(bytes) / 10 capped at 0.3
            let byte_score = ((total_sent as f64).log10() / 10.0).min(0.3);
            score += byte_score;
        }

        // Factor 2: distinct remote hosts (0.05 per host, cap 0.2)
        let distinct_hosts: std::collections::HashSet<&str> = self
            .network_events
            .iter()
            .filter(|e| e.app_id == app)
            .map(|e| e.destination.as_str())
            .collect();
        score += (distinct_hosts.len() as f64 * 0.05).min(0.2);

        // Factor 3: sensitive file reads (0.05 per file, cap 0.2)
        let sensitive_reads = self
            .file_events
            .iter()
            .filter(|e| {
                e.app_id == app
                    && e.access_kind == FileAccessKind::Read
                    && (e.path.starts_with("/etc/")
                        || e.path.starts_with("/home/")
                        || e.path.contains("/.ssh/"))
            })
            .count();
        score += (sensitive_reads as f64 * 0.05).min(0.2);

        // Factor 4: clipboard access (+0.05)
        if self.clipboard_events.iter().any(|e| e.app_id == app) {
            score += 0.05;
        }

        // Factor 5: screen capture (+0.1)
        if self.screen_events.iter().any(|e| e.app_id == app) {
            score += 0.1;
        }

        // Factor 6: existing violations for this app (0.03 each, cap 0.15)
        let violation_count = self
            .violations
            .iter()
            .filter(|v| v.app_id == app)
            .count();
        score += (violation_count as f64 * 0.03).min(0.15);

        score.min(1.0)
    }
}

impl Default for DataFlowTracker {
    fn default() -> Self {
        Self::new(10_000)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers -----------------------------------------------------------

    fn make_event(app: &str, dt: DataType, dest: FlowDestination) -> DataFlowEvent {
        DataFlowEvent {
            app_id: app.into(),
            data_type: dt,
            destination: dest,
            bytes: 1024,
            timestamp: Utc::now(),
        }
    }

    fn file_read(app: &str, path: &str, size: u64) -> FileAccessEvent {
        FileAccessEvent {
            app_id: app.into(),
            path: path.into(),
            access_kind: FileAccessKind::Read,
            size_bytes: size,
            timestamp: Utc::now(),
        }
    }

    fn file_write(app: &str, path: &str, size: u64) -> FileAccessEvent {
        FileAccessEvent {
            app_id: app.into(),
            path: path.into(),
            access_kind: FileAccessKind::Write,
            size_bytes: size,
            timestamp: Utc::now(),
        }
    }

    fn net_event(app: &str, host: &str, port: u16, sent: u64, recv: u64) -> NetworkEvent {
        NetworkEvent {
            app_id: app.into(),
            destination: host.into(),
            port,
            bytes_sent: sent,
            bytes_received: recv,
            timestamp: Utc::now(),
        }
    }

    fn clip_event(app: &str) -> ClipboardEvent {
        ClipboardEvent {
            app_id: app.into(),
            access_kind: ClipboardAccessKind::Read,
            timestamp: Utc::now(),
        }
    }

    fn screen_event(app: &str) -> ScreenEvent {
        ScreenEvent {
            app_id: app.into(),
            capture_kind: ScreenCaptureKind::Screenshot,
            timestamp: Utc::now(),
        }
    }

    fn sample_policy(app: &str) -> DataFlowPolicy {
        DataFlowPolicy {
            app_id: app.into(),
            allowed_read_globs: vec!["/tmp/*".into(), "/home/user/docs/*".into()],
            allowed_write_globs: vec!["/tmp/*".into()],
            allowed_hosts: vec!["*.example.com".into(), "api.safe.io".into()],
            clipboard_allowed: false,
            screen_capture_allowed: false,
        }
    }

    // -- legacy tests (kept for backward compat) ---------------------------

    #[test]
    fn test_legacy_record_and_query() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record(make_event(
            "app1",
            DataType::Files,
            FlowDestination::LocalFile("/tmp/out".into()),
        ));
        tracker.record(make_event(
            "app1",
            DataType::Contacts,
            FlowDestination::Network("api.evil.com".into()),
        ));
        assert_eq!(tracker.flows_by_app("app1").len(), 2);
    }

    #[test]
    fn test_legacy_network_flows() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record(make_event(
            "a",
            DataType::Files,
            FlowDestination::Network("cdn.com".into()),
        ));
        tracker.record(make_event(
            "b",
            DataType::Files,
            FlowDestination::LocalFile("/tmp".into()),
        ));
        assert_eq!(tracker.network_flows().len(), 1);
    }

    #[test]
    fn test_legacy_eviction() {
        let mut tracker = DataFlowTracker::new(10);
        for i in 0..20 {
            tracker.record(make_event(
                &format!("app{i}"),
                DataType::Files,
                FlowDestination::Clipboard,
            ));
        }
        assert!(tracker.event_count() <= 10);
    }

    // -- new comprehensive tests -------------------------------------------

    #[test]
    fn test_file_policy_enforcement() {
        let mut tracker = DataFlowTracker::new(100);
        let mut ps = PolicySet::new(false);
        ps.add_policy(sample_policy("editor"));
        tracker.set_policies(ps);

        // Allowed read
        tracker.record_file_access(file_read("editor", "/tmp/scratch.txt", 100));
        assert!(tracker.violations().is_empty());

        // Denied read — /etc/shadow is not in allowed globs
        tracker.record_file_access(file_read("editor", "/etc/shadow", 64));
        assert_eq!(tracker.violations().len(), 1);
        assert_eq!(tracker.violations()[0].severity, ViolationSeverity::Critical);

        // Denied write — /home/user/docs is only in read globs
        tracker.record_file_access(file_write("editor", "/home/user/docs/secret.txt", 200));
        assert_eq!(tracker.violations().len(), 2);
    }

    #[test]
    fn test_network_policy_enforcement() {
        let mut tracker = DataFlowTracker::new(100);
        let mut ps = PolicySet::new(false);
        ps.add_policy(sample_policy("browser"));
        tracker.set_policies(ps);

        // Allowed host
        tracker.record_network(net_event("browser", "cdn.example.com", 443, 500, 2000));
        assert!(tracker.violations().is_empty());

        // Denied host
        tracker.record_network(net_event("browser", "evil.tracker.net", 80, 1000, 0));
        assert_eq!(tracker.violations().len(), 1);
        assert_eq!(tracker.violations()[0].action, "network_connect");
    }

    #[test]
    fn test_default_deny_blocks_unknown_app() {
        let mut tracker = DataFlowTracker::new(100);
        let ps = PolicySet::new(true); // default-deny, no per-app policies
        tracker.set_policies(ps);

        tracker.record_file_access(file_read("unknown_app", "/home/user/.bashrc", 32));
        tracker.record_network(net_event("unknown_app", "evil.com", 443, 100, 0));
        tracker.record_clipboard(clip_event("unknown_app"));
        tracker.record_screen(screen_event("unknown_app"));

        assert_eq!(tracker.violations().len(), 4);
    }

    #[test]
    fn test_clipboard_and_screen_policy() {
        let mut tracker = DataFlowTracker::new(100);
        let mut ps = PolicySet::new(false);
        ps.add_policy(sample_policy("malware")); // clipboard + screen denied
        tracker.set_policies(ps);

        tracker.record_clipboard(clip_event("malware"));
        assert_eq!(tracker.violations().len(), 1);
        assert_eq!(tracker.violations()[0].action, "clipboard_access");

        tracker.record_screen(screen_event("malware"));
        assert_eq!(tracker.violations().len(), 2);
        assert_eq!(tracker.violations()[1].action, "screen_capture");
    }

    #[test]
    fn test_top_senders() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record_network(net_event("big_sender", "cdn.com", 443, 50_000, 100));
        tracker.record_network(net_event("big_sender", "api.com", 443, 30_000, 200));
        tracker.record_network(net_event("small_sender", "api.com", 443, 500, 1000));

        let top = tracker.top_senders(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "big_sender");
        assert_eq!(top[0].1, 80_000);
        assert_eq!(top[1].0, "small_sender");
    }

    #[test]
    fn test_suspicious_flows_analytics() {
        let mut tracker = DataFlowTracker::new(100);

        // App reads sensitive file AND has network access  -> suspicious
        tracker.record_file_access(file_read("spy", "/etc/passwd", 200));
        tracker.record_network(net_event("spy", "exfil.bad.com", 443, 200, 0));

        // App reads sensitive file but NO network -> not suspicious
        tracker.record_file_access(file_read("offline_reader", "/home/user/diary.txt", 100));

        let suspicious = tracker.suspicious_flows();
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].app_id, "spy");
    }

    #[test]
    fn test_exfiltration_risk_score() {
        let mut tracker = DataFlowTracker::new(100);

        // Benign app — no activity
        assert!((tracker.data_exfiltration_risk("clean_app") - 0.0).abs() < f64::EPSILON);

        // Build up a risky profile for "spyware"
        tracker.record_file_access(file_read("spyware", "/etc/shadow", 64));
        tracker.record_file_access(file_read("spyware", "/home/user/.ssh/id_rsa", 1700));
        tracker.record_network(net_event("spyware", "c2.evil.com", 443, 100_000, 50));
        tracker.record_network(net_event("spyware", "backup.evil.com", 8080, 50_000, 10));
        tracker.record_clipboard(clip_event("spyware"));
        tracker.record_screen(screen_event("spyware"));

        let risk = tracker.data_exfiltration_risk("spyware");
        assert!(risk > 0.3, "expected high risk, got {risk}");
        assert!(risk <= 1.0);

        // Benign app with only a small local read
        tracker.record_file_access(file_read("notepad", "/tmp/notes.txt", 50));
        let safe_risk = tracker.data_exfiltration_risk("notepad");
        assert!(
            safe_risk < risk,
            "notepad risk ({safe_risk}) should be less than spyware ({risk})"
        );
    }

    #[test]
    fn test_glob_matching() {
        assert!(glob_matches("/tmp/*", "/tmp/foo.txt"));
        assert!(glob_matches("/tmp/*", "/tmp/bar"));
        assert!(!glob_matches("/tmp/*", "/etc/foo"));
        assert!(glob_matches("*.example.com", "cdn.example.com"));
        assert!(glob_matches("*.example.com", "sub.example.com"));
        assert!(!glob_matches("*.example.com", "evil.com"));
        assert!(glob_matches("file?.txt", "file1.txt"));
        assert!(!glob_matches("file?.txt", "file10.txt"));
    }
}
