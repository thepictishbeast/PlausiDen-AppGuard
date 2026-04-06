//! Certificate tracker — monitor X.509 certificates used by applications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tracked certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub serial: String,
    pub algorithm: String,
    pub key_bits: u32,
    pub san: Vec<String>,
    pub ca: bool,
    pub pinned_for: Vec<String>, // app_ids that have pinned this cert
}

impl Certificate {
    /// Is the certificate currently valid?
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Days until expiry.
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - Utc::now()).num_days()
    }

    /// Is it expired?
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Is it expiring soon (within N days)?
    pub fn expiring_soon(&self, days: i64) -> bool {
        let remaining = self.days_until_expiry();
        remaining >= 0 && remaining <= days
    }

    /// Is it a weak key?
    pub fn has_weak_key(&self) -> bool {
        match self.algorithm.to_lowercase().as_str() {
            "rsa" => self.key_bits < 2048,
            "ecdsa" => self.key_bits < 256,
            _ => false,
        }
    }
}

/// Per-app certificate usage record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertUsage {
    pub app_id: String,
    pub fingerprint: String,
    pub host: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: u64,
}

/// Certificate tracker.
pub struct CertTracker {
    certs: HashMap<String, Certificate>, // fingerprint → cert
    usage: Vec<CertUsage>,
    usage_limit: usize,
}

impl CertTracker {
    pub fn new() -> Self {
        Self {
            certs: HashMap::new(),
            usage: Vec::new(),
            usage_limit: 10_000,
        }
    }

    /// Register a certificate.
    pub fn register(&mut self, cert: Certificate) {
        self.certs.insert(cert.fingerprint.clone(), cert);
    }

    /// Pin a cert for a specific app.
    pub fn pin(&mut self, fingerprint: &str, app_id: &str) -> bool {
        if let Some(cert) = self.certs.get_mut(fingerprint) {
            if !cert.pinned_for.iter().any(|a| a == app_id) {
                cert.pinned_for.push(app_id.into());
            }
            return true;
        }
        false
    }

    /// Record that an app observed a cert.
    pub fn record_usage(&mut self, app_id: &str, fingerprint: &str, host: &str) {
        let now = Utc::now();
        if let Some(existing) = self.usage.iter_mut().find(|u|
            u.app_id == app_id && u.fingerprint == fingerprint && u.host == host
        ) {
            existing.last_seen = now;
            existing.seen_count += 1;
        } else {
            self.usage.push(CertUsage {
                app_id: app_id.into(),
                fingerprint: fingerprint.into(),
                host: host.into(),
                first_seen: now,
                last_seen: now,
                seen_count: 1,
            });
        }
        if self.usage.len() > self.usage_limit {
            self.usage.remove(0);
        }
    }

    /// Check if the observed certificate matches a pinned cert for the app.
    pub fn check_pinning(&self, app_id: &str, fingerprint: &str) -> PinningResult {
        let pinned: Vec<&String> = self.certs.values()
            .filter(|c| c.pinned_for.iter().any(|a| a == app_id))
            .map(|c| &c.fingerprint)
            .collect();
        if pinned.is_empty() {
            return PinningResult::NoPin;
        }
        if pinned.iter().any(|f| *f == fingerprint) {
            PinningResult::PinMatch
        } else {
            PinningResult::PinViolation
        }
    }

    /// Get a certificate by fingerprint.
    pub fn get(&self, fingerprint: &str) -> Option<&Certificate> {
        self.certs.get(fingerprint)
    }

    /// Certificates expiring within N days.
    pub fn expiring_within(&self, days: i64) -> Vec<&Certificate> {
        self.certs.values().filter(|c| c.expiring_soon(days)).collect()
    }

    /// Expired certificates.
    pub fn expired(&self) -> Vec<&Certificate> {
        self.certs.values().filter(|c| c.is_expired()).collect()
    }

    /// Certs with weak keys.
    pub fn weak_keys(&self) -> Vec<&Certificate> {
        self.certs.values().filter(|c| c.has_weak_key()).collect()
    }

    /// CAs.
    pub fn cas(&self) -> Vec<&Certificate> {
        self.certs.values().filter(|c| c.ca).collect()
    }

    /// Usage records for an app.
    pub fn usage_for_app(&self, app_id: &str) -> Vec<&CertUsage> {
        self.usage.iter().filter(|u| u.app_id == app_id).collect()
    }

    pub fn cert_count(&self) -> usize { self.certs.len() }
    pub fn usage_count(&self) -> usize { self.usage.len() }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinningResult {
    NoPin,
    PinMatch,
    PinViolation,
}

impl Default for CertTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(fp: &str, subject: &str, days_until_expiry: i64, algorithm: &str, key_bits: u32) -> Certificate {
        Certificate {
            fingerprint: fp.into(),
            subject: subject.into(),
            issuer: "CA".into(),
            not_before: Utc::now() - chrono::Duration::days(1),
            not_after: Utc::now() + chrono::Duration::days(days_until_expiry),
            serial: "001".into(),
            algorithm: algorithm.into(),
            key_bits,
            san: vec![],
            ca: false,
            pinned_for: vec![],
        }
    }

    #[test]
    fn test_is_valid() {
        let c = cert("abc", "example.com", 30, "rsa", 2048);
        assert!(c.is_valid());
    }

    #[test]
    fn test_is_expired() {
        let c = cert("abc", "example.com", -1, "rsa", 2048);
        assert!(c.is_expired());
    }

    #[test]
    fn test_expiring_soon() {
        let c = cert("abc", "example.com", 5, "rsa", 2048);
        assert!(c.expiring_soon(10));
    }

    #[test]
    fn test_weak_key_rsa() {
        let c = cert("abc", "example.com", 30, "rsa", 1024);
        assert!(c.has_weak_key());
    }

    #[test]
    fn test_weak_key_ecdsa() {
        let c = cert("abc", "example.com", 30, "ecdsa", 192);
        assert!(c.has_weak_key());
    }

    #[test]
    fn test_register_and_get() {
        let mut t = CertTracker::new();
        t.register(cert("abc", "example.com", 30, "rsa", 2048));
        assert!(t.get("abc").is_some());
    }

    #[test]
    fn test_pin_and_check() {
        let mut t = CertTracker::new();
        t.register(cert("abc", "example.com", 30, "rsa", 2048));
        t.pin("abc", "firefox");
        assert_eq!(t.check_pinning("firefox", "abc"), PinningResult::PinMatch);
        assert_eq!(t.check_pinning("firefox", "xyz"), PinningResult::PinViolation);
    }

    #[test]
    fn test_no_pin() {
        let t = CertTracker::new();
        assert_eq!(t.check_pinning("firefox", "abc"), PinningResult::NoPin);
    }

    #[test]
    fn test_expiring_within() {
        let mut t = CertTracker::new();
        t.register(cert("a", "a.com", 5, "rsa", 2048));
        t.register(cert("b", "b.com", 100, "rsa", 2048));
        assert_eq!(t.expiring_within(10).len(), 1);
    }

    #[test]
    fn test_weak_keys_list() {
        let mut t = CertTracker::new();
        t.register(cert("a", "a.com", 30, "rsa", 1024));
        t.register(cert("b", "b.com", 30, "rsa", 2048));
        assert_eq!(t.weak_keys().len(), 1);
    }

    #[test]
    fn test_record_usage() {
        let mut t = CertTracker::new();
        t.record_usage("firefox", "abc", "example.com");
        t.record_usage("firefox", "abc", "example.com");
        assert_eq!(t.usage_for_app("firefox")[0].seen_count, 2);
    }
}
