//! Per-application network ACL — enforce app-level egress/ingress allow-lists.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// A network ACL rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub app_id: String,
    pub direction: Direction,
    pub action: Action,
    pub target: Target,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Egress,
    Ingress,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    AnyAddress,
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
    Domain(String),
    Port(u16),
    PortRange(u16, u16),
}

/// Result of an ACL check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclDecision {
    Allowed,
    Denied,
    Logged,
    DefaultDeny, // no matching rule, default-deny policy
}

/// Per-app network ACL engine.
pub struct NetworkAcl {
    rules: Vec<AclRule>,
    default_action: Action,
    hit_counts: HashMap<String, u64>, // rule_id → count
}

impl NetworkAcl {
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
            hit_counts: HashMap::new(),
        }
    }

    /// Default-deny is the recommended posture.
    pub fn default_deny() -> Self { Self::new(Action::Deny) }

    /// Default-allow for testing.
    pub fn default_allow() -> Self { Self::new(Action::Allow) }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: AclRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() != before
    }

    /// Enable or disable a rule.
    pub fn set_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            r.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Check whether an app's connection is permitted.
    pub fn check(&mut self, app_id: &str, direction: &Direction, addr: &IpAddr, port: u16)
        -> AclDecision
    {
        for rule in &self.rules {
            if !rule.enabled { continue; }
            if rule.app_id != app_id { continue; }
            if !direction_matches(&rule.direction, direction) { continue; }
            if !target_matches(&rule.target, addr, port) { continue; }

            *self.hit_counts.entry(rule.id.clone()).or_insert(0) += 1;

            return match rule.action {
                Action::Allow => AclDecision::Allowed,
                Action::Deny => AclDecision::Denied,
                Action::Log => AclDecision::Logged,
            };
        }
        match self.default_action {
            Action::Allow => AclDecision::Allowed,
            Action::Deny => AclDecision::DefaultDeny,
            Action::Log => AclDecision::Logged,
        }
    }

    /// All rules for a given app, in priority order.
    pub fn rules_for(&self, app_id: &str) -> Vec<&AclRule> {
        self.rules.iter().filter(|r| r.app_id == app_id).collect()
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }

    pub fn hit_count(&self, rule_id: &str) -> u64 {
        *self.hit_counts.get(rule_id).unwrap_or(&0)
    }

    /// Rules that have never been hit — candidates for removal.
    pub fn unused_rules(&self) -> Vec<&AclRule> {
        self.rules.iter()
            .filter(|r| !self.hit_counts.contains_key(&r.id))
            .collect()
    }
}

fn direction_matches(rule_dir: &Direction, actual: &Direction) -> bool {
    matches!(rule_dir, Direction::Both)
        || rule_dir == actual
}

fn target_matches(target: &Target, addr: &IpAddr, port: u16) -> bool {
    match target {
        Target::AnyAddress => true,
        Target::Ip(ip) => ip == addr,
        Target::Cidr { network, prefix } => cidr_matches(network, *prefix, addr),
        Target::Port(p) => *p == port,
        Target::PortRange(start, end) => port >= *start && port <= *end,
        Target::Domain(_) => false, // needs resolver integration
    }
}

fn cidr_matches(network: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
    match (network, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            (u32::from(*n) & mask) == (u32::from(*a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let nb = n.octets();
            let ab = a.octets();
            let bytes_full = prefix / 8;
            let bits_remain = prefix % 8;
            for i in 0..bytes_full as usize {
                if nb[i] != ab[i] { return false; }
            }
            if bits_remain > 0 {
                let mask = 0xffu8 << (8 - bits_remain);
                if (nb[bytes_full as usize] & mask) != (ab[bytes_full as usize] & mask) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    fn rule(id: &str, app: &str, action: Action, target: Target, prio: i32) -> AclRule {
        AclRule {
            id: id.into(),
            app_id: app.into(),
            direction: Direction::Egress,
            action,
            target,
            priority: prio,
            enabled: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_default_deny_rejects_unmatched() {
        let mut acl = NetworkAcl::default_deny();
        let dec = acl.check("firefox", &Direction::Egress, &ip("1.2.3.4"), 443);
        assert_eq!(dec, AclDecision::DefaultDeny);
    }

    #[test]
    fn test_allow_rule() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "firefox", Action::Allow, Target::AnyAddress, 10));
        let dec = acl.check("firefox", &Direction::Egress, &ip("1.2.3.4"), 443);
        assert_eq!(dec, AclDecision::Allowed);
    }

    #[test]
    fn test_deny_higher_priority_wins() {
        let mut acl = NetworkAcl::default_allow();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::AnyAddress, 5));
        acl.add_rule(rule("r2", "app", Action::Deny, Target::Ip(ip("1.2.3.4")), 10));
        let dec = acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 80);
        assert_eq!(dec, AclDecision::Denied);
    }

    #[test]
    fn test_port_match() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::Port(443), 10));
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 443),
            AclDecision::Allowed
        );
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 80),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn test_port_range() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::PortRange(8000, 9000), 10));
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 8080),
            AclDecision::Allowed
        );
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 7999),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn test_cidr_v4() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow,
            Target::Cidr { network: ip("192.168.0.0"), prefix: 16 }, 10));
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("192.168.1.5"), 80),
            AclDecision::Allowed
        );
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("10.0.0.1"), 80),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn test_per_app_isolation() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "firefox", Action::Allow, Target::AnyAddress, 10));
        // Chrome not allowed.
        assert_eq!(
            acl.check("chrome", &Direction::Egress, &ip("1.2.3.4"), 80),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn test_disabled_rule_ignored() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::AnyAddress, 10));
        acl.set_enabled("r1", false);
        assert_eq!(
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 80),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn test_hit_counts() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::AnyAddress, 10));
        for _ in 0..3 {
            acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 80);
        }
        assert_eq!(acl.hit_count("r1"), 3);
    }

    #[test]
    fn test_unused_rules() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::AnyAddress, 10));
        acl.add_rule(rule("r2", "other", Action::Allow, Target::AnyAddress, 10));
        acl.check("app", &Direction::Egress, &ip("1.2.3.4"), 80);
        assert_eq!(acl.unused_rules().len(), 1);
    }

    #[test]
    fn test_remove_rule() {
        let mut acl = NetworkAcl::default_deny();
        acl.add_rule(rule("r1", "app", Action::Allow, Target::AnyAddress, 10));
        assert!(acl.remove_rule("r1"));
        assert_eq!(acl.rule_count(), 0);
    }
}
