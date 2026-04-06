//! Launch counter — per-app launch frequency and cadence tracking.

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single launch event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchEvent {
    pub app_id: String,
    pub timestamp: DateTime<Utc>,
    pub from_autostart: bool,
}

/// Per-app launch statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchStats {
    pub app_id: String,
    pub total_launches: u64,
    pub first_launch: DateTime<Utc>,
    pub last_launch: DateTime<Utc>,
    pub by_weekday: HashMap<Weekday, u32>,
    pub by_hour: [u32; 24],
    pub autostart_launches: u64,
}

impl LaunchStats {
    pub fn new(event: &LaunchEvent) -> Self {
        let mut by_hour = [0u32; 24];
        by_hour[event.timestamp.hour() as usize] = 1;
        let mut by_weekday = HashMap::new();
        by_weekday.insert(event.timestamp.weekday(), 1);
        Self {
            app_id: event.app_id.clone(),
            total_launches: 1,
            first_launch: event.timestamp,
            last_launch: event.timestamp,
            by_weekday,
            by_hour,
            autostart_launches: if event.from_autostart { 1 } else { 0 },
        }
    }

    pub fn record(&mut self, event: &LaunchEvent) {
        self.total_launches += 1;
        if event.timestamp > self.last_launch {
            self.last_launch = event.timestamp;
        }
        if event.timestamp < self.first_launch {
            self.first_launch = event.timestamp;
        }
        self.by_hour[event.timestamp.hour() as usize] += 1;
        *self.by_weekday.entry(event.timestamp.weekday()).or_insert(0) += 1;
        if event.from_autostart {
            self.autostart_launches += 1;
        }
    }

    /// Peak hour of day.
    pub fn peak_hour(&self) -> usize {
        let (peak, _) = self.by_hour.iter().enumerate()
            .max_by_key(|(_, v)| **v).unwrap_or((0, &0));
        peak
    }

    /// Average launches per day since first_launch.
    pub fn average_per_day(&self) -> f64 {
        let days = (Utc::now() - self.first_launch).num_days().max(1);
        self.total_launches as f64 / days as f64
    }

    /// Is the app used mostly on weekdays?
    pub fn is_work_app(&self) -> bool {
        let weekday: u32 = [Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri]
            .iter().map(|d| self.by_weekday.get(d).copied().unwrap_or(0)).sum();
        let weekend: u32 = [Weekday::Sat, Weekday::Sun]
            .iter().map(|d| self.by_weekday.get(d).copied().unwrap_or(0)).sum();
        weekday > weekend * 2
    }
}

/// Launch counter — tracks multiple apps.
pub struct LaunchCounter {
    stats: HashMap<String, LaunchStats>,
    events: Vec<LaunchEvent>,
    history_limit: usize,
}

impl LaunchCounter {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            events: Vec::new(),
            history_limit: 10_000,
        }
    }

    /// Record a launch.
    pub fn record(&mut self, event: LaunchEvent) {
        match self.stats.get_mut(&event.app_id) {
            Some(s) => s.record(&event),
            None => {
                self.stats.insert(event.app_id.clone(), LaunchStats::new(&event));
            }
        }
        self.events.push(event);
        if self.events.len() > self.history_limit {
            self.events.remove(0);
        }
    }

    /// Stats for a specific app.
    pub fn stats_for(&self, app_id: &str) -> Option<&LaunchStats> {
        self.stats.get(app_id)
    }

    /// Top N apps by total launches.
    pub fn top_apps(&self, n: usize) -> Vec<&LaunchStats> {
        let mut ranked: Vec<&LaunchStats> = self.stats.values().collect();
        ranked.sort_by(|a, b| b.total_launches.cmp(&a.total_launches));
        ranked.truncate(n);
        ranked
    }

    /// Apps that launch automatically at login.
    pub fn autostart_apps(&self) -> Vec<&LaunchStats> {
        self.stats.values().filter(|s| s.autostart_launches > 0).collect()
    }

    /// Apps not launched in N days.
    pub fn dormant_apps(&self, days: i64) -> Vec<&LaunchStats> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        self.stats.values().filter(|s| s.last_launch < cutoff).collect()
    }

    /// Work apps (heavy weekday usage).
    pub fn work_apps(&self) -> Vec<&LaunchStats> {
        self.stats.values().filter(|s| s.is_work_app()).collect()
    }

    /// Total apps tracked.
    pub fn app_count(&self) -> usize {
        self.stats.len()
    }

    /// Total launch events recorded.
    pub fn total_events(&self) -> usize {
        self.events.len()
    }
}

impl Default for LaunchCounter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(app: &str) -> LaunchEvent {
        LaunchEvent {
            app_id: app.into(),
            timestamp: Utc::now(),
            from_autostart: false,
        }
    }

    #[test]
    fn test_record_first_launch() {
        let mut c = LaunchCounter::new();
        c.record(launch("firefox"));
        assert_eq!(c.stats_for("firefox").unwrap().total_launches, 1);
    }

    #[test]
    fn test_record_multiple() {
        let mut c = LaunchCounter::new();
        for _ in 0..5 { c.record(launch("firefox")); }
        assert_eq!(c.stats_for("firefox").unwrap().total_launches, 5);
    }

    #[test]
    fn test_top_apps() {
        let mut c = LaunchCounter::new();
        for _ in 0..10 { c.record(launch("firefox")); }
        for _ in 0..5 { c.record(launch("chrome")); }
        for _ in 0..2 { c.record(launch("vim")); }
        let top = c.top_apps(2);
        assert_eq!(top[0].app_id, "firefox");
        assert_eq!(top[1].app_id, "chrome");
    }

    #[test]
    fn test_autostart_filter() {
        let mut c = LaunchCounter::new();
        let mut auto = launch("daemon");
        auto.from_autostart = true;
        c.record(auto);
        c.record(launch("firefox"));
        assert_eq!(c.autostart_apps().len(), 1);
    }

    #[test]
    fn test_app_count() {
        let mut c = LaunchCounter::new();
        c.record(launch("a"));
        c.record(launch("b"));
        c.record(launch("a"));
        assert_eq!(c.app_count(), 2);
    }

    #[test]
    fn test_dormant_apps() {
        let mut c = LaunchCounter::new();
        let mut old = launch("ancient");
        old.timestamp = Utc::now() - chrono::Duration::days(60);
        c.record(old);
        c.record(launch("current"));
        let dormant = c.dormant_apps(30);
        assert_eq!(dormant.len(), 1);
        assert_eq!(dormant[0].app_id, "ancient");
    }

    #[test]
    fn test_peak_hour() {
        let mut c = LaunchCounter::new();
        c.record(launch("app"));
        let stats = c.stats_for("app").unwrap();
        assert!(stats.peak_hour() < 24);
    }

    #[test]
    fn test_average_per_day() {
        let mut c = LaunchCounter::new();
        let mut first = launch("app");
        first.timestamp = Utc::now() - chrono::Duration::days(2);
        c.record(first);
        c.record(launch("app"));
        let avg = c.stats_for("app").unwrap().average_per_day();
        assert!(avg > 0.0);
    }

    #[test]
    fn test_total_events() {
        let mut c = LaunchCounter::new();
        c.record(launch("a"));
        c.record(launch("b"));
        assert_eq!(c.total_events(), 2);
    }
}
