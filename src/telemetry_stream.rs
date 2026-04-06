//! Telemetry stream — aggregate per-app metrics into a stream for live dashboards.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// A single telemetry data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Datapoint {
    pub app_id: String,
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: DateTime<Utc>,
}

/// Per-app per-metric series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Series {
    pub app_id: String,
    pub metric: String,
    pub points: VecDeque<(DateTime<Utc>, f64)>,
    pub capacity: usize,
    pub unit: String,
}

impl Series {
    pub fn new(app_id: &str, metric: &str, capacity: usize) -> Self {
        Self {
            app_id: app_id.into(),
            metric: metric.into(),
            points: VecDeque::with_capacity(capacity),
            capacity,
            unit: String::new(),
        }
    }

    pub fn push(&mut self, ts: DateTime<Utc>, value: f64) {
        if self.points.len() == self.capacity {
            self.points.pop_front();
        }
        self.points.push_back((ts, value));
    }

    pub fn latest(&self) -> Option<f64> {
        self.points.back().map(|(_, v)| *v)
    }

    pub fn oldest(&self) -> Option<f64> {
        self.points.front().map(|(_, v)| *v)
    }

    pub fn min(&self) -> Option<f64> {
        self.points.iter().map(|(_, v)| *v).fold(None, |acc, v| {
            Some(match acc { None => v, Some(a) => a.min(v) })
        })
    }

    pub fn max(&self) -> Option<f64> {
        self.points.iter().map(|(_, v)| *v).fold(None, |acc, v| {
            Some(match acc { None => v, Some(a) => a.max(v) })
        })
    }

    pub fn avg(&self) -> Option<f64> {
        if self.points.is_empty() { return None; }
        let sum: f64 = self.points.iter().map(|(_, v)| *v).sum();
        Some(sum / self.points.len() as f64)
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    pub fn trend(&self) -> Option<Trend> {
        if self.points.len() < 2 { return None; }
        let recent: Vec<f64> = self.points.iter().rev().take(5).map(|(_, v)| *v).collect();
        let older: Vec<f64> = self.points.iter().rev().skip(5).take(5).map(|(_, v)| *v).collect();
        if recent.is_empty() || older.is_empty() { return None; }
        let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
        let older_avg = older.iter().sum::<f64>() / older.len() as f64;
        if (recent_avg - older_avg).abs() < older_avg * 0.05 {
            Some(Trend::Flat)
        } else if recent_avg > older_avg {
            Some(Trend::Rising)
        } else {
            Some(Trend::Falling)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Rising,
    Falling,
    Flat,
}

/// Telemetry stream manager.
pub struct TelemetryStream {
    series: HashMap<String, Series>, // key: "app_id:metric"
    capacity_per_series: usize,
    total_datapoints: u64,
}

impl TelemetryStream {
    pub fn new(capacity_per_series: usize) -> Self {
        Self {
            series: HashMap::new(),
            capacity_per_series,
            total_datapoints: 0,
        }
    }

    fn key(app_id: &str, metric: &str) -> String {
        format!("{}:{}", app_id, metric)
    }

    /// Push a datapoint.
    pub fn push(&mut self, dp: Datapoint) {
        let key = Self::key(&dp.app_id, &dp.metric);
        let series = self.series.entry(key).or_insert_with(|| {
            let mut s = Series::new(&dp.app_id, &dp.metric, self.capacity_per_series);
            s.unit = dp.unit.clone();
            s
        });
        series.push(dp.timestamp, dp.value);
        self.total_datapoints += 1;
    }

    /// Get a series.
    pub fn get(&self, app_id: &str, metric: &str) -> Option<&Series> {
        self.series.get(&Self::key(app_id, metric))
    }

    /// All series for an app.
    pub fn series_for(&self, app_id: &str) -> Vec<&Series> {
        self.series.values().filter(|s| s.app_id == app_id).collect()
    }

    /// All series for a metric.
    pub fn series_by_metric(&self, metric: &str) -> Vec<&Series> {
        self.series.values().filter(|s| s.metric == metric).collect()
    }

    /// Apps showing a specific trend.
    pub fn apps_with_trend(&self, metric: &str, trend: &Trend) -> Vec<String> {
        self.series.values()
            .filter(|s| s.metric == metric)
            .filter(|s| s.trend().as_ref() == Some(trend))
            .map(|s| s.app_id.clone())
            .collect()
    }

    pub fn series_count(&self) -> usize { self.series.len() }
    pub fn total_datapoints(&self) -> u64 { self.total_datapoints }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dp(app: &str, metric: &str, value: f64) -> Datapoint {
        Datapoint {
            app_id: app.into(),
            metric: metric.into(),
            value,
            unit: "%".into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_push_and_get() {
        let mut s = TelemetryStream::new(100);
        s.push(dp("firefox", "cpu", 25.5));
        let series = s.get("firefox", "cpu").unwrap();
        assert_eq!(series.latest(), Some(25.5));
    }

    #[test]
    fn test_capacity_eviction() {
        let mut s = TelemetryStream::new(3);
        for i in 0..5 {
            s.push(dp("firefox", "cpu", i as f64));
        }
        assert_eq!(s.get("firefox", "cpu").unwrap().len(), 3);
    }

    #[test]
    fn test_min_max_avg() {
        let mut s = TelemetryStream::new(100);
        s.push(dp("a", "m", 10.0));
        s.push(dp("a", "m", 20.0));
        s.push(dp("a", "m", 30.0));
        let series = s.get("a", "m").unwrap();
        assert_eq!(series.min(), Some(10.0));
        assert_eq!(series.max(), Some(30.0));
        assert_eq!(series.avg(), Some(20.0));
    }

    #[test]
    fn test_series_for_app() {
        let mut s = TelemetryStream::new(100);
        s.push(dp("a", "cpu", 10.0));
        s.push(dp("a", "memory", 100.0));
        s.push(dp("b", "cpu", 20.0));
        assert_eq!(s.series_for("a").len(), 2);
    }

    #[test]
    fn test_series_by_metric() {
        let mut s = TelemetryStream::new(100);
        s.push(dp("a", "cpu", 10.0));
        s.push(dp("b", "cpu", 20.0));
        s.push(dp("c", "memory", 100.0));
        assert_eq!(s.series_by_metric("cpu").len(), 2);
    }

    #[test]
    fn test_trend_rising() {
        let mut s = TelemetryStream::new(100);
        for i in 0..10 {
            s.push(dp("a", "cpu", i as f64 * 2.0));
        }
        assert_eq!(s.get("a", "cpu").unwrap().trend(), Some(Trend::Rising));
    }

    #[test]
    fn test_trend_falling() {
        let mut s = TelemetryStream::new(100);
        for i in 0..10 {
            s.push(dp("a", "cpu", 100.0 - i as f64 * 5.0));
        }
        assert_eq!(s.get("a", "cpu").unwrap().trend(), Some(Trend::Falling));
    }

    #[test]
    fn test_apps_with_trend() {
        let mut s = TelemetryStream::new(100);
        for i in 0..10 {
            s.push(dp("hot", "cpu", i as f64 * 5.0));
            s.push(dp("cold", "cpu", 50.0));
        }
        let rising = s.apps_with_trend("cpu", &Trend::Rising);
        assert!(rising.contains(&"hot".to_string()));
    }

    #[test]
    fn test_total_datapoints() {
        let mut s = TelemetryStream::new(100);
        s.push(dp("a", "m", 1.0));
        s.push(dp("b", "m", 2.0));
        assert_eq!(s.total_datapoints(), 2);
    }
}
