//! Data flow tracking — monitors where app data goes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEvent {
    pub app_id: String,
    pub data_type: DataType,
    pub destination: FlowDestination,
    pub bytes: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType { Contacts, Photos, Location, Messages, Files, Clipboard, Keystrokes }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowDestination { LocalFile(String), Network(String), Clipboard, SystemService(String) }

pub struct DataFlowTracker {
    events: Vec<DataFlowEvent>,
    max_events: usize,
}

impl DataFlowTracker {
    pub fn new(max_events: usize) -> Self { Self { events: Vec::new(), max_events } }

    pub fn record(&mut self, event: DataFlowEvent) {
        self.events.push(event);
        if self.events.len() > self.max_events { self.events.drain(..self.max_events / 2); }
    }

    pub fn flows_by_app(&self, app_id: &str) -> Vec<&DataFlowEvent> {
        self.events.iter().filter(|e| e.app_id == app_id).collect()
    }

    pub fn network_flows(&self) -> Vec<&DataFlowEvent> {
        self.events.iter().filter(|e| matches!(e.destination, FlowDestination::Network(_))).collect()
    }

    pub fn suspicious_flows(&self) -> Vec<&DataFlowEvent> {
        self.events.iter().filter(|e| {
            matches!(e.data_type, DataType::Contacts | DataType::Location | DataType::Keystrokes)
                && matches!(e.destination, FlowDestination::Network(_))
        }).collect()
    }

    pub fn total_bytes_by_app(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for e in &self.events { *map.entry(e.app_id.clone()).or_default() += e.bytes; }
        map
    }

    pub fn event_count(&self) -> usize { self.events.len() }
}

impl Default for DataFlowTracker { fn default() -> Self { Self::new(10000) } }

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(app: &str, dt: DataType, dest: FlowDestination) -> DataFlowEvent {
        DataFlowEvent { app_id: app.into(), data_type: dt, destination: dest, bytes: 1024, timestamp: Utc::now() }
    }

    #[test]
    fn test_record_and_query() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record(make_event("app1", DataType::Files, FlowDestination::LocalFile("/tmp/out".into())));
        tracker.record(make_event("app1", DataType::Contacts, FlowDestination::Network("api.evil.com".into())));
        assert_eq!(tracker.flows_by_app("app1").len(), 2);
    }

    #[test]
    fn test_suspicious_detection() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record(make_event("spy", DataType::Location, FlowDestination::Network("tracker.com".into())));
        tracker.record(make_event("safe", DataType::Files, FlowDestination::LocalFile("/tmp".into())));
        assert_eq!(tracker.suspicious_flows().len(), 1);
    }

    #[test]
    fn test_network_flows() {
        let mut tracker = DataFlowTracker::new(100);
        tracker.record(make_event("a", DataType::Files, FlowDestination::Network("cdn.com".into())));
        tracker.record(make_event("b", DataType::Files, FlowDestination::LocalFile("/tmp".into())));
        assert_eq!(tracker.network_flows().len(), 1);
    }

    #[test]
    fn test_eviction() {
        let mut tracker = DataFlowTracker::new(10);
        for i in 0..20 { tracker.record(make_event(&format!("app{i}"), DataType::Files, FlowDestination::Clipboard)); }
        assert!(tracker.event_count() <= 10);
    }
}
