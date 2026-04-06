//! Data attribution — track which app touched which file last.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Attribution record for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionRecord {
    pub path: PathBuf,
    pub last_writer: String,
    pub last_reader: String,
    pub creator: String,
    pub created_at: DateTime<Utc>,
    pub last_written: DateTime<Utc>,
    pub last_read: DateTime<Utc>,
    pub write_count: u64,
    pub read_count: u64,
    pub all_writers: Vec<String>,
    pub all_readers: Vec<String>,
}

/// Data attribution tracker.
pub struct AttributionTracker {
    records: HashMap<PathBuf, AttributionRecord>,
}

impl AttributionTracker {
    pub fn new() -> Self {
        Self { records: HashMap::new() }
    }

    /// Record a file write.
    pub fn record_write(&mut self, path: PathBuf, writer: &str) {
        let now = Utc::now();
        let record = self.records.entry(path.clone()).or_insert_with(|| AttributionRecord {
            path: path.clone(),
            last_writer: writer.into(),
            last_reader: writer.into(),
            creator: writer.into(),
            created_at: now,
            last_written: now,
            last_read: now,
            write_count: 0,
            read_count: 0,
            all_writers: Vec::new(),
            all_readers: Vec::new(),
        });
        record.last_writer = writer.into();
        record.last_written = now;
        record.write_count += 1;
        if !record.all_writers.contains(&writer.to_string()) {
            record.all_writers.push(writer.into());
        }
    }

    /// Record a file read.
    pub fn record_read(&mut self, path: PathBuf, reader: &str) {
        let now = Utc::now();
        if let Some(record) = self.records.get_mut(&path) {
            record.last_reader = reader.into();
            record.last_read = now;
            record.read_count += 1;
            if !record.all_readers.contains(&reader.to_string()) {
                record.all_readers.push(reader.into());
            }
        }
    }

    /// Get attribution for a file.
    pub fn get(&self, path: &PathBuf) -> Option<&AttributionRecord> {
        self.records.get(path)
    }

    /// Find files written by a specific app.
    pub fn files_by_writer(&self, writer: &str) -> Vec<&AttributionRecord> {
        self.records.values()
            .filter(|r| r.all_writers.iter().any(|w| w == writer))
            .collect()
    }

    /// Find files read by a specific app.
    pub fn files_by_reader(&self, reader: &str) -> Vec<&AttributionRecord> {
        self.records.values()
            .filter(|r| r.all_readers.iter().any(|w| w == reader))
            .collect()
    }

    /// Find files with shared access (multiple writers/readers).
    pub fn shared_files(&self) -> Vec<&AttributionRecord> {
        self.records.values()
            .filter(|r| r.all_writers.len() > 1 || r.all_readers.len() > 1)
            .collect()
    }

    pub fn record_count(&self) -> usize { self.records.len() }
}

impl Default for AttributionTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_write() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/etc/test"), "firefox");
        let r = tracker.get(&PathBuf::from("/etc/test")).unwrap();
        assert_eq!(r.last_writer, "firefox");
        assert_eq!(r.creator, "firefox");
        assert_eq!(r.write_count, 1);
    }

    #[test]
    fn test_record_read() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/file"), "firefox");
        tracker.record_read(PathBuf::from("/file"), "vim");
        let r = tracker.get(&PathBuf::from("/file")).unwrap();
        assert_eq!(r.last_reader, "vim");
    }

    #[test]
    fn test_creator_unchanged() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/file"), "firefox");
        tracker.record_write(PathBuf::from("/file"), "vim");
        let r = tracker.get(&PathBuf::from("/file")).unwrap();
        assert_eq!(r.creator, "firefox");
        assert_eq!(r.last_writer, "vim");
    }

    #[test]
    fn test_files_by_writer() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/a"), "firefox");
        tracker.record_write(PathBuf::from("/b"), "firefox");
        tracker.record_write(PathBuf::from("/c"), "vim");
        assert_eq!(tracker.files_by_writer("firefox").len(), 2);
    }

    #[test]
    fn test_shared_files() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/shared"), "firefox");
        tracker.record_write(PathBuf::from("/shared"), "vim");
        tracker.record_write(PathBuf::from("/private"), "firefox");
        assert_eq!(tracker.shared_files().len(), 1);
    }

    #[test]
    fn test_write_count() {
        let mut tracker = AttributionTracker::new();
        for _ in 0..5 {
            tracker.record_write(PathBuf::from("/file"), "firefox");
        }
        assert_eq!(tracker.get(&PathBuf::from("/file")).unwrap().write_count, 5);
    }

    #[test]
    fn test_record_count() {
        let mut tracker = AttributionTracker::new();
        tracker.record_write(PathBuf::from("/a"), "firefox");
        tracker.record_write(PathBuf::from("/b"), "vim");
        assert_eq!(tracker.record_count(), 2);
    }
}
