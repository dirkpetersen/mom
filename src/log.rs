use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use syslog::{Facility, Formatter3164};

#[derive(Serialize, Clone)]
pub struct Entry {
    pub timestamp: String,
    pub real_uid: u32,
    pub real_user: String,
    pub operation: String,
    pub packages: Vec<String>,
    pub outcome: String,
    pub detail: Option<String>,
}

impl Entry {
    pub fn new(
        real_uid: u32,
        real_user: impl Into<String>,
        operation: impl Into<String>,
        packages: Vec<String>,
        outcome: impl Into<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            real_uid,
            real_user: real_user.into(),
            operation: operation.into(),
            packages,
            outcome: outcome.into(),
            detail,
        }
    }
}

pub struct AuditLogger {
    log_path: String,
}

impl AuditLogger {
    pub fn new(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
        }
    }

    /// Write one JSON log entry to the audit file and syslog.
    /// Logging failures are non-fatal — mom still proceeds.
    pub fn log(&self, entry: Entry) {
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("mom: warning: failed to serialize log entry: {e}");
                return;
            }
        };

        // Write to JSON audit file
        if let Err(e) = self.write_to_file(&json) {
            eprintln!("mom: warning: failed to write audit log: {e}");
        }

        // Write to syslog
        self.write_to_syslog(&entry, &json);
    }

    fn write_to_file(&self, json: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .with_context(|| format!("cannot open log file {}", self.log_path))?;
        writeln!(file, "{json}").with_context(|| format!("cannot write to {}", self.log_path))?;
        Ok(())
    }

    fn write_to_syslog(&self, entry: &Entry, json: &str) {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "mom".into(),
            pid: std::process::id(),
        };
        let msg = format!(
            "user={} uid={} op={} packages=[{}] outcome={} detail={}",
            entry.real_user,
            entry.real_uid,
            entry.operation,
            entry.packages.join(","),
            entry.outcome,
            entry.detail.as_deref().unwrap_or("-"),
        );
        if let Ok(mut writer) = syslog::unix(formatter) {
            let _ = if entry.outcome == "success" || entry.outcome == "initiated" {
                writer.info(msg)
            } else {
                writer.warning(msg)
            };
        }
        let _ = json; // suppress unused warning; json available for future structured syslog
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_entry_serialises_correctly() {
        let e = Entry::new(
            1001,
            "alice",
            "install",
            vec!["curl".into()],
            "success",
            None,
        );
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"real_uid\":1001"));
        assert!(json.contains("\"real_user\":\"alice\""));
        assert!(json.contains("\"operation\":\"install\""));
        assert!(json.contains("\"outcome\":\"success\""));
        assert!(json.contains("\"detail\":null"));
    }

    #[test]
    fn test_log_writes_to_file() {
        let f = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(f.path().to_str().unwrap());
        logger.log(Entry::new(
            1001,
            "alice",
            "install",
            vec!["curl".into()],
            "success",
            None,
        ));
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("\"outcome\":\"success\""));
    }

    #[test]
    fn test_log_with_detail() {
        let f = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(f.path().to_str().unwrap());
        logger.log(Entry::new(
            1002,
            "bob",
            "install",
            vec!["nmap".into()],
            "denied",
            Some("matches deny list pattern nmap".into()),
        ));
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("\"outcome\":\"denied\""));
        assert!(content.contains("deny list"));
    }
}
