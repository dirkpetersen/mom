use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
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
        // SECURITY: Use O_NOFOLLOW to prevent symlink-following attacks.
        // A symlink at the log path could cause root to write to an
        // attacker-chosen file. O_NOFOLLOW makes open() fail with ELOOP
        // if the path is a symlink.
        let c_path = std::ffi::CString::new(self.log_path.as_str())
            .with_context(|| format!("log path contains null byte: {}", self.log_path))?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW,
                0o640,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("cannot open log file {}: {err}", self.log_path);
        }
        // SECURITY: fchmod after open to set correct mode regardless of umask.
        // The startup umask(0o077) would strip group-read from 0o640, making
        // the log unreadable by ops groups. fchmod bypasses the umask.
        unsafe { libc::fchmod(fd, 0o640) };
        let mut file = unsafe { File::from_raw_fd(fd) };
        writeln!(file, "{json}").with_context(|| format!("cannot write to {}", self.log_path))?;
        Ok(())
    }

    /// Replace control characters (newlines, tabs, etc.) with underscores
    /// to prevent syslog injection via crafted usernames from NSS/LDAP.
    fn sanitize_for_syslog(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_control() { '_' } else { c })
            .collect()
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
            Self::sanitize_for_syslog(&entry.real_user),
            entry.real_uid,
            Self::sanitize_for_syslog(&entry.operation),
            entry
                .packages
                .iter()
                .map(|p| Self::sanitize_for_syslog(p))
                .collect::<Vec<_>>()
                .join(","),
            Self::sanitize_for_syslog(&entry.outcome),
            Self::sanitize_for_syslog(entry.detail.as_deref().unwrap_or("-")),
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
