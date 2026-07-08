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
    /// Returns true if at least one sink (file or syslog) accepted the entry.
    /// Callers decide whether a total logging failure is fatal: outcome
    /// entries are best-effort, but pre-exec "initiated" entries must not be
    /// lost — a privileged operation without any durable audit record defeats
    /// the audit trail this setuid tool promises.
    pub fn log(&self, entry: Entry) -> bool {
        let json = match serde_json::to_string(&entry) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("mom: warning: failed to serialize log entry: {e}");
                return false;
            }
        };

        // Write to JSON audit file
        let file_ok = match self.write_to_file(&json) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("mom: warning: failed to write audit log: {e}");
                false
            }
        };

        // Write to syslog
        let syslog_ok = self.write_to_syslog(&entry, &json);

        file_ok || syslog_ok
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
        if unsafe { libc::fchmod(fd, 0o640) } != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "mom: warning: fchmod on log file {} failed: {err}",
                self.log_path
            );
        }
        let mut file = unsafe { File::from_raw_fd(fd) };

        // SECURITY: O_NOFOLLOW only guards the final path component. Validate the
        // opened fd itself (fstat — no TOCTOU) before writing as root:
        //   - must be a regular file (not a fifo/device/etc.)
        //   - exactly one hard link (blocks a pre-existing hardlink to a
        //     sensitive file such as /etc/passwd that we'd otherwise append to)
        //   - owned by root when we actually hold root (the production setuid
        //     case); skipped when unprivileged so tests on user-owned temp files
        //     still exercise the path.
        // On any failure we refuse the file write; the entry still reaches syslog.
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .with_context(|| format!("cannot fstat log file {}", self.log_path))?;
        if !meta.is_file() {
            anyhow::bail!(
                "log file {} is not a regular file — refusing to write",
                self.log_path
            );
        }
        if meta.nlink() != 1 {
            anyhow::bail!(
                "log file {} has {} hard links (expected 1) — refusing to write",
                self.log_path,
                meta.nlink()
            );
        }
        if unsafe { libc::geteuid() } == 0 && meta.uid() != 0 {
            anyhow::bail!(
                "log file {} must be owned by root (uid 0), found uid {} — refusing to write",
                self.log_path,
                meta.uid()
            );
        }

        writeln!(file, "{json}").with_context(|| format!("cannot write to {}", self.log_path))?;
        Ok(())
    }

    /// Sanitize a string for safe syslog inclusion.
    /// Replaces control characters, `%` (format string risk in some syslog
    /// implementations), and non-ASCII (LDAP/SSSD usernames that could
    /// corrupt log encoding) with underscores.
    fn sanitize_for_syslog(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_control() || c == '%' || !c.is_ascii() {
                    '_'
                } else {
                    c
                }
            })
            .collect()
    }

    /// Returns true if the message was accepted by the local syslog socket.
    fn write_to_syslog(&self, entry: &Entry, json: &str) -> bool {
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
        let sent = if let Ok(mut writer) = syslog::unix(formatter) {
            let res = if entry.outcome == "success" || entry.outcome == "initiated" {
                writer.info(msg)
            } else {
                writer.warning(msg)
            };
            res.is_ok()
        } else {
            false
        };
        let _ = json; // suppress unused warning; json available for future structured syslog
        sent
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
    fn test_log_refuses_hardlinked_file() {
        // A pre-existing file with >1 hard link is rejected (finding 4): an
        // attacker-planted hardlink to a sensitive file must not be appended to.
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("mom.log");
        std::fs::write(&primary, b"").unwrap();
        std::fs::hard_link(&primary, dir.path().join("mom.log.link")).unwrap();
        let logger = AuditLogger::new(primary.to_str().unwrap());
        assert!(logger.write_to_file("{}").is_err());
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
