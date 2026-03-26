use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::FromRawFd;

pub const DEFAULT_GROUP: &str = "mom";
pub const DEFAULT_DENY_LIST: &str = "/etc/mom/deny.list";
pub const DEFAULT_LOG_FILE: &str = "/var/log/mom.log";
pub const CONFIG_PATH: &str = "/etc/mom/mom.conf";

#[derive(Debug, Clone)]
pub struct Config {
    pub group: String,
    pub deny_list: String,
    pub log_file: String,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            group: DEFAULT_GROUP.to_string(),
            deny_list: DEFAULT_DENY_LIST.to_string(),
            log_file: DEFAULT_LOG_FILE.to_string(),
            http_proxy: None,
            https_proxy: None,
        }
    }
}

impl Config {
    /// Load configuration from CONFIG_PATH.
    /// Falls back to safe defaults if the file does not exist.
    /// Validates ownership and permissions using open-then-fstat to avoid TOCTOU.
    pub fn load() -> Result<Self> {
        // SECURITY: Open with O_NOFOLLOW to reject symlinks. A symlink at the
        // config path could redirect to an attacker-controlled file that passes
        // ownership checks (e.g. any root-owned readable file).
        let file = match open_nofollow(CONFIG_PATH) {
            Ok(f) => f,
            Err(OpenNoFollowError::NotFound) => return Ok(Config::default()),
            Err(OpenNoFollowError::IsSymlink) => {
                bail!("security error: {CONFIG_PATH} is a symlink — refusing to read")
            }
            Err(OpenNoFollowError::Other(e)) => {
                return Err(e).with_context(|| format!("cannot open {CONFIG_PATH}"))
            }
        };

        // SECURITY: validate using fstat on the already-opened fd to prevent TOCTOU
        validate_file_metadata(&file, CONFIG_PATH, FileOwnership::Root)?;

        let map = parse_kv(BufReader::new(file))?;

        let deny_list = map
            .get("deny_list")
            .cloned()
            .unwrap_or_else(|| DEFAULT_DENY_LIST.to_string());
        let log_file = map
            .get("log_file")
            .cloned()
            .unwrap_or_else(|| DEFAULT_LOG_FILE.to_string());
        let group = map
            .get("group")
            .cloned()
            .unwrap_or_else(|| DEFAULT_GROUP.to_string());

        // Validate paths are absolute and free of null bytes
        validate_config_path(&deny_list, "deny_list")?;
        validate_config_path(&log_file, "log_file")?;

        // Validate group name: ASCII alphanumeric, hyphens, underscores only
        // (Linux group names are restricted to ASCII; Unicode would silently fail)
        if group.is_empty()
            || !group
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!(
                "config error: group name '{}' contains invalid characters",
                group
            );
        }

        let cfg = Config {
            group,
            deny_list,
            log_file,
            http_proxy: map
                .get("http_proxy")
                .map(|v| validate_proxy_url(v, "http_proxy"))
                .transpose()?,
            https_proxy: map
                .get("https_proxy")
                .map(|v| validate_proxy_url(v, "https_proxy"))
                .transpose()?,
        };
        Ok(cfg)
    }
}

/// Who must own a file for it to be trusted.
pub enum FileOwnership {
    /// Must be owned by uid 0
    Root,
    /// Must be owned by uid 0 or by the specified gid
    RootOrGroup(u32),
}

/// Error type for open_nofollow, distinguishing ENOENT, ELOOP, and other errors.
pub enum OpenNoFollowError {
    NotFound,
    IsSymlink,
    Other(std::io::Error),
}

/// Open a file with O_RDONLY | O_NOFOLLOW | O_CLOEXEC.
/// Returns ELOOP as IsSymlink if the path is a symbolic link.
pub fn open_nofollow(path: &str) -> std::result::Result<File, OpenNoFollowError> {
    let c_path = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(e) => return Err(OpenNoFollowError::Other(std::io::Error::other(e))),
    };
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOENT) => Err(OpenNoFollowError::NotFound),
            Some(libc::ELOOP) => Err(OpenNoFollowError::IsSymlink),
            _ => Err(OpenNoFollowError::Other(err)),
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Validate an already-opened file using fstat (no TOCTOU).
/// The file must have been opened with O_NOFOLLOW to prevent symlink traversal.
/// Checks:
/// - ownership (root or root-or-group depending on `ownership`)
/// - not world-writable
/// - not group-writable (security-sensitive files must not be writable by group members)
/// - is a regular file (not a directory, device, etc.)
pub fn validate_file_metadata(file: &File, path: &str, ownership: FileOwnership) -> Result<()> {
    let meta = file
        .metadata()
        .with_context(|| format!("cannot fstat {path}"))?;

    // Reject if not a regular file
    if !meta.is_file() {
        bail!("security error: {path} is not a regular file");
    }

    // Reject group-writable or world-writable files
    if meta.mode() & 0o022 != 0 {
        bail!("security error: {path} is group- or world-writable — refusing to read");
    }

    match ownership {
        FileOwnership::Root => {
            if meta.uid() != 0 {
                bail!(
                    "security error: {path} must be owned by root (uid 0), found uid {}",
                    meta.uid()
                );
            }
        }
        FileOwnership::RootOrGroup(gid) => {
            // File must be owned by root (uid 0). The group may be root or
            // the configured mom group. We no longer accept files owned by
            // a non-root mom-group member, because on shared filesystems
            // that member could delete and recreate the file.
            if meta.uid() != 0 {
                bail!(
                    "security error: {path} must be owned by root (uid 0), found uid {}",
                    meta.uid()
                );
            }
            if meta.gid() != 0 && meta.gid() != gid {
                bail!(
                    "security error: {path} must have group root or gid {gid} \
                     (found gid={})",
                    meta.gid()
                );
            }
        }
    }

    Ok(())
}

/// Validate that a config path value is absolute and contains no null bytes.
fn validate_config_path(path: &str, key: &str) -> Result<()> {
    if path.contains('\0') {
        bail!("config error: {key} contains null byte");
    }
    if !path.starts_with('/') {
        bail!("config error: {key} must be an absolute path, got: {path:?}");
    }
    Ok(())
}

/// Validate that a proxy URL looks reasonable.
/// Accepts http:// and https:// URLs only. Rejects shell metacharacters.
fn validate_proxy_url(value: &str, key: &str) -> Result<String> {
    if !value.starts_with("http://") && !value.starts_with("https://") {
        bail!("security error: {key} must start with http:// or https://, got: {value:?}");
    }
    // Reject any non-printable or non-ASCII characters, plus shell metacharacters
    for ch in value.chars() {
        if !ch.is_ascii() || ch.is_ascii_control() {
            bail!("security error: {key} contains non-printable or non-ASCII character {ch:?}");
        }
    }
    let forbidden = [
        ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\'', '"', '\\', ' ', '\t',
    ];
    for ch in forbidden {
        if value.contains(ch) {
            bail!("security error: {key} contains forbidden character {ch:?}");
        }
    }
    Ok(value.to_string())
}

/// Parse a simple `key = value` file.
/// Lines starting with `#` or empty lines are ignored.
/// Values are trimmed of leading/trailing whitespace.
fn parse_kv(reader: impl BufRead) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.with_context(|| "I/O error reading config")?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, val) = trimmed
            .split_once('=')
            .with_context(|| format!("malformed config line {}: {:?}", lineno + 1, trimmed))?;
        let key = key.trim().to_lowercase();
        let val = val.trim().to_string();
        if !val.is_empty() {
            map.insert(key, val);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_default_config() {
        let c = Config::default();
        assert_eq!(c.group, "mom");
        assert_eq!(c.deny_list, "/etc/mom/deny.list");
        assert_eq!(c.log_file, "/var/log/mom.log");
        assert!(c.http_proxy.is_none());
        assert!(c.https_proxy.is_none());
    }

    #[test]
    fn test_parse_kv_basic() {
        let input = "group = devs\nlog_file = /tmp/mom.log\n";
        let map = parse_kv(Cursor::new(input)).unwrap();
        assert_eq!(map["group"], "devs");
        assert_eq!(map["log_file"], "/tmp/mom.log");
    }

    #[test]
    fn test_parse_kv_comments_and_blank_lines() {
        let input = "# comment\n\ngroup = devs\n  # another comment\n";
        let map = parse_kv(Cursor::new(input)).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map["group"], "devs");
    }

    #[test]
    fn test_parse_kv_empty_value_ignored() {
        let input = "http_proxy = \ngroup = ops\n";
        let map = parse_kv(Cursor::new(input)).unwrap();
        assert!(!map.contains_key("http_proxy"));
        assert_eq!(map["group"], "ops");
    }

    #[test]
    fn test_parse_kv_proxy_settings() {
        let input = "http_proxy = http://proxy.example.com:3128\nhttps_proxy = http://proxy.example.com:3128\n";
        let map = parse_kv(Cursor::new(input)).unwrap();
        assert_eq!(map["http_proxy"], "http://proxy.example.com:3128");
        assert_eq!(map["https_proxy"], "http://proxy.example.com:3128");
    }

    #[test]
    fn test_parse_kv_malformed_line_errors() {
        let input = "no_equals_sign\n";
        assert!(parse_kv(Cursor::new(input)).is_err());
    }

    #[test]
    fn test_parse_kv_case_insensitive_keys() {
        let input = "GROUP = devs\n";
        let map = parse_kv(Cursor::new(input)).unwrap();
        assert_eq!(map["group"], "devs");
    }

    #[test]
    fn test_validate_proxy_url_valid() {
        assert!(validate_proxy_url("http://proxy:3128", "http_proxy").is_ok());
        assert!(validate_proxy_url("https://proxy.corp.com:8080", "https_proxy").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_rejects_non_http() {
        assert!(validate_proxy_url("socks5://proxy:1080", "http_proxy").is_err());
        assert!(validate_proxy_url("ftp://proxy", "http_proxy").is_err());
    }

    #[test]
    fn test_validate_proxy_url_rejects_shell_metacharacters() {
        assert!(validate_proxy_url("http://proxy; rm -rf /", "http_proxy").is_err());
        assert!(validate_proxy_url("http://proxy$(evil)", "http_proxy").is_err());
        assert!(validate_proxy_url("http://proxy`evil`", "http_proxy").is_err());
        assert!(validate_proxy_url("http://proxy|cmd", "http_proxy").is_err());
    }
}
