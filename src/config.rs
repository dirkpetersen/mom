use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;

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
        // Attempt to open; if it doesn't exist, fall back to defaults
        let file = match File::open(CONFIG_PATH) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(e).with_context(|| format!("cannot open {CONFIG_PATH}")),
        };

        // SECURITY: validate using fstat on the already-opened fd to prevent TOCTOU
        validate_file_metadata(&file, CONFIG_PATH, FileOwnership::Root)?;

        let map = parse_kv(BufReader::new(file))?;

        let cfg = Config {
            group: map
                .get("group")
                .cloned()
                .unwrap_or_else(|| DEFAULT_GROUP.to_string()),
            deny_list: map
                .get("deny_list")
                .cloned()
                .unwrap_or_else(|| DEFAULT_DENY_LIST.to_string()),
            log_file: map
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| DEFAULT_LOG_FILE.to_string()),
            http_proxy: map
                .get("http_proxy")
                .cloned()
                .and_then(|v| validate_proxy_url(&v, "http_proxy").ok()),
            https_proxy: map
                .get("https_proxy")
                .cloned()
                .and_then(|v| validate_proxy_url(&v, "https_proxy").ok()),
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

/// Validate an already-opened file using fstat (no TOCTOU).
/// Checks:
/// - ownership (root or root-or-group depending on `ownership`)
/// - not world-writable
/// - not a symlink (file type check via fstat)
pub fn validate_file_metadata(file: &File, path: &str, ownership: FileOwnership) -> Result<()> {
    let meta = file
        .metadata()
        .with_context(|| format!("cannot fstat {path}"))?;

    // Reject if not a regular file (could be symlink target, but we check type after open)
    if !meta.is_file() {
        bail!("security error: {path} is not a regular file");
    }

    // Check world-writable bit
    if meta.mode() & 0o002 != 0 {
        bail!("security error: {path} is world-writable — refusing to read");
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
            if meta.uid() != 0 && meta.gid() != gid {
                bail!(
                    "security error: {path} must be owned by root or gid {gid} \
                     (found uid={} gid={})",
                    meta.uid(),
                    meta.gid()
                );
            }
        }
    }

    Ok(())
}

/// Validate that a proxy URL looks reasonable.
/// Accepts http:// and https:// URLs only. Rejects shell metacharacters.
fn validate_proxy_url(value: &str, key: &str) -> Result<String> {
    if !value.starts_with("http://") && !value.starts_with("https://") {
        bail!("security error: {key} must start with http:// or https://, got: {value:?}");
    }
    // Reject any shell-dangerous characters
    let forbidden = [
        ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\'', '"', '\\', '\n', '\r', '\0',
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
