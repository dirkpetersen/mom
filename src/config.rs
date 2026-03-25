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
    /// Validates ownership and permissions before reading.
    pub fn load() -> Result<Self> {
        if !std::path::Path::new(CONFIG_PATH).exists() {
            return Ok(Config::default());
        }

        validate_config_file(CONFIG_PATH)?;

        let file = File::open(CONFIG_PATH).with_context(|| format!("cannot open {CONFIG_PATH}"))?;
        let map = parse_kv(BufReader::new(file))?;

        Ok(Config {
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
            http_proxy: map.get("http_proxy").cloned(),
            https_proxy: map.get("https_proxy").cloned(),
        })
    }
}

/// Validate that a config file is safe to read:
/// - owned by root (uid 0)
/// - not world-writable
fn validate_config_file(path: &str) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("cannot stat {path}"))?;

    if meta.uid() != 0 {
        bail!(
            "security error: {path} must be owned by root (uid 0), \
             found uid {}",
            meta.uid()
        );
    }

    // Check world-writable bit (mode & 0o002)
    if meta.mode() & 0o002 != 0 {
        bail!("security error: {path} is world-writable — refusing to read");
    }

    Ok(())
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
}
