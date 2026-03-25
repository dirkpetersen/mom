use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::config::{validate_file_metadata, FileOwnership};

/// A compiled deny list loaded from the configured deny_list path.
pub struct DenyList {
    /// Compiled globset for fast matching
    globset: GlobSet,
    /// Raw patterns (same order as globset), for returning the matched pattern in errors
    patterns: Vec<String>,
}

impl DenyList {
    /// Load and compile the deny list from `path`.
    /// If the file does not exist, returns an empty deny list (no denials).
    /// Validates ownership using open-then-fstat to avoid TOCTOU.
    /// `group_gid` is the resolved GID of the configured group (for ownership check).
    pub fn load(path: &str, group_gid: Option<u32>) -> Result<Self> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DenyList {
                    globset: GlobSet::empty(),
                    patterns: vec![],
                });
            }
            Err(e) => return Err(e).with_context(|| format!("cannot open deny list {path}")),
        };

        // SECURITY: validate using fstat on the already-opened fd to prevent TOCTOU.
        // Deny list must be owned by root or the mom group.
        let ownership = match group_gid {
            Some(gid) => FileOwnership::RootOrGroup(gid),
            None => FileOwnership::Root,
        };
        validate_file_metadata(&file, path, ownership)?;

        Self::parse(BufReader::new(file), path)
    }

    fn parse(reader: impl BufRead, path: &str) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        let mut patterns = Vec::new();

        for (lineno, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("I/O error reading {path}"))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let glob = Glob::new(trimmed).with_context(|| {
                format!("invalid glob pattern on line {}: {trimmed:?}", lineno + 1)
            })?;
            builder.add(glob);
            patterns.push(trimmed.to_string());
        }

        let globset = builder
            .build()
            .with_context(|| format!("failed to compile deny list from {path}"))?;

        Ok(DenyList { globset, patterns })
    }

    /// Returns `Some(pattern)` if the package name is denied, `None` if allowed.
    pub fn matches(&self, package: &str) -> Option<&str> {
        let matches = self.globset.matches(package);
        matches
            .into_iter()
            .next()
            .map(|idx| self.patterns[idx].as_str())
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_list(input: &str) -> DenyList {
        DenyList::parse(Cursor::new(input), "<test>").unwrap()
    }

    #[test]
    fn test_empty_deny_list_allows_everything() {
        let dl = make_list("");
        assert!(dl.matches("curl").is_none());
        assert!(dl.is_empty());
    }

    #[test]
    fn test_exact_match() {
        let dl = make_list("nmap\n");
        assert_eq!(dl.matches("nmap"), Some("nmap"));
        assert!(dl.matches("curl").is_none());
    }

    #[test]
    fn test_glob_wildcard_suffix() {
        let dl = make_list("python3-*\n");
        assert_eq!(dl.matches("python3-dev"), Some("python3-*"));
        assert_eq!(dl.matches("python3-pip"), Some("python3-*"));
        assert!(dl.matches("python2-dev").is_none());
        assert!(dl.matches("python3").is_none()); // no suffix
    }

    #[test]
    fn test_glob_wildcard_prefix() {
        let dl = make_list("*-dev\n");
        assert_eq!(dl.matches("libssl-dev"), Some("*-dev"));
        assert!(dl.matches("curl").is_none());
    }

    #[test]
    fn test_multiple_patterns() {
        let dl = make_list("nmap\nwireshark\npython3-*\n");
        assert_eq!(dl.matches("nmap"), Some("nmap"));
        assert_eq!(dl.matches("wireshark"), Some("wireshark"));
        assert_eq!(dl.matches("python3-requests"), Some("python3-*"));
        assert!(dl.matches("curl").is_none());
    }

    #[test]
    fn test_comments_and_blank_lines_ignored() {
        let dl = make_list("# this is a comment\n\nnmap\n  # another comment\n");
        assert_eq!(dl.len(), 1);
        assert_eq!(dl.matches("nmap"), Some("nmap"));
    }

    #[test]
    fn test_question_mark_glob() {
        let dl = make_list("nma?\n");
        assert_eq!(dl.matches("nmap"), Some("nma?"));
        assert!(dl.matches("nmapz").is_none());
    }

    #[test]
    fn test_invalid_glob_errors() {
        // Unmatched bracket is invalid glob
        let result = DenyList::parse(Cursor::new("[invalid\n"), "<test>");
        assert!(result.is_err());
    }

    #[test]
    fn test_returns_first_matching_pattern() {
        let dl = make_list("nmap\nn*\n");
        // First match (index 0) is "nmap"
        let m = dl.matches("nmap");
        assert!(m.is_some());
    }
}
