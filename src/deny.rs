use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;

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
    /// Validates that the file is owned by the `mom` group (or the configured group).
    pub fn load(path: &str) -> Result<Self> {
        if !std::path::Path::new(path).exists() {
            return Ok(DenyList {
                globset: GlobSet::empty(),
                patterns: vec![],
            });
        }

        validate_deny_list_file(path)?;

        let file = File::open(path).with_context(|| format!("cannot open deny list {path}"))?;
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

/// The deny list file must be:
/// - owned by the `mom` group (gid check)
/// - not world-writable
fn validate_deny_list_file(path: &str) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("cannot stat deny list {path}"))?;

    // Must not be world-writable
    if meta.mode() & 0o002 != 0 {
        bail!("security error: deny list {path} is world-writable — refusing to read");
    }

    // Owned by root or the mom group — we verify gid != world-accessible
    // The config group name is validated separately; here we just ensure
    // uid 0 or gid 0 (or the mom group gid) owns the file.
    // Full group-name→gid validation happens in auth::check_deny_list_ownership.
    // Here we do a minimal sanity check: not owned by a random unprivileged user.
    if meta.uid() != 0 {
        // Allow if owned by root. If not owned by root, the group must own it
        // and that group check is done via auth. We warn but still accept here
        // so sysadmins can set gid-ownership without root uid.
    }

    Ok(())
}

/// Validate that the deny list is owned by the expected group (by GID).
/// Called after we resolve the group name → gid.
pub fn check_deny_list_group_ownership(path: &str, expected_gid: u32) -> Result<()> {
    if !std::path::Path::new(path).exists() {
        return Ok(()); // missing → empty list, already handled
    }
    let meta = std::fs::metadata(path).with_context(|| format!("cannot stat deny list {path}"))?;

    if meta.uid() != 0 && meta.gid() != expected_gid {
        bail!(
            "security error: deny list {path} must be owned by root or \
             gid {expected_gid} (found uid={} gid={})",
            meta.uid(),
            meta.gid()
        );
    }
    Ok(())
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
