#![no_main]
use libfuzzer_sys::fuzz_target;

use globset::{Glob, GlobSet, GlobSetBuilder};
use std::io::{BufRead, Cursor};

/// Mirror of DenyList::parse logic — exercises glob compilation with arbitrary input.
/// Fuzz goal: ensure no panic on malformed glob patterns, OOM, or excessive memory use.
fn parse_deny_list(input: &[u8]) {
    let reader = Cursor::new(input);
    let mut builder = GlobSetBuilder::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Cap pattern length to prevent excessive memory from pathological globs
        if trimmed.len() > 256 {
            continue;
        }
        match Glob::new(trimmed) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(_) => continue,
        }
    }

    let _ = builder.build();
}

fuzz_target!(|data: &[u8]| {
    parse_deny_list(data);
});
