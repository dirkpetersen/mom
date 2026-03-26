#![no_main]
use libfuzzer_sys::fuzz_target;

/// Mirror of mom's is_valid_package_name — must match src/main.rs exactly.
/// Fuzz goal: ensure no panic, no unexpected acceptance of shell metacharacters.
fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '+' || c == '-')
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let result = is_valid_package_name(s);
        // If accepted, verify no shell-dangerous characters slipped through
        if result {
            assert!(!s.is_empty());
            assert!(s.chars().next().unwrap().is_ascii_alphanumeric());
            for c in s.chars() {
                assert!(
                    c.is_ascii_alphanumeric() || c == '.' || c == '+' || c == '-',
                    "unexpected char accepted: {c:?}"
                );
            }
            // Must not contain shell metacharacters
            for bad in &[';', '|', '&', '$', '`', '(', ')', '<', '>', '\'', '"', '\\', ' ', '\n', '\r', '\t', '\0'] {
                assert!(!s.contains(*bad), "shell metachar accepted: {bad:?}");
            }
        }
    }
});
