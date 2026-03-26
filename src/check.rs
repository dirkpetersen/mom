use anyhow::Result;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::FromRawFd;

use crate::auth;
use crate::config::{Config, CONFIG_PATH};
use crate::deny;
use crate::detect;

/// Run the --check validation mode.
/// Validates config, deny list, package manager detection, and binary permissions.
/// Prints results to stdout. Does not perform any package operations.
/// Returns Ok(()) even if warnings are found; only hard errors propagate.
pub fn run_check(cfg: &Config) -> Result<()> {
    let mut errors = 0usize;
    let mut warnings = 0usize;

    println!("mom --check: validating configuration\n");

    // ── Config file ────────────────────────────────────────────────────────────
    if std::path::Path::new(CONFIG_PATH).exists() {
        ok(&format!("config file present: {CONFIG_PATH}"));
    } else {
        warn(&format!(
            "config file not found ({CONFIG_PATH}); using safe defaults"
        ));
        warnings += 1;
    }

    println!("  group       = {}", cfg.group);
    println!("  deny_list   = {}", cfg.deny_list);
    println!("  log_file    = {}", cfg.log_file);
    println!(
        "  http_proxy  = {}",
        cfg.http_proxy.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  https_proxy = {}",
        cfg.https_proxy.as_deref().unwrap_or("(not set)")
    );
    println!();

    // ── Group ─────────────────────────────────────────────────────────────────
    let group_gid = match auth::gid_for_group(&cfg.group) {
        Ok(gid) => {
            ok(&format!("group '{}' exists (gid={})", cfg.group, gid));
            Some(gid)
        }
        Err(e) => {
            err(&format!("group '{}' not found: {e}", cfg.group));
            errors += 1;
            None
        }
    };

    // ── Deny list ─────────────────────────────────────────────────────────────
    if std::path::Path::new(&cfg.deny_list).exists() {
        match deny::DenyList::load(&cfg.deny_list, group_gid) {
            Ok(dl) => {
                ok(&format!(
                    "deny list OK: {} pattern(s) loaded from {}",
                    dl.len(),
                    cfg.deny_list
                ));
            }
            Err(e) => {
                err(&format!("deny list error: {e}"));
                errors += 1;
            }
        }
    } else {
        warn(&format!(
            "deny list not found ({}); treating as empty",
            cfg.deny_list
        ));
        warnings += 1;
    }

    // ── Log file / directory ──────────────────────────────────────────────────
    if let Some(parent) = std::path::Path::new(&cfg.log_file).parent() {
        if parent.exists() {
            ok(&format!("log directory exists: {}", parent.display()));
        } else {
            err(&format!(
                "log directory does not exist: {}",
                parent.display()
            ));
            errors += 1;
        }
    }

    // ── Package manager ───────────────────────────────────────────────────────
    println!();
    match detect::detect_package_manager() {
        Ok(pm) => ok(&format!("package manager detected: {}", pm.binary())),
        Err(e) => {
            err(&format!("package manager detection failed: {e}"));
            errors += 1;
        }
    }

    // ── Binary setuid check ───────────────────────────────────────────────────
    check_binary_permissions(&mut errors, &mut warnings);

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    if errors == 0 && warnings == 0 {
        println!("All checks passed.");
    } else {
        if errors > 0 {
            println!("{errors} error(s) found — mom may not function correctly.");
        }
        if warnings > 0 {
            println!("{warnings} warning(s) found — mom will use defaults.");
        }
        if errors > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn check_binary_permissions(errors: &mut usize, warnings: &mut usize) {
    // Find our own binary path
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => {
            warn("could not determine binary path for permission check");
            *warnings += 1;
            return;
        }
    };

    // Use O_NOFOLLOW + fstat to avoid symlink-following TOCTOU
    let c_path = match std::ffi::CString::new(exe.to_string_lossy().as_bytes().to_vec()) {
        Ok(c) => c,
        Err(_) => {
            warn("binary path contains null byte");
            *warnings += 1;
            return;
        }
    };
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        warn(&format!("could not open binary {}: {e}", exe.display()));
        *warnings += 1;
        return;
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            warn(&format!("could not fstat binary {}: {e}", exe.display()));
            *warnings += 1;
            return;
        }
    };

    let mode = meta.mode();
    let uid = meta.uid();

    // Check owned by root
    if uid != 0 {
        err(&format!(
            "binary {} is owned by uid {} (should be root)",
            exe.display(),
            uid
        ));
        *errors += 1;
    } else {
        ok(&format!("binary owned by root: {}", exe.display()));
    }

    // Check setuid bit
    if mode & 0o4000 != 0 {
        ok("setuid bit is set");
    } else {
        err(&format!(
            "setuid bit is NOT set on {} — mom cannot escalate privileges. \
             Run: chmod u+s {}",
            exe.display(),
            exe.display()
        ));
        *errors += 1;
    }

    // Report permission mode
    let mode_octal = mode & 0o7777;
    if mode_octal == 0o4750 {
        ok(&format!(
            "permissions: {mode_octal:04o} (group-restricted setuid — recommended)"
        ));
    } else if mode_octal == 0o4755 {
        warn(&format!(
            "permissions: {mode_octal:04o} (open setuid — any local user can execute, \
             including 'mom refresh' which runs a privileged network operation as root. \
             Consider 4750 with group restriction instead)"
        ));
        *warnings += 1;
    } else {
        warn(&format!(
            "permissions: {mode_octal:04o} (expected 4750 or 4755)"
        ));
        *warnings += 1;
    }
}

fn ok(msg: &str) {
    println!("  [OK]   {msg}");
}

fn warn(msg: &str) {
    println!("  [WARN] {msg}");
}

fn err(msg: &str) {
    println!("  [ERR]  {msg}");
}
