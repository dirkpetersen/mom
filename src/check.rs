use anyhow::Result;

use crate::auth;
use crate::config::{Config, CONFIG_PATH};
use crate::deny;
use crate::detect;

/// Run the --check validation mode.
/// Validates config, deny list, and package manager detection.
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
    match auth::gid_for_group(&cfg.group) {
        Ok(gid) => ok(&format!("group '{}' exists (gid={})", cfg.group, gid)),
        Err(e) => {
            err(&format!("group '{}' not found: {e}", cfg.group));
            errors += 1;
        }
    }

    // ── Deny list ─────────────────────────────────────────────────────────────
    if std::path::Path::new(&cfg.deny_list).exists() {
        match deny::DenyList::load(&cfg.deny_list) {
            Ok(dl) => {
                ok(&format!(
                    "deny list OK: {} pattern(s) loaded from {}",
                    dl.len(),
                    cfg.deny_list
                ));
                // Verify group ownership
                if let Ok(gid) = auth::gid_for_group(&cfg.group) {
                    if let Err(e) = deny::check_deny_list_group_ownership(&cfg.deny_list, gid) {
                        err(&format!("deny list ownership: {e}"));
                        errors += 1;
                    } else {
                        ok(&format!("deny list ownership OK (gid={})", gid));
                    }
                }
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

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    if errors == 0 && warnings == 0 {
        println!("✓ All checks passed.");
    } else {
        if errors > 0 {
            println!("✗ {errors} error(s) found — mom will not function correctly.");
        }
        if warnings > 0 {
            println!("⚠ {warnings} warning(s) found — mom will use defaults.");
        }
        if errors > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
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
