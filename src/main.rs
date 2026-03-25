mod auth;
mod check;
mod config;
mod deny;
mod detect;
mod exec;
mod log;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use nix::unistd::{getegid, geteuid, getgid, getuid};

/// Maximum allowed length for a single package name.
const MAX_PACKAGE_NAME_LEN: usize = 256;

/// Maximum number of packages per invocation.
const MAX_PACKAGE_COUNT: usize = 100;

#[derive(Parser)]
#[command(
    name = "mom",
    version,
    about = "Meta Overlay Manager — install packages without root access",
    long_about = "\
mom allows non-root users to install and update packages on systems where \
they lack root access. It wraps apt-get (Debian/Ubuntu) or dnf (RHEL) and \
must be deployed as a setuid-root binary.\n\
\n\
For setup instructions see: man mom(8)"
)]
struct Cli {
    /// Suppress prompts — same semantics as `apt-get -y` / `dnf -y`
    #[arg(short = 'y', long = "yes", global = true)]
    yes: bool,

    /// Validate configuration and deny list without performing any package operations
    #[arg(long = "check", global = true)]
    check: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install one or more packages
    Install {
        /// Package name(s) to install
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Refresh repos, then update named packages (errors if not installed)
    Update {
        /// Package name(s) to update
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Refresh package repository metadata only
    Refresh,
}

fn main() {
    // SECURITY: Clear the entire inherited environment immediately, before any
    // Rust stdlib or dependency code can read attacker-controlled env vars
    // (e.g. RUST_LOG, LD_PRELOAD, http_proxy, LANG, LC_*, TERM, HOME, etc.).
    // This must happen before Cli::parse() or any allocator/logger initialization.
    clear_environment();

    // SECURITY: Set a restrictive umask so any files we create (audit log, etc.)
    // are not world-readable/writable by default.
    unsafe { libc::umask(0o077) };

    if let Err(e) = run() {
        eprintln!("mom: {e}");
        std::process::exit(1);
    }
}

/// Remove all environment variables from the current process.
fn clear_environment() {
    let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    for key in keys {
        unsafe { std::env::remove_var(&key) };
    }
}

fn run() -> Result<()> {
    // ── Capture real identity before any privilege operations ─────────────────
    let real_uid = getuid();
    let real_gid = getgid();
    let euid = geteuid();
    let _egid = getegid();

    // ── Verify we are running as root via setuid ──────────────────────────────
    if euid.as_raw() != 0 {
        bail!(
            "mom must be installed as a setuid-root binary \
             (run as uid {} but effective uid is {}; expected 0). \
             See man mom(8) for installation instructions.",
            real_uid.as_raw(),
            euid.as_raw()
        );
    }

    // ── Drop supplemental groups immediately ─────────────────────────────────
    auth::drop_supplemental_groups()?;

    // ── Resolve caller identity for logging ──────────────────────────────────
    let real_user = auth::username_for_uid(real_uid)?;

    // ── Load configuration (safe defaults if /etc/mom/mom.conf absent) ────────
    let cfg = config::Config::load()?;

    // ── Set up audit logger ───────────────────────────────────────────────────
    let logger = log::AuditLogger::new(&cfg.log_file);

    // ── Parse CLI ─────────────────────────────────────────────────────────────
    let cli = Cli::parse();

    // ── --check overrides all subcommands ────────────────────────────────────
    if cli.check {
        return check::run_check(&cfg);
    }

    // ── Dispatch subcommand ───────────────────────────────────────────────────
    match cli.command {
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }

        Some(Commands::Refresh) => {
            // Any user may refresh — no group check
            let pm = detect::detect_package_manager()?;
            logger.log(log::Entry::new(
                real_uid.as_raw(),
                &real_user,
                "refresh",
                vec![],
                "initiated",
                None,
            ));
            let rc = exec::refresh(&pm, cli.yes, &cfg)?;
            log_outcome(&logger, real_uid.as_raw(), &real_user, "refresh", &[], rc);
            maybe_exit(rc);
            Ok(())
        }

        Some(Commands::Install { packages }) => {
            require_group_membership(
                real_uid, real_gid, &cfg, &logger, &real_user, "install", &packages,
            )?;

            let packages = validate_packages(
                packages,
                &cfg,
                real_uid.as_raw(),
                &real_user,
                "install",
                &logger,
            )?;

            let pm = detect::detect_package_manager()?;
            logger.log(log::Entry::new(
                real_uid.as_raw(),
                &real_user,
                "install",
                packages.clone(),
                "initiated",
                None,
            ));
            let rc = exec::install(&pm, &packages, cli.yes, &cfg)?;
            log_outcome(
                &logger,
                real_uid.as_raw(),
                &real_user,
                "install",
                &packages,
                rc,
            );
            maybe_exit(rc);
            Ok(())
        }

        Some(Commands::Update { packages }) => {
            require_group_membership(
                real_uid, real_gid, &cfg, &logger, &real_user, "update", &packages,
            )?;

            let packages = validate_packages(
                packages,
                &cfg,
                real_uid.as_raw(),
                &real_user,
                "update",
                &logger,
            )?;

            let pm = detect::detect_package_manager()?;

            // Verify every package is installed before attempting update
            for pkg in &packages {
                match exec::is_installed(&pm, pkg, &cfg) {
                    Ok(true) => {}
                    Ok(false) => {
                        let detail = format!("package '{pkg}' is not installed");
                        logger.log(log::Entry::new(
                            real_uid.as_raw(),
                            &real_user,
                            "update",
                            packages.clone(),
                            "denied",
                            Some(detail.clone()),
                        ));
                        bail!("{detail}; use 'mom install {pkg}' first");
                    }
                    Err(e) => bail!("could not check installation status of '{pkg}': {e}"),
                }
            }

            logger.log(log::Entry::new(
                real_uid.as_raw(),
                &real_user,
                "update",
                packages.clone(),
                "initiated",
                None,
            ));
            let rc = exec::update(&pm, &packages, cli.yes, &cfg)?;
            log_outcome(
                &logger,
                real_uid.as_raw(),
                &real_user,
                "update",
                &packages,
                rc,
            );
            maybe_exit(rc);
            Ok(())
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_group_membership(
    real_uid: nix::unistd::Uid,
    real_gid: nix::unistd::Gid,
    cfg: &config::Config,
    logger: &log::AuditLogger,
    real_user: &str,
    operation: &str,
    packages: &[String],
) -> Result<()> {
    if let Err(e) = auth::check_group_membership(real_uid, real_gid, &cfg.group) {
        logger.log(log::Entry::new(
            real_uid.as_raw(),
            real_user,
            operation,
            packages.to_vec(),
            "denied",
            Some(e.to_string()),
        ));
        bail!("{e}");
    }
    Ok(())
}

fn validate_packages(
    packages: Vec<String>,
    cfg: &config::Config,
    real_uid: u32,
    real_user: &str,
    operation: &str,
    logger: &log::AuditLogger,
) -> Result<Vec<String>> {
    // Enforce package count limit
    if packages.len() > MAX_PACKAGE_COUNT {
        let detail = format!(
            "too many packages ({}, max {})",
            packages.len(),
            MAX_PACKAGE_COUNT
        );
        logger.log(log::Entry::new(
            real_uid,
            real_user,
            operation,
            packages.clone(),
            "denied",
            Some(detail.clone()),
        ));
        bail!("{detail}");
    }

    for pkg in &packages {
        // Enforce name length limit
        if pkg.len() > MAX_PACKAGE_NAME_LEN {
            let detail = format!(
                "package name too long ({} chars, max {})",
                pkg.len(),
                MAX_PACKAGE_NAME_LEN
            );
            logger.log(log::Entry::new(
                real_uid,
                real_user,
                operation,
                packages.clone(),
                "denied",
                Some(detail.clone()),
            ));
            bail!("{detail}");
        }

        if !is_valid_package_name(pkg) {
            let detail = format!("invalid package name '{pkg}'");
            logger.log(log::Entry::new(
                real_uid,
                real_user,
                operation,
                packages.clone(),
                "denied",
                Some(detail.clone()),
            ));
            bail!("{detail} — only alphanumeric characters, '.', '+', and '-' are allowed");
        }
    }

    // Load deny list — now with group ownership verification (TOCTOU-safe)
    let group_gid = auth::gid_for_group(&cfg.group).ok();
    let deny_list = deny::DenyList::load(&cfg.deny_list, group_gid)?;

    for pkg in &packages {
        if let Some(pattern) = deny_list.matches(pkg) {
            let detail = format!("package '{pkg}' matches deny list pattern '{pattern}'");
            logger.log(log::Entry::new(
                real_uid,
                real_user,
                operation,
                packages.clone(),
                "denied",
                Some(detail.clone()),
            ));
            bail!("{detail}");
        }
    }
    Ok(packages)
}

/// Validate a package name against the allowed character set.
/// Pattern: `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$`
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

fn log_outcome(
    logger: &log::AuditLogger,
    uid: u32,
    user: &str,
    op: &str,
    packages: &[String],
    exit_code: i32,
) {
    let (outcome, detail) = if exit_code == 0 {
        ("success".to_string(), None)
    } else {
        ("failed".to_string(), Some(format!("exit code {exit_code}")))
    };
    logger.log(log::Entry::new(
        uid,
        user,
        op,
        packages.to_vec(),
        outcome,
        detail,
    ));
}

fn maybe_exit(rc: i32) {
    if rc != 0 {
        std::process::exit(rc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_package_names() {
        let valid = [
            "curl",
            "wget",
            "python3",
            "libssl-dev",
            "g++",
            "node.js",
            "libc6",
            "apt-get",
            "ca-certificates",
            "A0",
            "z",
        ];
        for name in &valid {
            assert!(is_valid_package_name(name), "expected valid: {name}");
        }
    }

    #[test]
    fn test_invalid_package_names() {
        let invalid = [
            "",
            "-starts-with-dash",
            ".starts-with-dot",
            "+starts-with-plus",
            "has spaces",
            "semi;colon",
            "back`tick",
            "dol$ar",
            "pipe|char",
            "amp&ersand",
            "great>er",
            "less<er",
            "foo=1.2.3", // version pinning not allowed
            "foo/bar",   // path separator
            "../etc/passwd",
            "$(evil)",
        ];
        for name in &invalid {
            assert!(!is_valid_package_name(name), "expected invalid: {name}");
        }
    }

    #[test]
    fn test_valid_package_name_starts_with_digit() {
        assert!(is_valid_package_name("2to3"));
    }

    #[test]
    fn test_valid_package_name_with_all_allowed_chars() {
        assert!(is_valid_package_name("a0.+b-c"));
    }

    #[test]
    fn test_package_name_length_limit() {
        let long_name = "a".repeat(MAX_PACKAGE_NAME_LEN);
        assert!(is_valid_package_name(&long_name));
        // length check is in validate_packages, not is_valid_package_name
    }
}
