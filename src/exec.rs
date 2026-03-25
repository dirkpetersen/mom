use anyhow::{Context, Result};
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::config::Config;
use crate::detect::PackageManager;

/// PID of the child process; used by signal handlers to forward signals.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);

/// Signal handler: forward the received signal to the child process.
extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, sig) };
    }
}

/// Run `apt-get install [packages]` or `dnf install [packages]`.
pub fn install(pm: &PackageManager, packages: &[String], yes: bool, cfg: &Config) -> Result<i32> {
    let args = pm.install_cmd_args(packages, yes);
    run_pkg_cmd(pm.binary(), &args, cfg)
}

/// Refresh repos, then run `apt-get install --only-upgrade` / `dnf upgrade`.
pub fn update(pm: &PackageManager, packages: &[String], yes: bool, cfg: &Config) -> Result<i32> {
    // Step 1: refresh
    let rc = refresh(pm, yes, cfg)?;
    if rc != 0 {
        return Ok(rc);
    }
    // Step 2: upgrade
    let args = pm.update_cmd_args(packages, yes);
    run_pkg_cmd(pm.binary(), &args, cfg)
}

/// Run `apt-get update` / `dnf makecache`.
pub fn refresh(pm: &PackageManager, _yes: bool, cfg: &Config) -> Result<i32> {
    let args = pm.refresh_cmd_args();
    run_pkg_cmd(pm.binary(), &args, cfg)
}

/// Check whether a package is currently installed.
///
/// Debian: `dpkg-query --status <pkg>` exits 0 if installed.
/// RHEL:   `rpm -q <pkg>` exits 0 if installed.
pub fn is_installed(pm: &PackageManager, package: &str, cfg: &Config) -> Result<bool> {
    let args = pm.is_installed_cmd_args(package);
    let rc = run_pkg_cmd_silent(pm.is_installed_binary(), &args, cfg)?;
    Ok(rc == 0)
}

/// Fork and exec `binary` with `args`, forwarding stdin/stdout/stderr to the
/// caller's terminal. Signals (SIGINT, SIGTERM, SIGHUP) are forwarded to the
/// child. Returns the child's exit code.
fn run_pkg_cmd(binary: &str, args: &[String], cfg: &Config) -> Result<i32> {
    let env = build_env(cfg);
    run_execve(binary, args, &env, false)
}

/// Like `run_pkg_cmd` but suppresses stdout/stderr (used for `is_installed` checks).
fn run_pkg_cmd_silent(binary: &str, args: &[String], cfg: &Config) -> Result<i32> {
    let env = build_env(cfg);
    run_execve(binary, args, &env, true)
}

fn run_execve(binary: &str, args: &[String], env: &[String], silent: bool) -> Result<i32> {
    let c_binary = CString::new(binary).context("binary path contains null byte")?;

    // Build argv: binary name first, then arguments
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_binary.clone());
    for arg in args {
        c_args.push(CString::new(arg.as_str()).context("argument contains null byte")?);
    }

    // Build clean environment
    let c_env: Vec<CString> = env
        .iter()
        .map(|e| CString::new(e.as_str()).context("env var contains null byte"))
        .collect::<Result<_>>()?;

    // Set up signal forwarding before fork so the handler is in place
    setup_signal_forwarding()?;

    // Block forwarded signals before fork to prevent race between fork() and
    // CHILD_PID.store(). Unblock after the store.
    let mut block_set = SigSet::empty();
    block_set.add(Signal::SIGINT);
    block_set.add(Signal::SIGTERM);
    block_set.add(Signal::SIGHUP);
    block_set.add(Signal::SIGQUIT);
    block_set
        .thread_block()
        .context("failed to block signals before fork")?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            // Unblock signals in child
            let _ = block_set.thread_unblock();

            // Redirect stdout/stderr to /dev/null if silent
            if silent {
                redirect_to_devnull();
            }
            // exec replaces the child process — no return on success
            let _ = execve(&c_binary, &c_args, &c_env);
            // SECURITY: execve only returns on error. Use _exit() (not std::process::exit)
            // to avoid running Rust destructors that could flush shared buffers after fork.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            // Store child PID while signals are still blocked — no race.
            CHILD_PID.store(child.as_raw(), Ordering::SeqCst);

            // Now unblock signals so forwarding works
            block_set
                .thread_unblock()
                .context("failed to unblock signals after fork")?;

            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        CHILD_PID.store(-1, Ordering::SeqCst);
                        return Ok(code);
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        CHILD_PID.store(-1, Ordering::SeqCst);
                        // Re-raise so our exit status reflects the signal
                        let _ = signal::raise(sig);
                        return Ok(128 + sig as i32);
                    }
                    Ok(WaitStatus::Stopped(_, _))
                    | Ok(WaitStatus::Continued(_))
                    | Ok(WaitStatus::StillAlive) => continue,
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {
                        continue
                    }
                    // EINTR from signal delivery — retry waitpid
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => {
                        CHILD_PID.store(-1, Ordering::SeqCst);
                        return Err(e).context("waitpid failed");
                    }
                }
            }
        }
    }
}

fn setup_signal_forwarding() -> Result<()> {
    let handler = SigHandler::Handler(forward_signal);
    let action = SigAction::new(handler, SaFlags::SA_RESTART, SigSet::empty());
    // SAFETY: Our handler is async-signal-safe (only calls kill(2) and an atomic load).
    unsafe {
        signal::sigaction(Signal::SIGINT, &action).context("failed to set SIGINT handler")?;
        signal::sigaction(Signal::SIGTERM, &action).context("failed to set SIGTERM handler")?;
        signal::sigaction(Signal::SIGHUP, &action).context("failed to set SIGHUP handler")?;
        signal::sigaction(Signal::SIGQUIT, &action).context("failed to set SIGQUIT handler")?;
    }
    Ok(())
}

/// Build a minimal, clean environment for the child process.
/// The caller's environment is completely discarded; only safe values are included.
fn build_env(cfg: &Config) -> Vec<String> {
    let mut env = vec![
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "HOME=/root".to_string(),
        "LANG=C".to_string(),
    ];
    if let Some(ref p) = cfg.http_proxy {
        env.push(format!("http_proxy={p}"));
    }
    if let Some(ref p) = cfg.https_proxy {
        env.push(format!("https_proxy={p}"));
    }
    env
}

fn redirect_to_devnull() {
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if fd >= 0 {
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::dup2(fd, libc::STDERR_FILENO);
            libc::close(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_env_no_proxy() {
        let cfg = Config {
            group: "mom".into(),
            deny_list: "/etc/mom/deny.list".into(),
            log_file: "/var/log/mom.log".into(),
            http_proxy: None,
            https_proxy: None,
        };
        let env = build_env(&cfg);
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.iter().any(|e| e == "HOME=/root"));
        assert!(!env.iter().any(|e| e.starts_with("http_proxy=")));
        assert!(!env.iter().any(|e| e.starts_with("https_proxy=")));
    }

    #[test]
    fn test_build_env_with_proxy() {
        let cfg = Config {
            group: "mom".into(),
            deny_list: "/etc/mom/deny.list".into(),
            log_file: "/var/log/mom.log".into(),
            http_proxy: Some("http://proxy.example.com:3128".into()),
            https_proxy: Some("http://proxy.example.com:3128".into()),
        };
        let env = build_env(&cfg);
        assert!(env
            .iter()
            .any(|e| e == "http_proxy=http://proxy.example.com:3128"));
        assert!(env
            .iter()
            .any(|e| e == "https_proxy=http://proxy.example.com:3128"));
    }

    #[test]
    fn test_build_env_no_sensitive_vars() {
        // Simulate a polluted environment — build_env must not include any of these
        unsafe {
            std::env::set_var("LD_PRELOAD", "/evil.so");
            std::env::set_var("EVIL_VAR", "injected");
        }
        let cfg = Config::default();
        let env = build_env(&cfg);
        assert!(!env.iter().any(|e| e.starts_with("LD_PRELOAD=")));
        assert!(!env.iter().any(|e| e.starts_with("EVIL_VAR=")));
    }

    #[test]
    fn test_run_pkg_cmd_missing_binary_exits_127() {
        let cfg = Config::default();
        let rc = run_pkg_cmd("/nonexistent/binary", &["--version".to_string()], &cfg).unwrap();
        assert_eq!(rc, 127);
    }

    #[test]
    fn test_run_pkg_cmd_true_exits_zero() {
        // /usr/bin/true always succeeds — use it as a safe smoke test
        let cfg = Config::default();
        if std::path::Path::new("/usr/bin/true").exists() {
            let rc = run_pkg_cmd("/usr/bin/true", &[], &cfg).unwrap();
            assert_eq!(rc, 0);
        }
    }

    #[test]
    fn test_run_pkg_cmd_false_exits_nonzero() {
        let cfg = Config::default();
        if std::path::Path::new("/usr/bin/false").exists() {
            let rc = run_pkg_cmd("/usr/bin/false", &[], &cfg).unwrap();
            assert_ne!(rc, 0);
        }
    }
}
