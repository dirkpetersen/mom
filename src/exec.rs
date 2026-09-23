use anyhow::{Context, Result};
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::config::Config;
use crate::detect::{PackageManager, DPKG_SAFETY_OPTS};

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

/// How the package manager may interact with the caller's terminal.
///
/// mom clears its whole environment, so without this TERM is unset and
/// debconf falls back to its Readline frontend. A caller without a TTY (a
/// script or AI agent) can then hang on a prompt or get killed mid-dpkg,
/// leaving packages half-installed for everyone.
#[derive(Debug, Clone, PartialEq)]
pub struct Interaction {
    /// No usable terminal (or `-y`): set DEBIAN_FRONTEND=noninteractive.
    /// Conffile prompts are suppressed in every mode (`DPKG_SAFETY_OPTS`).
    noninteractive: bool,
    /// Caller's TERM, validated by `is_valid_term`; only set when interactive.
    term: Option<String>,
}

impl Interaction {
    /// True if no one can answer prompts (`-y` or no TTY on stdin).
    pub fn noninteractive(&self) -> bool {
        self.noninteractive
    }

    pub fn new(yes: bool, stdin_is_tty: bool, term: Option<String>) -> Self {
        let noninteractive = yes || !stdin_is_tty;
        Interaction {
            noninteractive,
            // Re-validate here so no unchecked value can reach the child env.
            term: term.filter(|t| !noninteractive && is_valid_term(t)),
        }
    }
}

/// True if stdin is a terminal.
pub fn stdin_is_tty() -> bool {
    // SAFETY: isatty(3) only inspects the fd.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Maximum accepted length of the caller's TERM value.
const MAX_TERM_LEN: usize = 64;

/// Validate a caller-supplied TERM value: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`.
///
/// SECURITY: TERM is the only caller environment variable that reaches the
/// child. ncurses/terminfo treat a TERM containing `/` as a path, so the
/// charset excludes `/` (and everything else that could form a path or
/// escape sequence); the value is only used to look up a system terminfo entry.
pub fn is_valid_term(term: &str) -> bool {
    let bytes = term.as_bytes();
    match bytes.first() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    bytes.len() <= MAX_TERM_LEN
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

/// Validate a raw TERM value captured from the caller's environment.
/// Non-UTF-8 or invalid values are dropped.
pub fn sanitize_term(raw: Option<std::ffi::OsString>) -> Option<String> {
    raw.and_then(|v| v.into_string().ok())
        .filter(|t| is_valid_term(t))
}

/// Insert the dpkg safety options (`DPKG_SAFETY_OPTS`) right after the
/// subcommand. Applied in every mode, interactive or not.
fn with_dpkg_safety_args(pm: &PackageManager, mut args: Vec<String>) -> Vec<String> {
    if !args.is_empty() {
        args.splice(1..1, pm.dpkg_safety_args());
    }
    args
}

/// Run `apt-get install [packages]` or `dnf install [packages]`.
pub fn install(
    pm: &PackageManager,
    packages: &[String],
    yes: bool,
    no_recommends: bool,
    ui: &Interaction,
    cfg: &Config,
) -> Result<i32> {
    let args = with_dpkg_safety_args(pm, pm.install_cmd_args(packages, yes, no_recommends));
    run_pkg_cmd(pm.binary(), &args, &pkg_env(cfg, pm, ui))
}

/// Refresh repos, then run `apt-get install --only-upgrade` / `dnf upgrade`.
pub fn update(
    pm: &PackageManager,
    packages: &[String],
    yes: bool,
    no_recommends: bool,
    ui: &Interaction,
    cfg: &Config,
) -> Result<i32> {
    // Step 1: refresh
    let rc = refresh(pm, ui, cfg)?;
    if rc != 0 {
        return Ok(rc);
    }
    // Step 2: upgrade
    let args = with_dpkg_safety_args(pm, pm.update_cmd_args(packages, yes, no_recommends));
    run_pkg_cmd(pm.binary(), &args, &pkg_env(cfg, pm, ui))
}

/// Run `apt-get update && apt-get upgrade` / `dnf upgrade` (full system upgrade).
pub fn upgrade(pm: &PackageManager, yes: bool, ui: &Interaction, cfg: &Config) -> Result<i32> {
    let rc = refresh(pm, ui, cfg)?;
    if rc != 0 {
        return Ok(rc);
    }
    let args = with_dpkg_safety_args(pm, pm.upgrade_cmd_args(yes));
    run_pkg_cmd(pm.binary(), &args, &pkg_env(cfg, pm, ui))
}

/// Run `apt-get update` / `dnf makecache`.
pub fn refresh(pm: &PackageManager, ui: &Interaction, cfg: &Config) -> Result<i32> {
    let args = pm.refresh_cmd_args();
    run_pkg_cmd(pm.binary(), &args, &pkg_env(cfg, pm, ui))
}

/// Run `apt-get install --reinstall <packages>` to unpack half-installed
/// packages again. `packages` must come from `dpkg_broken_packages`, never
/// from the caller.
pub fn apt_reinstall(
    packages: &[String],
    yes: bool,
    ui: &Interaction,
    cfg: &Config,
) -> Result<i32> {
    let pm = PackageManager::Apt;
    let args = with_dpkg_safety_args(&pm, pm.reinstall_cmd_args(packages, yes));
    run_pkg_cmd(pm.binary(), &args, &pkg_env(cfg, &pm, ui))
}

/// Directory dpkg uses as its journal of in-progress status updates.
const DPKG_UPDATES_DIR: &str = "/var/lib/dpkg/updates";

/// True if a previous dpkg run was interrupted (e.g. a `mom install` killed
/// with Ctrl+C). Mirrors apt's own check (`debSystem::CheckUpdates`): any file
/// in /var/lib/dpkg/updates whose name is all digits. While this holds, every
/// apt-get operation fails with "dpkg was interrupted, you must manually run
/// 'dpkg --configure -a'", which a non-root caller cannot do.
pub fn dpkg_interrupted() -> bool {
    dpkg_interrupted_in(std::path::Path::new(DPKG_UPDATES_DIR))
}

fn dpkg_interrupted_in(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.as_encoded_bytes();
        !name.is_empty() && name.iter().all(u8::is_ascii_digit)
    })
}

/// Run `dpkg --configure -a` to finish an interrupted dpkg run. Takes no
/// caller input and only configures packages already unpacked on the system.
pub fn dpkg_configure_pending(ui: &Interaction, cfg: &Config) -> Result<i32> {
    // SECURITY: DPKG_SAFETY_OPTS in every mode (no conffile prompt, no
    // pager); dpkg takes these general options before the action.
    let mut args: Vec<String> = DPKG_SAFETY_OPTS.iter().map(|o| o.to_string()).collect();
    args.push("--configure".to_string());
    args.push("-a".to_string());
    run_pkg_cmd(
        "/usr/bin/dpkg",
        &args,
        &pkg_env(cfg, &PackageManager::Apt, ui),
    )
}

/// Output cap for the full dpkg status listing. A large system lists tens of
/// thousands of packages at well under 100 bytes each; 16 MiB is far beyond
/// that while still bounding memory.
const DPKG_STATUS_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Packages whose dpkg status shows an interrupted install, as reported by
/// the root-owned dpkg database.
#[derive(Debug, Default, PartialEq)]
pub struct DpkgBroken {
    /// Status `H` (half-installed) or reinst-required flag `R`: the unpack was
    /// interrupted and the package must be unpacked again (`apt-get install
    /// --reinstall`). `dpkg --configure -a` cannot fix these.
    pub reinstall: Vec<String>,
    /// Status `U` (unpacked), `F` (half-configured), `W` (triggers-awaited) or
    /// `t` (triggers-pending): finished by `dpkg --configure -a`.
    pub configure: Vec<String>,
    /// Broken entries mom will not repair automatically: a name outside the
    /// strict charset, or a half-installed package whose selection is not
    /// install/hold (e.g. an interrupted removal). Escaped for display.
    pub unrepairable: Vec<String>,
}

impl DpkgBroken {
    pub fn is_empty(&self) -> bool {
        self.reinstall.is_empty() && self.configure.is_empty() && self.unrepairable.is_empty()
    }
}

/// Query dpkg for packages left in an intermediate state by an interrupted run.
pub fn dpkg_broken_packages(cfg: &Config) -> Result<DpkgBroken> {
    let args = vec!["-W".to_string(), format!("-f={DPKG_STATUS_FORMAT}")];
    let (rc, output, truncated) = run_capture_full(
        "/usr/bin/dpkg-query",
        &args,
        &build_env(cfg),
        DPKG_STATUS_MAX_BYTES,
    )?;
    if rc != 0 {
        anyhow::bail!("dpkg-query exited with code {rc}");
    }
    // A truncated listing could end in a partial name that happens to be a
    // different, valid package name — never act on it.
    if truncated {
        anyhow::bail!("dpkg status listing exceeds {DPKG_STATUS_MAX_BYTES} bytes");
    }
    Ok(parse_dpkg_status(&output))
}

/// dpkg-query format: 3-char status abbreviation, `|`, package name. `|` can
/// appear in neither field, so each line splits unambiguously even though the
/// abbreviation's third (error-flag) character is normally a space.
const DPKG_STATUS_FORMAT: &str = "${db:Status-Abbrev}|${binary:Package}\\n";

/// Parse `DPKG_STATUS_FORMAT` output. `${db:Status-Abbrev}` is exactly three
/// characters: selection (`u`nknown, `i`nstall, `h`old, `r`emove, `p`urge),
/// status (`n`ot-installed, `c`onfig-files, `H`alf-installed, `U`npacked,
/// half-con`F`igured, triggers-a`W`aited, triggers-pending `t`, `i`nstalled),
/// and error flag (space, or `R` for reinst-required). Malformed lines and
/// unknown status letters are ignored — the operation then fails in apt as it
/// would have without mom's repair step.
fn parse_dpkg_status(output: &str) -> DpkgBroken {
    let mut broken = DpkgBroken::default();
    for line in output.lines() {
        let Some((abbrev, name)) = line.split_once('|') else {
            continue;
        };
        let &[want, status, eflag] = abbrev.as_bytes() else {
            continue;
        };
        let needs_reinstall = status == b'H' || eflag == b'R';
        let needs_configure = matches!(status, b'U' | b'F' | b'W' | b't');
        if !needs_reinstall && !needs_configure {
            continue;
        }
        if !is_valid_dpkg_name(name) {
            broken.unrepairable.push(name.escape_debug().to_string());
        } else if needs_reinstall {
            // Only reinstall what the admin (or an earlier mom run) selected
            // for installation. `apt-get install` on a package whose
            // interrupted operation was a removal/purge would reverse that
            // decision.
            if matches!(want, b'i' | b'h') {
                broken.reinstall.push(name.to_string());
            } else {
                broken.unrepairable.push(name.to_string());
            }
        } else {
            broken.configure.push(name.to_string());
        }
    }
    broken
}

/// Maximum length of the `:arch` qualifier on a dpkg package name.
const MAX_ARCH_LEN: usize = 32;

/// Validate a package name reported by dpkg before it is placed in apt-get's
/// argv.
///
/// SECURITY: `${binary:Package}` appends `:<arch>` for Multi-Arch: same
/// packages (e.g. `libc6:amd64`) — on a typical system many libraries — so
/// rejecting `:` would leave the most common half-installed packages
/// unrepairable. We therefore allow exactly one `:arch` suffix, where the name
/// part must satisfy the caller-input rule (`is_valid_package_name`, length
/// limit) and the arch part must match `^[a-z0-9][a-z0-9-]*$` (Debian
/// architecture names, e.g. `amd64`, `i386`, `hurd-i386`). Neither part can
/// start with `-`, so the result can never be read as an option; apt resolves
/// `name:arch` as an exact package/architecture pair, and since the package is
/// in the dpkg database the exact name wins over apt's regex and trailing
/// `+`/`-` modifier interpretations.
fn is_valid_dpkg_name(name: &str) -> bool {
    let (pkg, arch) = match name.split_once(':') {
        Some((pkg, arch)) => (pkg, Some(arch)),
        None => (name, None),
    };
    if pkg.len() > crate::MAX_PACKAGE_NAME_LEN || !crate::is_valid_package_name(pkg) {
        return false;
    }
    match arch {
        None => true,
        Some(arch) => {
            let bytes = arch.as_bytes();
            matches!(bytes.first(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
                && bytes.len() <= MAX_ARCH_LEN
                && bytes
                    .iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        }
    }
}

/// Check whether a package is currently installed.
///
/// Debian: `dpkg-query -W -f='${db:Status-Abbrev}' <pkg>` — exits 0 and outputs
///         "ii " for installed, "rc " for config-files (removed but not purged).
///         We require "ii " to distinguish truly installed packages.
/// RHEL:   `rpm -q --qf '%{NAME}\n' <pkg>` — exits 0 if installed. We further
///         require a resolved NAME to equal the literal argument, because rpm
///         accepts spec forms like `name.arch` (hydra.x86_64) that would let
///         'mom update' act on a package the literal deny check never saw.
pub fn is_installed(pm: &PackageManager, package: &str, cfg: &Config) -> Result<bool> {
    let args = pm.is_installed_cmd_args(package);
    let env = build_env(cfg);
    match pm {
        PackageManager::Apt => {
            // Single execution: capture output and check both exit code and status prefix.
            let (rc, output) = run_capture(pm.is_installed_binary(), &args, &env, 64)?;
            Ok(rc == 0 && output.starts_with("ii"))
        }
        PackageManager::Dnf => {
            // 64 KiB cap: multiarch installs print one NAME per line.
            let (rc, output) = run_capture(pm.is_installed_binary(), &args, &env, 64 * 1024)?;
            Ok(rc == 0 && any_line_equals(&output, package))
        }
    }
}

/// Confirm that `package` names an *exact* package known to apt.
///
/// `apt-get install` reinterprets an argument as a POSIX regex when it contains
/// `.`/`?`/`*` and matches no package exactly, and treats a trailing `-`/`+` as a
/// remove/install modifier. The package-name validator permits `.`, `+`, and `-`,
/// so without this check a `mom`-group user could smuggle a denied package past
/// the literal deny match (`n.ap` -> `nmap`) or remove arbitrary packages
/// (`bash-` removes `bash`). apt-get prefers an exact package name over both
/// reinterpretations, so once we know the literal string is a real package name,
/// `apt-get install <name>` can only act on that single package and the deny
/// check on the literal string is authoritative.
pub fn apt_package_exists_exact(package: &str, cfg: &Config) -> Result<bool> {
    let env = build_env(cfg);
    let args = vec!["show".to_string(), package.to_string()];
    // apt-cache reads only the local cache (no network) and does not apply the
    // install/remove modifier semantics. We compare the literal string against
    // each `Package:` field, so even if apt-cache itself expanded a regex the
    // result is still rejected unless the literal equals a real package name.
    let (_rc, output) = run_capture("/usr/bin/apt-cache", &args, &env, 256 * 1024)?;
    Ok(show_output_names_exact(&output, package))
}

/// Return true if `apt-cache show` output contains a `Package:` field whose
/// value equals `package` exactly.
fn show_output_names_exact(output: &str, package: &str) -> bool {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("Package:"))
        .any(|name| name.trim() == package)
}

/// Confirm that `package` names an *exact* package known to dnf.
///
/// dnf/rpm accept the `name.arch` spec form (`hydra.x86_64` resolves to
/// `hydra`), and the package-name validator permits `.`, so without this check
/// a `mom`-group user could smuggle a denied package past the literal deny
/// match on RHEL-family systems. `dnf repoquery --qf '%{name}'` resolves the
/// spec the same way `dnf install` would; requiring a resolved NAME to equal
/// the literal argument rejects arch-suffix (and any other spec) forms while
/// still allowing legitimate dotted names like `python3.11`.
pub fn dnf_package_exists_exact(package: &str, cfg: &Config) -> Result<bool> {
    let env = build_env(cfg);
    let args = vec![
        "-q".to_string(),
        "repoquery".to_string(),
        "--qf".to_string(),
        "%{name}\n".to_string(),
        package.to_string(),
    ];
    let (_rc, output) = run_capture(PackageManager::Dnf.binary(), &args, &env, 256 * 1024)?;
    Ok(any_line_equals(&output, package))
}

/// Return true if any trimmed line of `output` equals `package` exactly.
fn any_line_equals(output: &str, package: &str) -> bool {
    output.lines().any(|line| line.trim() == package)
}

/// Fork and exec `binary` with `args`, forwarding stdin/stdout/stderr to the
/// caller's terminal. Signals (SIGINT, SIGTERM, SIGHUP) are forwarded to the
/// child. Returns the child's exit code.
fn run_pkg_cmd(binary: &str, args: &[String], env: &[String]) -> Result<i32> {
    run_execve(binary, args, env, false)
}

/// Run a command and capture its stdout (for parsing output like dpkg-query
/// status or apt-cache stanzas). Stderr is redirected to /dev/null. Returns
/// (exit_code, trimmed_stdout). Accumulated output is capped at `max_bytes` to
/// prevent OOM from a compromised binary; bytes past the cap are drained and
/// discarded so the child never blocks on a full pipe.
fn run_capture(
    binary: &str,
    args: &[String],
    env: &[String],
    max_bytes: usize,
) -> Result<(i32, String)> {
    let (rc, output, _truncated) = run_capture_full(binary, args, env, max_bytes)?;
    Ok((rc, output))
}

/// Like `run_capture`, but also reports whether output was truncated at
/// `max_bytes`, for callers that must not act on a partial listing.
fn run_capture_full(
    binary: &str,
    args: &[String],
    env: &[String],
    max_bytes: usize,
) -> Result<(i32, String, bool)> {
    let c_binary = CString::new(binary).context("binary path contains null byte")?;
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_binary.clone());
    for arg in args {
        c_args.push(CString::new(arg.as_str()).context("argument contains null byte")?);
    }
    let c_env: Vec<CString> = env
        .iter()
        .map(|e| CString::new(e.as_str()).context("env var contains null byte"))
        .collect::<Result<_>>()?;

    // Create a pipe with O_CLOEXEC so fds are not leaked to exec'd children
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        anyhow::bail!("pipe2() failed: {}", std::io::Error::last_os_error());
    }
    let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);

    let fork_result = unsafe { fork() };
    match fork_result {
        Err(e) => {
            // Clean up pipe fds on fork failure
            unsafe {
                libc::close(pipe_read);
                libc::close(pipe_write);
            }
            Err(e).context("fork failed")
        }
        Ok(ForkResult::Child) => {
            unsafe {
                libc::setresuid(0, 0, 0);
                libc::umask(0o022);
                libc::close(pipe_read);
                // dup pipe write end to stdout; abort child on failure to
                // prevent dpkg-query output leaking to the terminal
                if libc::dup2(pipe_write, libc::STDOUT_FILENO) < 0 {
                    libc::_exit(126);
                }
                libc::close(pipe_write);
                // Stderr to /dev/null
                let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                if devnull < 0 || libc::dup2(devnull, libc::STDERR_FILENO) < 0 {
                    libc::_exit(126);
                }
                libc::close(devnull);
            }
            let _ = execve(&c_binary, &c_args, &c_env);
            unsafe { libc::_exit(127) };
        }
        Ok(ForkResult::Parent { child }) => {
            unsafe { libc::close(pipe_write) };
            // Read stdout from the pipe. Accumulation is capped at `max_bytes`,
            // but we keep draining past the cap so the child never blocks on a
            // full pipe (which would deadlock the waitpid below).
            let mut file = unsafe { File::from_raw_fd(pipe_read) };
            use std::io::Read;
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut truncated = false;
            loop {
                match file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let room = max_bytes - buf.len();
                        if n > room {
                            truncated = true;
                        }
                        buf.extend_from_slice(&chunk[..n.min(room)]);
                        // bytes beyond the cap are read and discarded to drain
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            drop(file); // closes pipe_read
            let exit_code = loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => break code,
                    Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                    Err(nix::errno::Errno::EINTR) => continue,
                    _ => continue,
                }
            };
            let output = String::from_utf8_lossy(&buf).trim().to_string();
            Ok((exit_code, output, truncated))
        }
    }
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

            // Set all UIDs to root before exec. In a setuid context, the real
            // UID is the calling user (non-root). Modern apt-get/dpkg detect
            // ruid != euid and refuse privileged operations (dpkg returns
            // "requested operation requires superuser privilege"). All
            // authorization checks have already passed in the parent, so
            // presenting a clean root identity to the package manager is safe.
            unsafe { libc::setresuid(0, 0, 0) };

            // SECURITY: Reset umask to 0o022 before exec. The parent's
            // umask(0o077) is inherited across fork; if left in place,
            // apt-get creates /var/cache/apt/archives/partial/ as mode 700,
            // blocking the _apt user that apt uses for downloading packages.
            unsafe { libc::umask(0o022) };

            // Redirect stdout/stderr to /dev/null if silent
            if silent && !redirect_to_devnull() {
                // Cannot safely proceed with inherited stdout/stderr in a
                // setuid context — abort the child.
                unsafe { libc::_exit(126) };
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

/// Fixed variables for every package-manager run, in every mode.
///
/// SECURITY: package-manager runs share the caller's terminal while running as
/// root, so any helper that starts a pager or other interactive program hands
/// the caller a root shell (`less` allows `!cmd`). apt-listchanges' default
/// pager frontend runs sensible-pager as root and reopens /dev/tty even when
/// stdin is not a TTY; apt-listbugs can launch a browser. Disable both, point
/// every pager variable at `cat`, and set LESSSECURE=1 so a `less` that still
/// runs has shell escapes disabled. debconf stays interactive on a TTY, but
/// pinned to a frontend without shell-out (see `pkg_env`).
const PAGER_SAFETY_ENV: [&str; 4] = [
    "PAGER=cat",
    "SYSTEMD_PAGER=cat",
    "LESSSECURE=1",
    "MANPAGER=cat",
];

/// apt/dpkg-specific additions to `PAGER_SAFETY_ENV`.
///
/// SECURITY: ucf (called from many postinsts to manage files in /etc) has its
/// own conffile prompt, debconf `ucf/changeprompt`, whose "start a new shell"
/// choice runs `bash </dev/tty >/dev/tty` as root. UCF_FORCE_CONFFOLD=1 makes
/// ucf keep the existing file without asking, matching `--force-confold` in
/// `DPKG_SAFETY_OPTS`. NEEDRESTART_MODE=l makes needrestart only list stale
/// services: it never prompts, and never restarts services on behalf of a mom
/// user.
const APT_SAFETY_ENV: [&str; 5] = [
    "APT_LISTCHANGES_FRONTEND=none",
    "APT_LISTBUGS_FRONTEND=none",
    "DPKG_PAGER=cat",
    "UCF_FORCE_CONFFOLD=1",
    "NEEDRESTART_MODE=l",
];

/// Environment for package-manager runs attached to the caller's terminal:
/// `build_env`, the fixed pager/helper safety variables, and the terminal
/// handling chosen in `Interaction`.
///
/// SECURITY: every value is a fixed constant except TERM, the only
/// caller-derived value, which has passed `is_valid_term`; TERMINFO, TERMCAP
/// and all other terminal variables stay cleared. DEBIAN_FRONTEND is always
/// set on apt: with it unset, debconf would use the frontend configured in its
/// database, which may be Editor (runs /usr/bin/editor, e.g. vim `:!sh`, as
/// root), Web, Gnome or Kde. `dialog` falls back to Readline and then
/// Teletype when no dialog program or terminal is usable; none of these can
/// shell out.
fn pkg_env(cfg: &Config, pm: &PackageManager, ui: &Interaction) -> Vec<String> {
    let mut env = build_env(cfg);
    env.extend(PAGER_SAFETY_ENV.iter().map(|v| v.to_string()));
    if *pm == PackageManager::Apt {
        env.extend(APT_SAFETY_ENV.iter().map(|v| v.to_string()));
    }
    if *pm == PackageManager::Apt {
        env.push(if ui.noninteractive {
            "DEBIAN_FRONTEND=noninteractive".to_string()
        } else {
            "DEBIAN_FRONTEND=dialog".to_string()
        });
    }
    if !ui.noninteractive {
        if let Some(term) = ui.term.as_deref().filter(|t| is_valid_term(t)) {
            env.push(format!("TERM={term}"));
        }
    }
    env
}

/// Redirect stdout and stderr to /dev/null. Returns false on failure.
fn redirect_to_devnull() -> bool {
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if fd < 0 {
            return false;
        }
        let ok =
            libc::dup2(fd, libc::STDOUT_FILENO) >= 0 && libc::dup2(fd, libc::STDERR_FILENO) >= 0;
        libc::close(fd);
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpkg_interrupted_detection() {
        let dir = tempfile::tempdir().unwrap();
        // Missing directory: not interrupted
        assert!(!dpkg_interrupted_in(&dir.path().join("missing")));
        // Empty directory: not interrupted
        assert!(!dpkg_interrupted_in(dir.path()));
        // Non-numeric names (e.g. dpkg's "tmp.i") are ignored, as apt does
        std::fs::write(dir.path().join("tmp.i"), "").unwrap();
        assert!(!dpkg_interrupted_in(dir.path()));
        // A numbered journal file means dpkg was interrupted
        std::fs::write(dir.path().join("0001"), "").unwrap();
        assert!(dpkg_interrupted_in(dir.path()));
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_dpkg_status_healthy() {
        // ii (installed) and rc (config-files) need no repair
        let out = "ii |curl\nrc |oldpkg\nii |libc6:amd64\nun |never-installed\n";
        assert_eq!(parse_dpkg_status(out), DpkgBroken::default());
        assert!(parse_dpkg_status(out).is_empty());
    }

    #[test]
    fn test_parse_dpkg_status_half_installed() {
        let out = "ii |curl\niHR|libpam-runtime\niH |libfoo1:amd64\nhH |held-pkg\n";
        let b = parse_dpkg_status(out);
        assert_eq!(
            b.reinstall,
            names(&["libpam-runtime", "libfoo1:amd64", "held-pkg"])
        );
        assert!(b.configure.is_empty());
        assert!(b.unrepairable.is_empty());
    }

    #[test]
    fn test_parse_dpkg_status_reinst_required_flag() {
        // The R error flag alone (any status) means the package must be reinstalled
        let b = parse_dpkg_status("iUR|libbar\n");
        assert_eq!(b.reinstall, names(&["libbar"]));
        assert!(b.configure.is_empty());
    }

    #[test]
    fn test_parse_dpkg_status_configure_states() {
        let out = "iU |unpacked\niF |halfconf\niW |awaiting:i386\nit |pending\n";
        let b = parse_dpkg_status(out);
        assert_eq!(
            b.configure,
            names(&["unpacked", "halfconf", "awaiting:i386", "pending"])
        );
        assert!(b.reinstall.is_empty());
        assert!(b.unrepairable.is_empty());
    }

    #[test]
    fn test_parse_dpkg_status_interrupted_removal_not_reinstalled() {
        // Reinstalling would reverse the admin's remove/purge decision
        let b = parse_dpkg_status("rH |going-away\npHR|purged\nuH |unknown-sel\n");
        assert!(b.reinstall.is_empty());
        assert_eq!(
            b.unrepairable,
            names(&["going-away", "purged", "unknown-sel"])
        );
    }

    #[test]
    fn test_parse_dpkg_status_malformed_lines_ignored() {
        let out = "\ngarbage\niH\niHlibfoo\niH  |toolong-abbrev\ni|x\n|\niX |unknown-status\n";
        assert_eq!(parse_dpkg_status(out), DpkgBroken::default());
    }

    #[test]
    fn test_parse_dpkg_status_invalid_names_unrepairable() {
        let out = "iH |-o\niH |foo:amd64:i386\niH |foo:AMD64\niH |foo:\niH |:amd64\n\
                   iH |foo bar\niU |evil;rm\niH |\n";
        let b = parse_dpkg_status(out);
        assert!(b.reinstall.is_empty());
        assert!(b.configure.is_empty());
        assert_eq!(b.unrepairable.len(), 8);
    }

    #[test]
    fn test_parse_dpkg_status_unrepairable_escaped() {
        let b = parse_dpkg_status("iH |x\u{1b}[2J\n");
        assert_eq!(b.unrepairable, names(&["x\\u{1b}[2J"]));
    }

    #[test]
    fn test_valid_dpkg_names() {
        for name in [
            "libpam-runtime",
            "g++",
            "libc6:amd64",
            "libc6:i386",
            "libfoo:hurd-i386",
            "gir1.2-glib-2.0:arm64",
        ] {
            assert!(is_valid_dpkg_name(name), "expected valid: {name}");
        }
        let long = "a".repeat(crate::MAX_PACKAGE_NAME_LEN + 1);
        let long_arch = format!("foo:{}", "a".repeat(MAX_ARCH_LEN + 1));
        for name in [
            "",
            "-foo",
            "foo:",
            ":amd64",
            "foo:-amd64",
            "foo:amd64:i386",
            "foo:amd_64",
            "foo=1.0",
            "foo/bar",
            long.as_str(),
            long_arch.as_str(),
        ] {
            assert!(!is_valid_dpkg_name(name), "expected invalid: {name}");
        }
    }

    #[test]
    fn test_valid_terms() {
        for t in [
            "xterm-256color",
            "screen.xterm",
            "xterm",
            "vt100",
            "rxvt-unicode",
            "st+x_y",
        ] {
            assert!(is_valid_term(t), "expected valid: {t}");
        }
        assert!(is_valid_term(&"a".repeat(MAX_TERM_LEN)));
    }

    #[test]
    fn test_invalid_terms() {
        let overlong = "a".repeat(MAX_TERM_LEN + 1);
        for t in [
            "",
            "../x",
            "/usr/share/terminfo/x",
            "x/y",
            ".xterm",
            "-xterm",
            "xterm\n",
            "xterm\u{1b}",
            "xterm\0",
            "xterm 256",
            "xterm=1",
            "xtérm",
            overlong.as_str(),
        ] {
            assert!(!is_valid_term(t), "expected invalid: {t:?}");
        }
    }

    #[test]
    fn test_sanitize_term() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(sanitize_term(None), None);
        assert_eq!(
            sanitize_term(Some(OsString::from("xterm-256color"))),
            Some("xterm-256color".to_string())
        );
        assert_eq!(sanitize_term(Some(OsString::from("../x"))), None);
        assert_eq!(
            sanitize_term(Some(OsString::from_vec(vec![b'x', 0xff]))),
            None
        );
    }

    #[test]
    fn test_interaction_modes() {
        let term = || Some("xterm".to_string());
        // Interactive TTY, no -y: TERM passed through
        let ui = Interaction::new(false, true, term());
        assert!(!ui.noninteractive);
        assert_eq!(ui.term.as_deref(), Some("xterm"));
        // -y or no TTY: non-interactive, TERM dropped
        for ui in [
            Interaction::new(true, true, term()),
            Interaction::new(false, false, term()),
            Interaction::new(true, false, term()),
        ] {
            assert!(ui.noninteractive);
            assert_eq!(ui.term, None);
        }
        // Invalid TERM never survives construction
        let ui = Interaction::new(false, true, Some("/tmp/evil".to_string()));
        assert_eq!(ui.term, None);
    }

    #[test]
    fn test_pkg_env_noninteractive_apt() {
        let cfg = Config::default();
        let ui = Interaction::new(true, true, Some("xterm".to_string()));
        let env = pkg_env(&cfg, &PackageManager::Apt, &ui);
        assert!(env.iter().any(|e| e == "DEBIAN_FRONTEND=noninteractive"));
        assert!(!env.iter().any(|e| e == "DEBIAN_FRONTEND=dialog"));
        assert!(!env.iter().any(|e| e.starts_with("TERM=")));
        // DEBIAN_FRONTEND is apt-scoped
        let env = pkg_env(&cfg, &PackageManager::Dnf, &ui);
        assert!(!env.iter().any(|e| e.starts_with("DEBIAN_FRONTEND=")));
    }

    #[test]
    fn test_pkg_env_interactive_term() {
        let cfg = Config::default();
        let ui = Interaction::new(false, true, Some("xterm-256color".to_string()));
        let env = pkg_env(&cfg, &PackageManager::Apt, &ui);
        assert!(env.iter().any(|e| e == "TERM=xterm-256color"));
        assert!(!env.iter().any(|e| e.starts_with("TERMINFO")));
        // debconf pinned to Dialog (never the DB-configured frontend), exactly once
        let frontends: Vec<_> = env
            .iter()
            .filter(|e| e.starts_with("DEBIAN_FRONTEND="))
            .collect();
        assert_eq!(frontends, vec!["DEBIAN_FRONTEND=dialog"]);
        // No TERM captured: none added, frontend still pinned
        let ui = Interaction::new(false, true, None);
        let env = pkg_env(&cfg, &PackageManager::Apt, &ui);
        assert!(!env.iter().any(|e| e.starts_with("TERM=")));
        assert!(env.iter().any(|e| e == "DEBIAN_FRONTEND=dialog"));
        // DEBIAN_FRONTEND is apt-scoped
        let env = pkg_env(&cfg, &PackageManager::Dnf, &ui);
        assert!(!env.iter().any(|e| e.starts_with("DEBIAN_FRONTEND=")));
    }

    const SAFETY_ARGV: [&str; 6] = [
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "-o",
        "Dpkg::Options::=--no-pager",
    ];

    #[test]
    fn test_dpkg_safety_args_every_apt_call() {
        // Unconditional: the args do not depend on -y or on a TTY.
        let pm = PackageManager::Apt;
        let pkgs = names(&["curl"]);
        let with = |mut head: Vec<&'static str>, tail: &[&'static str]| -> Vec<String> {
            head.splice(1..1, SAFETY_ARGV);
            head.extend_from_slice(tail);
            head.into_iter().map(String::from).collect()
        };
        assert_eq!(
            with_dpkg_safety_args(&pm, pm.install_cmd_args(&pkgs, false, false)),
            with(vec!["install"], &["curl"])
        );
        assert_eq!(
            with_dpkg_safety_args(&pm, pm.install_cmd_args(&pkgs, true, false)),
            with(vec!["install"], &["-y", "curl"])
        );
        assert_eq!(
            with_dpkg_safety_args(&pm, pm.update_cmd_args(&pkgs, false, false)),
            with(vec!["install"], &["--only-upgrade", "curl"])
        );
        assert_eq!(
            with_dpkg_safety_args(&pm, pm.upgrade_cmd_args(false)),
            with(vec!["upgrade"], &[])
        );
        assert_eq!(
            with_dpkg_safety_args(&pm, pm.reinstall_cmd_args(&pkgs, false)),
            with(vec!["install"], &["--reinstall", "curl"])
        );
        // dnf gets no extra argv
        let dnf = PackageManager::Dnf;
        let args = dnf.install_cmd_args(&pkgs, true, false);
        assert_eq!(with_dpkg_safety_args(&dnf, args.clone()), args);
    }

    #[test]
    fn test_dpkg_safety_opts_for_direct_dpkg() {
        assert_eq!(
            DPKG_SAFETY_OPTS,
            ["--force-confdef", "--force-confold", "--no-pager"]
        );
    }

    #[test]
    fn test_pkg_env_safety_vars_all_modes() {
        let cfg = Config::default();
        let modes = [
            Interaction::new(false, true, Some("xterm".to_string())),
            Interaction::new(true, true, None),
            Interaction::new(false, false, None),
        ];
        for ui in &modes {
            let env = pkg_env(&cfg, &PackageManager::Apt, ui);
            for var in [
                "APT_LISTCHANGES_FRONTEND=none",
                "APT_LISTBUGS_FRONTEND=none",
                "PAGER=cat",
                "DPKG_PAGER=cat",
                "SYSTEMD_PAGER=cat",
                "LESSSECURE=1",
                "UCF_FORCE_CONFFOLD=1",
                "NEEDRESTART_MODE=l",
            ] {
                assert!(env.iter().any(|e| e == var), "missing {var} in {ui:?}");
            }
            let env = pkg_env(&cfg, &PackageManager::Dnf, ui);
            assert!(env.iter().any(|e| e == "PAGER=cat"));
            assert!(env.iter().any(|e| e == "LESSSECURE=1"));
            assert!(!env
                .iter()
                .any(|e| e.starts_with("APT_LISTCHANGES_FRONTEND=")));
            assert!(!env.iter().any(|e| e.starts_with("UCF_FORCE_CONFFOLD=")));
        }
    }

    #[test]
    fn test_run_capture_full_reports_truncation() {
        if !std::path::Path::new("/usr/bin/echo").exists() {
            return;
        }
        let env = build_env(&Config::default());
        let args = vec!["hello world".to_string()];
        let (rc, out, truncated) = run_capture_full("/usr/bin/echo", &args, &env, 5).unwrap();
        assert_eq!((rc, out.as_str(), truncated), (0, "hello", true));
        let (_, out, truncated) = run_capture_full("/usr/bin/echo", &args, &env, 1024).unwrap();
        assert_eq!((out.as_str(), truncated), ("hello world", false));
    }

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
    fn test_show_output_exact_match() {
        let out = "Package: nmap\nVersion: 7.94\nDescription: scanner\n";
        assert!(show_output_names_exact(out, "nmap"));
    }

    #[test]
    fn test_show_output_regex_smuggle_rejected() {
        // `n.ap` triggers apt regex mode and resolves to nmap; the literal
        // string must NOT be accepted as an exact package (finding 1).
        let out = "Package: nmap\nVersion: 7.94\n";
        assert!(!show_output_names_exact(out, "n.ap"));
    }

    #[test]
    fn test_show_output_trailing_dash_rejected() {
        // `bash-` is apt's remove modifier; apt-cache reports no such package
        // so it must be rejected (finding 2).
        let out = "";
        assert!(!show_output_names_exact(out, "bash-"));
    }

    #[test]
    fn test_show_output_trailing_plus_rejected() {
        // `nmap+` (apt install modifier) does not name an exact package.
        let out = "Package: nmap\n";
        assert!(!show_output_names_exact(out, "nmap+"));
    }

    #[test]
    fn test_show_output_legit_plus_name_accepted() {
        // `g++` legitimately ends in `+` and is a real package — must pass.
        let out = "Package: g++\nVersion: 4:13.2.0\n";
        assert!(show_output_names_exact(out, "g++"));
    }

    #[test]
    fn test_show_output_legit_dotted_name_accepted() {
        // `.` is legal in Debian names (e.g. gir1.2-glib-2.0) — must pass.
        let out = "Package: gir1.2-glib-2.0\nVersion: 2.80\n";
        assert!(show_output_names_exact(out, "gir1.2-glib-2.0"));
    }

    #[test]
    fn test_show_output_empty_rejected() {
        assert!(!show_output_names_exact("", "anything"));
    }

    #[test]
    fn test_dnf_arch_suffix_rejected() {
        // `hydra.x86_64` resolves to NAME `hydra`; the literal must NOT be
        // accepted as an exact package (dnf deny-list bypass finding).
        assert!(!any_line_equals("hydra\n", "hydra.x86_64"));
    }

    #[test]
    fn test_dnf_exact_name_accepted() {
        assert!(any_line_equals("hydra\n", "hydra"));
    }

    #[test]
    fn test_dnf_legit_dotted_name_accepted() {
        // `python3.11` is a real RHEL package whose NAME contains a dot.
        assert!(any_line_equals("python3.11\n", "python3.11"));
    }

    #[test]
    fn test_dnf_multiarch_lines_accepted() {
        // rpm -q on a multiarch install prints one NAME per line.
        assert!(any_line_equals("curl\ncurl\n", "curl"));
    }

    #[test]
    fn test_dnf_empty_output_rejected() {
        assert!(!any_line_equals("", "anything"));
    }

    #[test]
    fn test_run_pkg_cmd_missing_binary_exits_127() {
        let cfg = Config::default();
        let rc = run_pkg_cmd(
            "/nonexistent/binary",
            &["--version".to_string()],
            &build_env(&cfg),
        )
        .unwrap();
        assert_eq!(rc, 127);
    }

    #[test]
    fn test_run_pkg_cmd_true_exits_zero() {
        // /usr/bin/true always succeeds — use it as a safe smoke test
        let cfg = Config::default();
        if std::path::Path::new("/usr/bin/true").exists() {
            let rc = run_pkg_cmd("/usr/bin/true", &[], &build_env(&cfg)).unwrap();
            assert_eq!(rc, 0);
        }
    }

    #[test]
    fn test_run_pkg_cmd_false_exits_nonzero() {
        let cfg = Config::default();
        if std::path::Path::new("/usr/bin/false").exists() {
            let rc = run_pkg_cmd("/usr/bin/false", &[], &build_env(&cfg)).unwrap();
            assert_ne!(rc, 0);
        }
    }
}
