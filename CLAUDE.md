# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mom** (Meta Overlay Manager) is a Rust tool that allows non-root users to install and update packages on systems where they lack root access. It wraps `apt-get` (Debian/Ubuntu) and `dnf` (RHEL/Rocky/Alma/Amazon Linux) and runs as a **setuid-root binary** with group-restricted execute permissions.

The crate is named `mom-inst` (that is also the .deb/.rpm package name); the binary is `mom`.

This tool runs with elevated privileges on behalf of untrusted users. Treat every design and implementation decision as a security-critical choice. `SECURITY.md` holds the threat model; update it when you change the attack surface.

## Agent Workflow (required)

For every change in this repo:

1. **Code**: write all code changes with a background agent running the **Opus** model.
2. **Security review**: before each commit, have a background agent running the **Fable** model do a security review of the pending diff. Fix what it finds before committing.
3. **Docs**: once the code is final, have a background agent running the **Sonnet** model update the README, the man page (`doc/mom.8`), the bash completion (`completions/mom.bash`), `SECURITY.md`, this file, and anything else the change affects.

The Fable security review (step 2) and the Sonnet docs update (step 3) can run in parallel.

## Build & Development Commands

```bash
cargo build                  # debug build
cargo build --release        # release build (lto, opt-level=z, panic=abort, stripped)
cargo test                   # run all tests (unit tests live in #[cfg(test)] mod in each src file)
cargo test <test_name>       # run a single test, e.g. cargo test test_invalid_package_names
cargo fmt --all -- --check   # CI format check
cargo clippy --locked --all-targets --all-features -- -D warnings   # CI lint, exactly as run in CI
cargo audit                  # dependency vulnerability scan
cargo fuzz run fuzz_package_name   # fuzz targets in fuzz/ (needs cargo-fuzz, nightly)
cargo fuzz run fuzz_deny_list
```

The binary refuses to run unless its effective UID is 0, so `cargo run` as a normal user only exercises the "not setuid" error path. To test end-to-end, install the binary setuid-root in a disposable container or VM.

## CLI Interface

```
mom install <pkg> [pkg...]    # install one or more packages
mom update <pkg> [pkg...]     # refresh repos, then update named packages (errors if not installed)
mom upgrade                   # refresh repos, then full system upgrade (apt-get upgrade / dnf upgrade)
mom refresh                   # refresh repo metadata only (apt-get update / dnf makecache)
mom --check                   # validate config, deny list, binary perms; no package operations
mom --version | --help
```

Global flags: `-y/--yes` (passed through as `-y`) and `--no-recommends` (`--no-install-recommends` / `--setopt=install_weak_deps=False`). Every subcommand, including `--check` and `refresh`, requires group membership.

**Explicitly not supported** (by design, do not add): removing packages, version pinning (`foo=1.2.3`), adding or modifying repositories, and installing from `.deb`/`.rpm` files, URLs, or other internet sources.

## Architecture

`src/main.rs` owns the whole control flow. Each subcommand arm runs the same pipeline, and **the order matters for security**:

1. `main()`: `TERM` is read from the caller's environment and validated (`exec::sanitize_term`) **before** anything else runs; it is the only caller env var carried past this point. Then `libc::clearenv()` and `umask(0o077)` run **before** `Cli::parse()` or anything else can read attacker-controlled env.
2. Check that euid == 0. Capture the real uid/gid, then `auth::drop_supplemental_groups()`.
3. `config::Config::load()` reads `/etc/mom/mom.conf`, falling back to defaults if it is absent.
4. `require_group_membership()`: on failure it logs a denied entry, sleeps 2s to rate-limit, and bails.
5. `validate_packages()`: enforces the count limit (100), length limit (256), and name regex, then runs `deny::DenyList::load()` and glob-matches each name.
6. `detect::detect_package_manager()`: apt-get vs dnf by binary existence, cross-checked against `/etc/debian_version` / `/etc/redhat-release`.
7. `install` only: `exec::apt_package_exists_exact` / `dnf_package_exists_exact`. The literal name must equal a real package name. The allowed chars `.+-` collide with apt regex matching, the trailing `-`/`+` remove/install modifiers, and dnf `name.arch` specs, any of which would let a name bypass the deny list. `update` instead checks `exec::is_installed` (dpkg-query / rpm -q, again comparing the exact name).
8. `repair_dpkg_if_interrupted()` (`install`/`update`/`upgrade`, apt only): re-reads dpkg's own status database (`exec::dpkg_broken_packages`), re-validates any broken package name (`is_valid_dpkg_name`) before it can reach argv, and runs the deny list against those names too. A denied broken package, or one whose interrupted operation was a remove/purge, refuses the whole operation rather than being repaired (denial is logged and rate-limited with the same 2s sleep as other denials). Otherwise it reinstalls half-installed packages (`apt-get install --reinstall`, auto-confirmed with `-y` when stdin isn't a TTY so it can't stall on apt's own prompt) and finishes with `dpkg --configure -a`, logged as audit operation `repair`; a failed pre-reinstall `dpkg --configure -a` pass is also audit-logged (outcome `failed`) before the reinstall is attempted. Runs after package validation and exact-name checks, before the "initiated" audit entry for the caller's own operation.
9. `require_audit_log()`: the "initiated" entry **must** reach the log file or syslog, or the operation is refused. Denial and outcome entries are best-effort.
10. `exec::*` forks and `execve`s the package manager, then `log_outcome()` records the result.

Module responsibilities:
- `auth.rs`: dropping groups, uid→name, group membership checks, and group→gid lookup.
- `config.rs`: the conf parser, plus the shared file-safety helpers `open_nofollow` and `validate_file_metadata` (open-then-fstat, TOCTOU-safe, with `FileOwnership::Root` or `RootOrGroup(gid)`). Reuse these for any new privileged file read. Config paths and proxy URLs are validated too.
- `deny.rs`: parses the deny list (whitespace-separated globs, `#` comments). It must be owned by root, and its group must be root or the configured group. A missing file means an empty list.
- `detect.rs`: the `PackageManager` enum. It builds all argv vectors (`install_cmd_args`, `update_cmd_args`, `upgrade_cmd_args`, `reinstall_cmd_args`, …) and holds the hardcoded binary paths. `DPKG_SAFETY_OPTS` (`--force-confdef --force-confold --no-pager`) and `dpkg_safety_args()` (the apt `-o Dpkg::Options::=` form) are fixed constants mom passes on **every** apt-get/dpkg invocation, unconditionally — see Security Invariants.
- `exec.rs`: fork/execve, signal forwarding (SIGINT/TERM/HUP/QUIT to the child via the `CHILD_PID` atomic), and `run_capture`/`run_capture_full` for queries with bounded, truncation-detecting output. `build_env()` is the base child environment: `PATH`, `HOME=/root`, `LANG=C`, plus the configured proxies — it is no longer the whole story. `pkg_env()` layers on top of it for every package-manager run, in every mode: fixed pager/helper-safety constants (`PAGER=cat`, `SYSTEMD_PAGER=cat`, `MANPAGER=cat`, `LESSSECURE=1`, plus on apt `APT_LISTCHANGES_FRONTEND=none`, `APT_LISTBUGS_FRONTEND=none`, `DPKG_PAGER=cat`, `UCF_FORCE_CONFFOLD=1`, `NEEDRESTART_MODE=l`). On apt, `DEBIAN_FRONTEND` is then always set to one of two fixed constants, never left unset: `noninteractive` when `ui.noninteractive` (stdin is not a TTY or `-y`), otherwise `dialog` — interactive mode is `DEBIAN_FRONTEND=dialog` **plus** a validated caller `TERM`, not TERM alone; leaving `DEBIAN_FRONTEND` unset would let debconf fall back to whatever frontend is configured in its own database (`Editor` runs a root shell via `vim :!sh`; `Web`/`Gnome`/`Kde` are equally unwanted). All of this is driven by the `Interaction` struct built in `main()`. Separately, `with_dpkg_safety_args()` splices `dpkg_safety_args()`/`DPKG_SAFETY_OPTS` into every apt-get install/update/upgrade/reinstall call and every `dpkg --configure -a`, **unconditionally in every mode** (not gated on `Interaction`), so a caller can never reach dpkg's conffile prompt (which offers a root shell or a pager shell-escape); `UCF_FORCE_CONFFOLD=1` does the same for `ucf`'s independent conffile prompt. In the child, `setresuid(0,0,0)` (dpkg refuses ruid≠euid) and `umask(0o022)` (so apt's `_apt` user can write partial downloads) run before exec. The child calls `_exit`, never `exit`.
- `log.rs`: `AuditLogger` writes JSON lines to the log file and to syslog (`LOG_AUTH`). `log()` returns whether at least one sink succeeded.
- `check.rs`: `--check` diagnostics for sysadmins (config, deny list, binary mode/owner).

## Security Invariants

- Never use `sh -c`, `system()`, or `popen()`. Pass arguments as discrete `execve` argv entries, and use hardcoded absolute binary paths (`/usr/bin/apt-get`, `/usr/bin/dnf`, `/usr/bin/apt-cache`, dpkg-query, rpm).
- Package names must match `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$` (`is_valid_package_name` in main.rs). Loosening this also requires revisiting the exact-name checks in step 7.
- The deny check runs on the literal string. Any new code path that hands a user-supplied name to apt/dnf needs the same exact-name resolution, or the deny list can be bypassed (see recent commits a9842a4 and 2b65aa5).
- Every authorization failure (not in group, denied package, invalid name, config validation failure) must be audit-logged.
- Pass apt/dnf stdout/stderr straight through. Rely on apt/dnf's own locking; do not add a separate lock file.
- `DPKG_SAFETY_OPTS` (`--force-confdef --force-confold --no-pager`) must reach every apt-get install/update/upgrade/reinstall call and every `dpkg --configure -a`, **unconditionally, in every mode** — not gated behind `-y` or `Interaction`/TTY state. This closes dpkg's conffile prompt, which otherwise offers an interactive caller a root shell (`Z`) or a pager shell-escape (`D`); removing or conditionalizing it reopens that root-escalation path. Likewise, the fixed pager/helper-safety env vars (`PAGER`, `SYSTEMD_PAGER`, `MANPAGER=cat`, `LESSSECURE=1`, and on apt `APT_LISTCHANGES_FRONTEND`/`APT_LISTBUGS_FRONTEND`/`DPKG_PAGER`/`UCF_FORCE_CONFFOLD`/`NEEDRESTART_MODE`) must be set in every mode.
- `DEBIAN_FRONTEND` must always be set to a fixed constant on apt (`noninteractive` or `dialog`), never left unset and never caller-derived. Interactive mode is `DEBIAN_FRONTEND=dialog` plus a validated `TERM` — TERM alone is not enough, since an unset `DEBIAN_FRONTEND` lets debconf fall back to an admin-configured frontend (`Editor` shells out via `vim :!sh`).

## Configuration

`/etc/mom/mom.conf` uses a key = value format. It must be root-owned and not group- or world-writable. Keys and defaults: `group` (`mom`), `deny_list` (`/etc/mom/deny.list`), `log_file` (`/var/log/mom.log`), `http_proxy`, `https_proxy` (proxy vars are passed only to the child).

Deny list sources live in `deny/`: a generic `deny.list` plus `deny.apt.list` / `deny.dnf.list`. At install time, the package postinst scripts concatenate generic + OS-specific into `/etc/mom/deny.list`, owned `root:mom` with mode 640, but only if that file is empty or missing.

Audit log format is one JSON object per line: `timestamp, real_uid, real_user, operation, packages, outcome (initiated|success|failed|denied), detail`.

## Packaging & Release

- `.github/workflows/ci.yml` runs fmt, clippy, test, audit, and x86_64/aarch64 cross builds on push/PR to `main`.
- `.github/workflows/release.yml` runs on a `v*.*.*` tag. It builds binaries, then assembles the `.deb` (Debian bookworm, Ubuntu 22.04/24.04/26.04) and `.rpm` (Rocky 9, Alma 10, Amazon Linux 2023) packages **inline in the workflow**: the DEBIAN control files, the rpm spec, the postinst logic, the default mom.conf, and the logrotate config are all generated there. Packaging changes usually go in release.yml.
- The `debian/` directory is a separate dh/cargo source-package layout (for distro-style builds). Keep it in sync with release.yml when packaging behavior changes.
- Shipped extras: `doc/mom.8` (man page, which documents `chmod 4750 /usr/bin/mom && chown root:mom /usr/bin/mom`), `completions/mom.bash`, and `packaging/logrotate.d/mom`. Update the man page, completions, and README when the CLI changes.
- Package versions come from the git tag (`GITHUB_REF_NAME`, which must be semver), not from Cargo.toml. Keep `Cargo.toml` `version` in step anyway so `mom --version` matches. Release with `git tag vX.Y.Z && git push origin vX.Y.Z`.
