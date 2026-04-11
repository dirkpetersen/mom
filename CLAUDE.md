# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mom** (Meta Overlay Manager) is a Rust tool that allows non-root users to install and update packages on systems where they lack root access. It wraps `apt-get` (Debian/Ubuntu) and `dnf` (RHEL) and runs as a **setuid-root binary** with group-restricted execute permissions.

This tool runs with elevated privileges on behalf of untrusted users — treat every design and implementation decision as a security-critical choice.

## Build & Development Commands

```bash
cargo build                  # debug build
cargo build --release        # release build
cargo test                   # run all tests
cargo test <test_name>       # run a single test
cargo clippy                 # lint
cargo fmt                    # format code
cargo audit                  # check for known vulnerabilities in dependencies
```

## Target Platforms & Packaging

Packages must be produced for:
- Debian (latest stable)
- RHEL 9 and RHEL 10
- Ubuntu 22.04, 24.04, 26.04

Released as downloadable artifacts from GitHub Releases. Two forms:
- Single static binary
- Full package (binary + man page + bash completions + logrotate.d config)

## CLI Interface

```
mom install <pkg> [pkg...]    # install one or more packages
mom update <pkg> [pkg...]     # refresh repos, then update named packages (errors if not installed)
mom refresh                   # refresh repo metadata only (requires group membership)
mom --version
mom --help
mom --check                   # validate config and deny list, no package operations (sysadmin use)
```

`-y` / `--yes` flag: suppress prompts (passed as `-y` to apt-get/dnf), same semantics as native tools.

**Explicitly not supported** (by design):
- Uninstalling or removing packages
- Version pinning (`mom install foo=1.2.3` is not valid — package name only)
- Adding or modifying package repositories
- Installing from `.deb`/`.rpm` files, URLs, or internet sources directly

## Privilege Model (Option A: setuid + group-restricted execute)

Two deployment modes, both use a **setuid-root binary**:

| Mode | Permissions | Ownership |
|------|-------------|-----------|
| setuid (open) | `rwsr-xr-x` (4755) | `root:root` |
| group-restricted | `rwsr-x---` (4750) | `root:mom` |

In group-restricted mode, only members of the `mom` group (or the group named in `mom.conf`) can execute the binary. In both cases the binary runs as root. Detection at runtime: effective UID = 0 confirms privilege was granted; real UID identifies the calling user.

`mom refresh` requires group membership, like all other subcommands. It runs through the setuid privilege path to gain root for `apt-get update` / `dnf makecache`.

The sysadmin sets the binary permissions manually post-install. Document `chmod 4750 /usr/bin/mom && chown root:mom /usr/bin/mom` in the man page.

## Configuration

**`/etc/mom/mom.conf`** — key/value format, owned and writable only by root. mom must validate ownership and permissions before reading; refuse to run if the file is world-writable or not owned by root.

| Key | Default | Description |
|-----|---------|-------------|
| `group` | `mom` | Group eligible to execute mom |
| `deny_list` | `/etc/mom/deny.list` | Path to package deny list (can be on shared FS) |
| `log_file` | `/var/log/mom.log` | Audit log path |
| `http_proxy` | _(none)_ | Proxy URL passed explicitly to apt-get/dnf |
| `https_proxy` | _(none)_ | Proxy URL passed explicitly to apt-get/dnf |

If `mom.conf` does not exist, fall back to safe defaults (all values above).

**Deny list file** (path configured via `deny_list`): one or more entries per line (space-separated), glob patterns supported (e.g., `python3-*`). The file must be owned by the `mom` group; refuse to run if ownership check fails. If the file does not exist, treat as empty (no denials). Comments with `#` should be supported.

## Security Architecture

### Environment Sanitization
- **Strip the entire environment** before exec'ing `apt-get`/`dnf`.
- Use hardcoded absolute paths: `/usr/bin/apt-get`, `/usr/bin/dnf`.
- Never use `sh -c` or shell interpolation.
- Pass arguments as discrete `execve` argv entries.
- Proxy settings from `mom.conf` are passed explicitly as `http_proxy`/`https_proxy` env vars to the child only.

### Input Validation
- Package names validated against strict regex: `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$`.
- No shell metacharacters permitted in any argument.
- Check package name against deny list (glob matching) before exec.

### Privilege Hardening
- Drop supplemental groups immediately after startup.
- Use `execve` directly (never `system()` / `popen()`).
- `mom update foo` must verify the package is already installed before attempting update; error out if not.

### Concurrency
- Rely on apt-get/dnf's own locking; do not implement a separate lock file.

### Output
- Pass stdout/stderr from apt-get/dnf directly to the user (no capture or filtering).

### Signal Handling
- Forward signals (including SIGINT / Ctrl+C) to the child apt-get/dnf process.

## Audit Logging

All invocations logged to `/var/log/mom.log` (path configurable) in **JSON**, one object per line:

```json
{"timestamp": "2026-03-25T12:00:00Z", "real_uid": 1001, "real_user": "alice", "operation": "install", "packages": ["curl"], "outcome": "success", "detail": null}
{"timestamp": "2026-03-25T12:01:00Z", "real_uid": 1002, "real_user": "bob", "operation": "install", "packages": ["python3-dev"], "outcome": "denied", "detail": "package matches deny list pattern python3-*"}
```

Failed authorization attempts (not in group, package denied, config validation failure) must also be logged. Also log to syslog.

Log rotation handled via a `logrotate.d` config included in the full package.

## Package Manager Detection

At runtime, detect by checking binary existence:
- `/usr/bin/apt-get` present → Debian/Ubuntu mode
- `/usr/bin/dnf` present → RHEL mode
- Both or neither → error with clear message

Also verify the detected system matches expectations (e.g., check `/etc/debian_version` or `/etc/redhat-release`).

## CI/CD (GitHub Actions)

Two workflows in `.github/workflows/`:

**`ci.yml`** — runs on every push/PR to `main`:
- `cargo fmt --check` — format enforcement
- `cargo clippy` — lint with `-D warnings`
- `cargo test` — full test suite
- `cargo audit` — dependency vulnerability scan
- Cross-compilation build check for x86_64 and aarch64

**`release.yml`** — triggered by pushing a version tag (`v*.*.*`):
1. Builds release binaries for x86_64 and aarch64
2. Builds `.deb` packages in distro-specific containers (Debian bookworm, Ubuntu 22.04/24.04/26.04)
3. Builds `.rpm` packages in distro-specific containers (Rocky Linux 9, AlmaLinux 10 — RHEL-compatible)
4. Publishes all artifacts + standalone binaries to a GitHub Release

To cut a release:
```bash
git tag v0.1.0
git push origin v0.1.0
```
