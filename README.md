# mom - Meta Overlay Manager

Allow non-root users to install and update packages on systems where they lack root access.

**mom** is a Rust-based tool that wraps `apt-get` (Debian/Ubuntu) and `dnf` (RHEL) with a security-hardened setuid binary. It gives end users the ability to install software without requiring root access or sudo privileges.

## Features

- Install and update packages by name via `apt-get` or `dnf`
- Automatic package manager detection (Debian/Ubuntu vs RHEL)
- Package deny list with glob pattern support
- Full environment sanitization — no `LD_PRELOAD`, `PATH`, or shell injection vectors
- JSON audit logging of all operations (including denied attempts)
- Syslog integration
- Proxy support via configuration file

## Quick Start

```bash
mom install curl wget           # install packages
mom update curl                 # update a specific package (auto-refreshes repos)
mom refresh                     # refresh repo metadata only
mom --check                     # validate configuration (sysadmin use)
```

Add `-y` to suppress prompts, same as `apt-get` and `dnf`.

## Installation

Download packages from [GitHub Releases](https://github.com/dirkpetersen/mom/releases):

| Platform | Package |
|----------|---------|
| Debian (latest) | `.deb` |
| Ubuntu 22.04, 24.04, 26.04 | `.deb` |
| RHEL 9, RHEL 10 | `.rpm` |
| Any Linux (x86_64, aarch64) | Static binary |

### Post-install Setup

The sysadmin must configure the binary permissions after installing:

```bash
# Option 1: Any user can run mom (setuid open)
chmod 4755 /usr/bin/mom
chown root:root /usr/bin/mom

# Option 2: Only members of the "mom" group can run mom (recommended)
groupadd mom
chmod 4750 /usr/bin/mom
chown root:mom /usr/bin/mom
usermod -aG mom <username>      # add users as needed
```

## Configuration

**`/etc/mom/mom.conf`** — simple key/value format:

```ini
# Group eligible to execute mom (default: mom)
# group = mom

# Path to package deny list — can be on a shared filesystem
# deny_list = /etc/mom/deny.list

# Audit log path (JSON format)
# log_file = /var/log/mom.log

# Proxy settings (passed explicitly to apt-get/dnf)
# http_proxy =
# https_proxy =
```

If the config file does not exist, safe defaults are used.

### Package Deny List

Create a deny list file (default: `/etc/mom/deny.list`) with one entry per line. Glob patterns are supported:

```
# Prevent installation of development headers
*-dev
*-devel

# Block specific packages
nmap
wireshark
```

The deny list file must be owned by the `mom` group.

## Security

mom is designed to run as a **setuid-root binary**, so security is paramount:

- **Environment sanitization**: The entire caller environment is stripped before executing package managers. Only proxy settings from `mom.conf` are passed to the child process.
- **Input validation**: Package names are validated against a strict regex. No shell metacharacters, version specifiers, or file paths are accepted.
- **Hardcoded paths**: Package manager binaries are called via absolute paths (`/usr/bin/apt-get`, `/usr/bin/dnf`) using `execve` directly — no shell interpolation.
- **Privilege hardening**: Supplemental groups are dropped immediately after startup.
- **Audit trail**: Every invocation (successful or denied) is logged to a JSON audit log and syslog.
- **Config validation**: Config and deny list files are checked for correct ownership and permissions before use.

### What mom does NOT support (by design)

- Uninstalling or removing packages
- Version pinning (`mom install foo=1.2.3`)
- Adding or modifying package repositories
- Installing from `.deb`/`.rpm` files, URLs, or other internet sources

## Building from Source

```bash
cargo build --release
```

Run tests and lints:

```bash
cargo test
cargo clippy
cargo fmt --check
cargo audit
```

## License

[MIT](LICENSE)
