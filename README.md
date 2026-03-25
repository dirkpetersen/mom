```
╔╦╗╔═╗╔╦╗
║║║║ ║║║║  Meta Overlay Manager
╩ ╩╚═╝╩ ╩  install packages without root access
```

[![CI](https://github.com/dirkpetersen/mom/actions/workflows/ci.yml/badge.svg)](https://github.com/dirkpetersen/mom/actions/workflows/ci.yml)
[![Release](https://github.com/dirkpetersen/mom/actions/workflows/release.yml/badge.svg)](https://github.com/dirkpetersen/mom/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Debian%20%7C%20Ubuntu%20%7C%20RHEL-informational)](#installation)

Allow non-root users to install and update packages on systems where they lack root access.

**mom** is a Rust-based tool that wraps `apt-get` (Debian/Ubuntu) and `dnf` (RHEL) with a security-hardened setuid binary. A sysadmin deploys it once; authorized users can then install packages without sudo or root access.

## Quick Start

```bash
mom install curl wget           # install one or more packages
mom update curl                 # refresh repos and update a package
mom refresh                     # refresh repo metadata only
mom --check                     # validate configuration (sysadmin use)
```

Add `-y` to suppress interactive prompts — same semantics as `apt-get -y` and `dnf -y`.

## Features

- Install and update packages by name on Debian/Ubuntu and RHEL/Rocky Linux
- Automatic package manager detection at runtime (`apt-get` vs `dnf`)
- Package deny list with glob pattern support (`python3-*`, `*-dev`)
- Full environment sanitization — `LD_PRELOAD`, `PATH`, and all caller env vars are stripped before invoking the package manager
- JSON audit log of every operation, including denied attempts
- Syslog integration (`LOG_AUTH` facility)
- Proxy support via `/etc/mom/mom.conf`
- Group-restricted execution: only members of the `mom` group can install/update

## Installation

Download packages from [GitHub Releases](https://github.com/dirkpetersen/mom/releases):

| Platform | Package |
|----------|---------|
| Debian (bookworm) | `.deb` |
| Ubuntu 22.04 LTS | `.deb` |
| Ubuntu 24.04 LTS | `.deb` |
| Ubuntu 26.04 LTS | `.deb` |
| RHEL 9 / Rocky 9 | `.rpm` |
| RHEL 10 / Rocky 10 | `.rpm` |
| Any Linux x86_64 | Static binary |
| Any Linux aarch64 | Static binary |

### Post-install Setup

The sysadmin must configure binary permissions after installing. The package does **not** set the setuid bit automatically.

```bash
# Recommended: only mom group members can run mom (group-restricted setuid)
groupadd mom
chown root:mom /usr/bin/mom
chmod 4750 /usr/bin/mom            # rwsr-x---
usermod -aG mom alice              # add users as needed

# Alternative: any user can call mom (open setuid)
chown root:root /usr/bin/mom
chmod 4755 /usr/bin/mom            # rwsr-xr-x
```

#### Completing the setup

```bash
# Create config directory
mkdir -p /etc/mom
chown root:root /etc/mom && chmod 755 /etc/mom

# Create deny list (required ownership check)
touch /etc/mom/deny.list
chown root:mom /etc/mom/deny.list && chmod 640 /etc/mom/deny.list

# Create log file
touch /var/log/mom.log
chown root:root /var/log/mom.log && chmod 640 /var/log/mom.log

# Verify
mom --check
```

## Configuration

**`/etc/mom/mom.conf`** — key/value format, must be owned by root:

```ini
# Group eligible to run mom (default: mom)
# group = mom

# Path to package deny list — can be on a shared filesystem
# deny_list = /etc/mom/deny.list

# Audit log destination
# log_file = /var/log/mom.log

# Proxy passed explicitly to apt-get/dnf (not inherited from environment)
# http_proxy  = http://proxy.example.com:3128
# https_proxy = http://proxy.example.com:3128
```

If `/etc/mom/mom.conf` does not exist, safe defaults are used for all values.

### Package Deny List

`/etc/mom/deny.list` — one entry per line, glob patterns supported:

```
# Block network scanning tools
nmap
wireshark

# Block all Python extension headers
python3-*

# Block all development packages
*-dev
*-devel
```

The deny list file must be owned by root or the `mom` group. If the file is absent, no packages are denied.

## Audit Log

Every invocation is logged to `/var/log/mom.log` as JSON (one object per line) and to syslog (`LOG_AUTH`):

```json
{"timestamp":"2026-03-25T12:00:00Z","real_uid":1001,"real_user":"alice","operation":"install","packages":["curl"],"outcome":"success","detail":null}
{"timestamp":"2026-03-25T12:01:00Z","real_uid":1002,"real_user":"bob","operation":"install","packages":["nmap"],"outcome":"denied","detail":"package 'nmap' matches deny list pattern 'nmap'"}
```

Monitor in real time:
```bash
tail -f /var/log/mom.log | jq .
journalctl -t mom -f
```

## Security

mom runs as a **setuid-root binary**. Security measures applied at runtime:

| Mechanism | Details |
|-----------|---------|
| Environment sanitization | Caller env is entirely discarded; only `PATH`, `HOME`, `LANG`, and configured proxy are passed to child |
| Input validation | Package names validated against `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$` — no shell metacharacters accepted |
| Hardcoded binary paths | `/usr/bin/apt-get` and `/usr/bin/dnf` — caller `PATH` never used |
| No shell | Arguments passed as discrete `execve(2)` argv entries |
| Privilege hardening | Supplemental groups dropped via `setgroups([])` at startup |
| Config validation | Ownership and permissions checked before reading config and deny list |
| Audit | All operations (success and denied) logged to JSON file and syslog |

See [SECURITY.md](SECURITY.md) for the full threat model, attack vectors, and hardening recommendations.

### What mom intentionally does NOT support

- Uninstalling or removing packages
- Version pinning (`mom install foo=1.2.3` is invalid)
- Adding or modifying repositories
- Installing from `.deb`/`.rpm` files, URLs, or direct internet sources

## Building from Source

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --check
cargo audit
```

Cross-compile for aarch64:
```bash
sudo apt-get install gcc-aarch64-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

## Releasing

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds `.deb` and `.rpm` packages for all supported
distros and publishes them as GitHub Release artifacts automatically.

## License

[MIT](LICENSE) — Copyright (c) 2026 Dirk Petersen
