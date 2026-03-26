# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.7+  | Yes       |
| < 0.2.7 | No — upgrade to latest |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing **security@dirkpetersen.dev** with subject line:
`[mom] Security Vulnerability Report`

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Proposed severity (see [CVSS](https://www.first.org/cvss/))

You will receive acknowledgement within 48 hours and a resolution timeline within 7 days.

---

## Security Architecture & Threat Model

### What mom does

`mom` is a **setuid-root binary** that allows non-root users in a designated group to invoke `apt-get` or `dnf` on their behalf. Because any setuid-root binary expands the attack surface of a system, this document describes the threats considered and the mitigations in place.

---

### Threat Model

#### Actors

| Actor | Description | Trust Level |
|-------|-------------|-------------|
| **Authorized user** | Member of the `mom` group, legitimately using the tool | Low — inputs must be validated |
| **Unauthorized user** | Any local user not in the `mom` group | Untrusted |
| **Remote attacker** | Attacker who has compromised an authorized user's session | Untrusted |
| **Sysadmin** | Configures `/etc/mom/mom.conf` and the deny list | Trusted |

#### Assets

| Asset | Impact if Compromised |
|-------|-----------------------|
| Root shell / root command execution | Full system compromise |
| `/etc/mom/mom.conf` | Redirect to attacker-controlled deny list or log; change authorized group |
| Deny list file | Remove denied packages to allow installation of prohibited software |
| `/var/log/mom.log` | Tamper with or suppress audit evidence |
| Package manager (apt-get/dnf) | Install malicious packages |

---

### Attack Vectors & Mitigations

#### 1. Environment Variable Injection

**Threat:** An attacker sets `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`,
`PERL5LIB`, `IFS`, `CDPATH`, or other variables before calling `mom`,
causing injected code to run in the setuid context or in `apt-get`/`dnf`.

**Mitigation:**
- The entire caller environment is **discarded** before `execve()`.
- The child process receives only: `PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
  `HOME=/root`, `LANG=C`, and (if configured) `http_proxy`/`https_proxy`
  from `/etc/mom/mom.conf`.
- No environment variable from the caller ever reaches the package manager.

#### 2. Argument Injection / Shell Metacharacter Injection

**Threat:** A user passes a malicious package name containing shell metacharacters
(`; rm -rf /`, `` `evil` ``, `$(cmd)`, `../../../etc/shadow`) hoping mom
passes it to a shell or constructs a command string.

**Mitigation:**
- Package names are validated against a strict allowlist regex before use:
  `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$`
- Any name that does not match is rejected with an error and logged.
- Arguments are passed as discrete `execve(2)` argv entries — **never** via
  a shell (`sh -c` is never used).
- There is no string concatenation of user input into commands.

#### 3. Path Traversal / Binary Substitution

**Threat:** An attacker manipulates `PATH` or creates a file at an expected
location to substitute a malicious binary for `apt-get` or `dnf`.

**Mitigation:**
- Package manager binaries are called with **hardcoded absolute paths**:
  `/usr/bin/apt-get` and `/usr/bin/dnf`.
- The caller's `PATH` is discarded (see §1).
- `execve(2)` is called directly — if the binary does not exist, the child
  exits with code 127. No pre-flight existence check is needed (which would
  introduce a TOCTOU gap).

#### 4. Configuration File Tampering

**Threat:** An attacker modifies `/etc/mom/mom.conf` to change the authorized
group, redirect the deny list to an attacker-controlled file, or disable logging.

**Mitigation:**
- Config file is opened with `O_NOFOLLOW | O_CLOEXEC` — symlinks are rejected
  with `ELOOP` (security error). This prevents an attacker from symlinking the
  config to an attacker-controlled file.
- After opening, mom verifies (using fstat on the already-opened fd):
  - File is owned by root (uid 0)
  - File is not group-writable or world-writable (mode `& 0o022 == 0`)
- If any check fails, mom refuses to run and logs the violation.
- Falls back to safe hardcoded defaults if the config file is absent.
- Config values are validated: paths must be absolute with no null bytes;
  group names must be ASCII alphanumeric (no Unicode); proxy URLs must be
  http/https with no shell metacharacters or whitespace.

#### 5. Deny List Bypass

**Threat:** An attacker modifies or replaces the deny list file to remove
restrictions, allowing installation of prohibited packages. On a shared
filesystem, a mom-group member could symlink the deny list to a root-owned
file with no valid patterns, bypassing all restrictions.

**Mitigation:**
- Deny list is opened with `O_NOFOLLOW | O_CLOEXEC` — symlinks are rejected.
- After opening, mom verifies (using fstat on the already-opened fd):
  - File is owned by root or the `mom` group
  - File is not group-writable or world-writable
- If the file is absent, an empty deny list is used (no denials) — this is
  a deliberate safe default.
- The deny list path can be set to a read-only or immutable location by the
  sysadmin.

#### 6. Supplemental Group Privilege

**Threat:** The caller has supplemental groups that grant access to
privileged resources. These groups are inherited by the setuid process.

**Mitigation:**
- `setgroups([])` is called **immediately at startup**, before any other
  operations, to drop all supplemental groups.
- Group membership for authorization is re-checked from `/etc/group` after
  supplemental groups have been dropped.

#### 7. TOCTOU (Time-of-Check-Time-of-Use) and Symlink Races

**Threat:** An attacker replaces a config or deny list file between mom's
ownership check and its read, substituting a malicious version. Or an attacker
places a symlink at the file path, pointing to a file that passes ownership
checks (e.g., `/etc/hostname` is root-owned, world-readable).

**Mitigation:**
- All security-critical files (config, deny list, audit log) are opened with
  `O_NOFOLLOW`, which causes `open(2)` to fail with `ELOOP` if the path is a
  symbolic link. This eliminates symlink-based attacks.
- After opening with `O_NOFOLLOW`, file validation uses **fstat on the open fd**
  (`file.metadata()` calls `fstat(2)`). The ownership/permissions check and the
  subsequent read operate on the same inode — no TOCTOU window exists.
- The `--check` diagnostic mode uses path-based `Path::exists()` and
  `std::fs::metadata()` for its output. These are not security-critical since
  `--check` makes no privilege decisions — it only prints diagnostic information
  for sysadmins.
- Config and deny list files should be placed on a local filesystem with
  restricted permissions.

#### 8. Concurrent Execution / Lock File Races

**Threat:** Multiple users invoke `mom install` simultaneously, causing
package manager corruption.

**Mitigation:**
- mom relies on the package manager's own locking (`/var/lib/dpkg/lock`,
  `/var/cache/dnf/`). These are mature, well-tested mechanisms.
- No additional lock file is introduced (which could itself become an
  attack surface).

#### 9. Signal Injection

**Threat:** An attacker sends signals to the `mom` process hoping to kill
it mid-operation in a way that leaves the package manager in a bad state,
or to influence control flow.

**Mitigation:**
- `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` are caught in the parent
  and forwarded to the child package manager process. The package manager
  handles them with its own cleanup logic.
- Signal handlers use `SA_RESTART` to prevent `waitpid()` from returning
  `EINTR` (which could orphan the child). The `waitpid` loop also explicitly
  retries on `EINTR` for belt-and-suspenders safety.
- Signals are blocked between `fork()` and `CHILD_PID.store()` to prevent
  a race where the handler fires before the parent knows the child's PID.
- Only async-signal-safe operations are performed in the signal handler
  (`kill(2)` and an atomic load).

#### 10. Log Injection / Log Forging

**Threat:** An attacker crafts a package name containing newlines, JSON
control characters, or other sequences to inject false entries into the
audit log or syslog.

**Mitigation:**
- JSON audit log entries are serialized via `serde_json`, which escapes all
  special characters including `\n`, `\r`, `"`, `\`, and control characters.
- Syslog messages have all fields passed through `sanitize_for_syslog()`,
  which replaces control characters with underscores. This covers
  `real_user`, `operation`, `packages`, `outcome`, and `detail` fields —
  preventing injection via crafted NSS/LDAP usernames or future code paths.
- Package names have already been validated against the strict regex before
  they reach the logger.
- The audit log file is opened with `O_NOFOLLOW` to prevent symlink attacks
  and `fchmod(fd, 0o640)` is called after creation to set correct permissions
  regardless of the startup umask.

#### 11. Unauthorized Package Installation (Group Restriction Bypass)

**Threat:** A user not in the `mom` group attempts to invoke `mom install`.

**Mitigation:**
- Group membership is verified by reading `/etc/group` after supplemental
  groups have been dropped.
- If the binary is deployed with 4750 permissions (`rwsr-x---`, group `mom`),
  the kernel itself prevents execution by non-members before mom's code runs.
- Failed authorization attempts are logged to both the JSON audit log and syslog.

#### 12. Package Manager Detection Spoofing

**Threat:** An attacker creates `/usr/bin/apt-get` on a RHEL system (or vice
versa) to confuse the detection logic.

**Mitigation:**
- Detection requires both binary existence **and** distro marker file
  (`/etc/debian_version` or `/etc/redhat-release`).
- If both or neither package managers are present, mom errors out.

---

### Defense in Depth Summary

| Layer | Mechanism |
|-------|-----------|
| Kernel | setuid bit + group-restricted execute (4750) |
| Runtime startup | `umask(0o077)`; drop supplemental groups (`setgroups([])`) |
| Input | Strict package name regex `^[a-zA-Z0-9][a-zA-Z0-9.+\-]*$`; max 256 chars; max 100 packages |
| File opens | `O_NOFOLLOW \| O_CLOEXEC` on all security-critical files (config, deny list, audit log) |
| File validation | `fstat` on open fd: ownership + group/world-writable bit checks |
| Config validation | Paths must be absolute; group names ASCII-only; proxy URLs scheme-checked and metachar-free |
| Execution | `execve` with hardcoded binary paths; clean environment (only PATH, HOME, LANG, proxy) |
| Signal handling | `SA_RESTART` + `EINTR` retry; signals blocked across `fork`/PID-store; SIGINT/SIGTERM/SIGHUP/SIGQUIT forwarded |
| Pipe hygiene | `pipe2(O_CLOEXEC)`; bounded reads (64 bytes); fd cleanup on fork failure |
| Audit (file) | JSON via `serde_json`; `O_NOFOLLOW`; `fchmod(0o640)` after create; logrotate with `root:mom` ownership |
| Audit (syslog) | All fields passed through `sanitize_for_syslog()` (control char replacement) |
| Package state | Apt: `dpkg-query -W -f='${db:Status-Abbrev}'` to distinguish installed (`ii`) from config-files (`rc`) |
| Packaging | Post-install scripts auto-configure group, setuid, permissions, log file |
| CI/CD | All GitHub Actions pinned to commit SHAs; `cargo audit` gates every release; `--locked` on all builds |
| Release integrity | SHA256SUMS file published with every release |

---

### Known Limitations

1. **apt-get/dnf are trusted**: mom trusts the package manager binaries at
   their hardcoded paths. If those binaries are compromised, mom provides
   no additional protection.

2. **No package signature verification**: mom does not independently verify
   package signatures — it relies on apt/dnf to do so. Ensure your GPG
   keys and repository configuration are maintained by a trusted sysadmin.

3. **Deny list is advisory**: The deny list prevents authorized users from
   requesting specific packages via `mom`, but does not prevent a root user
   from installing them directly.

4. **Proxy credentials in child environment**: If proxy URLs in `mom.conf`
   contain embedded credentials (`http://user:pass@proxy:3128`), these are
   passed as environment variables to the child `apt-get`/`dnf` process.
   On Linux, `/proc/<pid>/environ` is readable by the process owner (root
   only in this case). Sysadmins should prefer proxy configurations that
   do not require credentials in the URL.

5. **`mom refresh` bypasses group authorization**: Any user who can execute
   the binary may run `mom refresh`, which triggers a privileged `apt-get
   update` or `dnf makecache`. This is by design — refreshing repo metadata
   is a read-only operation. When deployed with 4750 permissions (group-
   restricted), the kernel prevents non-group members from executing the
   binary. Under 4755 (open setuid), any local user can trigger this
   privileged network operation.

6. **All security-critical files opened with O_NOFOLLOW**: The config,
   deny list, and audit log are all opened with `O_NOFOLLOW`. If any path
   is a symlink, the operation fails (security error for config/deny list;
   non-fatal for log). The post-install scripts create files before setting
   the setuid bit, so they always pre-exist on properly installed systems.

7. **No rate limiting on failed auth**: Repeated denied attempts are logged
   but not rate-limited. On systems with high attacker activity, this could
   grow the audit log rapidly. Sysadmins can use logrotate `maxsize` or
   external tools like `fail2ban` to mitigate.

8. **No Linux capabilities dropping**: After `setgroups([])`, mom retains
   the full capability set from effective UID 0. Dropping unused capabilities
   via `prctl(PR_SET_SECUREBITS)` or `capset` would reduce impact of any
   future memory safety vulnerability. This is a defense-in-depth
   recommendation; no exploitable vulnerability exists that would require it.

9. **`--check` uses path-based stat**: The `--check` diagnostic mode uses
   `std::fs::metadata()` (path-based, follows symlinks) for binary
   permission reporting. This is not security-critical since `--check`
   makes no authorization decisions.

---

### Hardening Recommendations for Sysadmins

```bash
# Recommended: group-restricted setuid (only mom group members can execute)
groupadd mom
chown root:mom /usr/bin/mom
chmod 4750 /usr/bin/mom

# Config file: root-owned, not world-readable
chown root:root /etc/mom/mom.conf
chmod 600 /etc/mom/mom.conf

# Deny list: root or mom group owned, not world-writable
chown root:mom /etc/mom/deny.list
chmod 640 /etc/mom/deny.list

# Audit log: root-owned, mom group readable for monitoring
chown root:mom /var/log/mom.log
chmod 640 /var/log/mom.log

# Monitor the audit log
journalctl -t mom -f
tail -f /var/log/mom.log | jq .
```

---

### Changelog

| Version | Date | Changes |
|---------|------|---------|
| v0.2.7 | 2026-03-25 | **Open config and deny list with `O_NOFOLLOW`** to prevent symlink bypass on shared filesystems. Sync inline logrotate configs with repo source. Sanitize all syslog message fields. |
| v0.2.6 | 2026-03-25 | **Harden pipe handling**: `pipe2(O_CLOEXEC)` to prevent fd leakage; bounded 64-byte read in `run_capture`; fd cleanup on fork failure. Fix logrotate to create rotated logs as `root:mom`. Consolidate `is_installed` into single `dpkg-query` execution. |
| v0.2.5 | 2026-03-25 | **Fix `dpkg-query` config-files state**: parse `${db:Status-Abbrev}` output to distinguish `ii` (installed) from `rc` (config-files). Add SHA256SUMS to release artifacts. Restrict group name validation to ASCII. |
| v0.2.4 | 2026-03-25 | **Sanitize package names in syslog**. Add `fchmod(fd, 0o640)` to log file creation (umask fix). Forward SIGQUIT to child. Add `--locked` to all CI/release builds. Add `cargo audit` gate in release workflow. Reject whitespace in proxy URLs. |
| v0.2.3 | 2026-03-25 | **Handle `EINTR` in waitpid loop** with explicit retry + `SA_RESTART`. Validate release tag format (semver regex). Sanitize syslog `real_user` and `detail` fields. Validate config paths as absolute. Warn on 4755 permissions in `--check`. Fix RPM `%files` for man page/completions. Fix bash completion quoting. |
| v0.2.2 | 2026-03-25 | **Reject group-writable files** in `validate_file_metadata` (`0o022` check). Open audit log with `O_NOFOLLOW`. Pin all GitHub Actions to commit SHAs. Remove TOCTOU pre-execve binary existence check. Document proxy credential exposure, refresh auth bypass, fstat vs path-based stat distinction. |
| v0.2.0 | 2026-03-25 | Post-install scripts auto-configure group, setuid, permissions. |
| v0.1.0 | 2026-03-25 | Initial release with security policy and threat model. |
