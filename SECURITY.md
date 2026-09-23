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
  from `/etc/mom/mom.conf` — plus, for the package-manager child specifically,
  a fixed set of pager/helper-frontend safety constants (§16), a fixed
  `DEBIAN_FRONTEND` (always `noninteractive` or `dialog`, on apt, never
  unset — §14), and, only on an interactive run, a validated caller `TERM`.
  On apt this also includes fixed `APT_LISTCHANGES_FRONTEND`/
  `APT_LISTBUGS_FRONTEND`/`DPKG_PAGER`/`UCF_FORCE_CONFFOLD`/
  `NEEDRESTART_MODE` constants. See §13–§16 below for how the one
  caller-derived exception (`TERM`) is bounded.
- No other environment variable from the caller ever reaches the package
  manager.

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

#### 13. Automatic dpkg Repair Widening Privilege

**Threat:** An earlier interrupted dpkg run (a killed `mom install`, or a
debconf prompt nobody could answer) leaves packages half-installed, which
makes every subsequent `apt-get` invocation fail until the database is
repaired — a root-only operation. If mom repaired unconditionally, it could
complete an interrupted install of a package the deny list forbids, or
reverse an interrupted removal, as a side effect of an unrelated caller
request — doing more than that request authorizes.

**Mitigation:**
- Broken package names come only from directly re-reading dpkg's own status
  database (`dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}'`),
  never from caller input, and that listing is capped at 16 MiB; a listing
  that hits the cap is refused outright rather than parsed, since a
  truncated line could end in a partial name that happens to be a different,
  valid package.
- Every name found broken is re-validated (`is_valid_dpkg_name`: the base
  name against the same regex as caller input, plus an optional `:arch`
  qualifier restricted to `^[a-z0-9][a-z0-9-]*$`) before it can enter
  `apt-get`/`dpkg` argv. A name that fails validation is treated as
  unrepairable, not skipped silently.
- The deny list is checked against every broken package (its bare name and,
  for Multi-Arch packages, the full `name:arch` form) **before** any repair
  command runs. A match refuses the entire install/update/upgrade and is
  logged as a denied `repair` entry — a denied package cannot be completed
  by riding along on someone else's request.
- A package whose interrupted operation was a `remove` or `purge` (dpkg
  selection `r`/`p`) is never reinstalled. Repair only ever finishes an
  install the admin (or an earlier mom run) already chose — never reverses a
  removal they chose instead. Such packages are reported as unrepairable and
  the whole operation is refused with instructions to contact the sysadmin.
- Half-installed packages (status `H`, or the `reinst-required` error flag)
  are unpacked again with `apt-get install --reinstall`; packages merely
  unpacked/half-configured/awaiting triggers are finished with
  `dpkg --configure -a`. Both take no caller input.
- Repair is logged as its own `repair` audit operation with
  `initiated`/`success`/`failed`/`denied` outcomes, same as every other
  operation, and only ever runs on Debian/Ubuntu (apt).

#### 14. TERM / debconf Frontend Environment Injection

**Threat:** Two related issues. First, clearing the environment leaves `TERM`
unset, so a terminal-based debconf frontend falls back to a line-based one
that can hang forever on a caller with no TTY (a script or AI agent), leaving
dpkg half-installed when it's eventually killed. Passing the caller's `TERM`
through to fix that risks a value crafted to be interpreted as a terminfo
path (directory traversal / arbitrary file read) or to inject terminal escape
sequences. Second, leaving `DEBIAN_FRONTEND` itself unset lets debconf fall
back to whatever frontend is recorded in *its own* configuration database —
which the sysadmin may have set to `Editor` (opens `$EDITOR`/`/usr/bin/editor`
as root; `vim`'s `:!sh` is a root shell escape), or to `Web`, `Gnome`, or
`Kde`, none of which mom's child process is set up to expect or contain.

**Mitigation:**
- `TERM` is captured from the caller's environment before `clearenv()` runs,
  and is the **only** caller-derived variable kept past that point.
- It is validated against `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` — no `/`, so
  it cannot name a path — both when captured (`sanitize_term`) and again
  immediately before it is written into the child environment
  (`is_valid_term`), so no unchecked value can reach the child even via a
  future code path.
- `TERM` is only ever added to the child environment on an interactive run
  (stdin is a TTY **and** `-y` was not given); non-interactive runs never
  receive it. `TERMINFO`, `TERMCAP`, and every other terminal-related
  variable stay cleared regardless.
- `DEBIAN_FRONTEND` is now **always** set on apt, to one of two fixed
  constants, never caller-derived and never left unset: `noninteractive` on a
  non-interactive run (`-y`, or stdin is not a TTY), and `dialog` otherwise.
  `dialog` cannot invoke an admin-configured `Editor`/`Web`/`Gnome`/`Kde`
  frontend, and itself falls back only to Readline and then Teletype if no
  dialog program or usable terminal is present — neither of which can shell
  out. An interactive caller can still answer ordinary (non-conffile)
  debconf questions through `dialog`; that is package-configuration policy,
  not a privilege escalation (see Known Limitations).
- (Conffile prompts specifically — dpkg's and `ucf`'s — are suppressed in
  every mode regardless of `DEBIAN_FRONTEND`; see §15.)

#### 15. dpkg/ucf Conffile Prompt as a Root Shell (pre-existing, fixed in v0.2.23)

**Threat:** dpkg's conffile-conflict prompt (shown whenever a package update
would overwrite a locally modified configuration file) offers, among its
normal options, `Z` — spawn a shell, as root, on the caller's own terminal —
and `D` — show a diff of the conffile through a pager, and the default pager
is `less`, whose `!cmd` command is itself a root shell escape. Before
v0.2.23, mom only suppressed this prompt in non-interactive mode
(`DEBIAN_FRONTEND=noninteractive`); an authorized but unprivileged caller
running `mom install`/`update`/`upgrade` interactively — the common case —
could hit this prompt directly on a routine conffile conflict and obtain a
root shell with no additional exploit, escalation, or misconfiguration
required. This was a real, reachable root-escalation path for any `mom`
group member, not a theoretical one. `ucf` — a separate helper many package
postinst scripts use to manage files under `/etc` that dpkg itself doesn't
track as conffiles — has its own, independent conffile prompt
(`ucf/changeprompt`) with the same shape of problem: a "start a new shell"
choice that also runs a root shell on the caller's terminal, not covered by
`DPKG_SAFETY_OPTS` at all since it isn't dpkg.

**Mitigation:**
- `--force-confdef --force-confold --no-pager` (`DPKG_SAFETY_OPTS` in
  `detect.rs`) are now passed on **every** `apt-get install`/`update`
  (`--only-upgrade`)/`upgrade`/reinstall call and on every
  `dpkg --configure -a` mom runs, **unconditionally, in every mode** —
  interactive or not, `-y` or not. dpkg is never given the chance to prompt
  in the first place, so the `Z`/`D` options never appear.
- These are fixed argv constants (`Vec<&'static str>`), never built from
  caller input, and are spliced in immediately after the subcommand in
  `with_dpkg_safety_args()`, applied identically regardless of `Interaction`.
- Existing (admin-modified) conffiles are kept automatically
  (`--force-confold`); the package default is taken automatically for
  conffiles the admin never touched (`--force-confdef`). Both outcomes are
  what an admin who wasn't watching the prompt would ordinarily choose, and
  neither installs a caller-influenced file; the new version is left as
  `*.dpkg-dist` for the admin to review (see Known Limitations).
- `--no-pager` closes the `D`/diff path outright; §16 additionally locks down
  every pager and pager-adjacent helper mom's child processes could still
  reach, in case a future dpkg/apt frontend adds another way to invoke one.
- `UCF_FORCE_CONFFOLD=1` (part of `APT_SAFETY_ENV`, set on every apt run in
  every mode) applies the same "always keep the existing file" policy to
  `ucf`'s independent prompt, leaving its own `*.ucf-dist` copy for the admin
  instead of ever offering `ucf`'s shell option.

#### 16. Pager / Helper Program Root Shell Escape

**Threat:** Package-manager runs share the caller's terminal while running as
root. Any helper program apt or dpkg invokes that can start a pager or
browser hands the caller a root-privileged interactive program on their own
terminal — `less` supports `!cmd`, and `apt-listchanges`' default frontend
runs `sensible-pager`/`less` as root and reopens `/dev/tty` even when stdin
is not a TTY, so it isn't caught by the `-y`/no-TTY non-interactive check.
`apt-listbugs` can similarly launch a browser.

**Mitigation:**
- Every package-manager run, in every mode, gets a fixed set of environment
  constants (`PAGER_SAFETY_ENV` in `exec.rs`): `PAGER=cat`, `SYSTEMD_PAGER=cat`,
  `MANPAGER=cat`, and `LESSSECURE=1` (disables `less`'s shell-escape and
  edit commands even if something still launches it).
- For `apt-get` specifically, `APT_LISTCHANGES_FRONTEND=none` and
  `APT_LISTBUGS_FRONTEND=none` disable those tools' interactive frontends
  outright, and `DPKG_PAGER=cat` covers dpkg's own pager hook.
- `NEEDRESTART_MODE=l` (also part of `APT_SAFETY_ENV`) makes `needrestart`
  only list services with stale libraries; it never prompts the caller and
  never restarts a service on their behalf, regardless of how the sysadmin
  has `needrestart` itself configured (see Known Limitations for the
  availability trade-off this implies).
- All of these are fixed string constants baked into the binary, never
  derived from caller input or `mom.conf`.
- debconf itself is deliberately left interactive on a TTY, but now always
  under the fixed `dialog` frontend (§14) rather than whatever an admin
  configured — Dialog and Readline have no shell-out — so an interactive
  caller still sees ordinary debconf prompts other than the conffile prompts
  closed in §15.

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
| Execution | `execve` with hardcoded binary paths; clean environment (PATH, HOME, LANG, proxy, fixed pager-safety vars, plus validated TERM or fixed DEBIAN_FRONTEND for the package-manager child only) |
| dpkg/ucf conffile safety | `--force-confdef --force-confold --no-pager` on every apt-get/dpkg call, plus `UCF_FORCE_CONFFOLD=1`, unconditionally, in every mode — closes dpkg's conffile prompt (root-shell `Z`, pager-escape `D`) and ucf's own equivalent shell option before either can appear |
| Pager/helper safety | `PAGER`/`SYSTEMD_PAGER`/`MANPAGER=cat`, `LESSSECURE=1` in every mode; apt also gets `APT_LISTCHANGES_FRONTEND=none`, `APT_LISTBUGS_FRONTEND=none`, `DPKG_PAGER=cat`, `NEEDRESTART_MODE=l` |
| Signal handling | `SA_RESTART` + `EINTR` retry; signals blocked across `fork`/PID-store; SIGINT/SIGTERM/SIGHUP/SIGQUIT forwarded |
| Pipe hygiene | `pipe2(O_CLOEXEC)`; bounded reads (64 bytes); fd cleanup on fork failure |
| Audit (file) | JSON via `serde_json`; `O_NOFOLLOW`; `fchmod(0o640)` after create; logrotate with `root:mom` ownership |
| Audit (syslog) | All fields passed through `sanitize_for_syslog()` (control char replacement) |
| Package state | Apt: `dpkg-query -W -f='${db:Status-Abbrev}'` to distinguish installed (`ii`) from config-files (`rc`) |
| Repair | Broken package names re-read from the root-owned dpkg database, capped and refused if truncated, re-validated before argv; deny list applied to them; interrupted removals never reinstalled; denials rate-limited (2s) like other denied attempts; a failed pre-reinstall `dpkg --configure -a` pass is audit-logged before retrying |
| Interactive/TTY handling | `DEBIAN_FRONTEND` always fixed on apt: `noninteractive` whenever `-y` or stdin isn't a TTY, else `dialog` (never unset, never an admin/caller-chosen frontend); a validated `TERM` passed through only on an interactive run; repair's own reinstall auto-confirms when stdin isn't a TTY so it can't stall on apt's confirmation prompt |
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

5. **`mom refresh` requires group membership** (since v0.2.8): All
   subcommands, including `refresh`, now require the caller to be a member
   of the configured `mom` group. This prevents unauthenticated users from
   triggering privileged network operations under 4755 (open setuid) mode.

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

10. **Automatic dpkg repair is Debian/Ubuntu only**: RHEL/dnf systems have no
    equivalent auto-repair step; dnf's own transaction handling is relied on
    as-is. An interrupted dpkg removal/purge is also never auto-repaired —
    mom refuses the operation and tells the caller to contact the sysadmin,
    since reinstalling would reverse a decision mom did not make.

11. **Interactive debconf answers are caller-controlled policy input**: On a
    TTY, without `-y`, an authorized group member answers any ordinary
    (non-conffile) debconf question a package's install/upgrade asks — for
    example whether `wireshark-common` installs `dumpcap` setuid, which
    device `grub-pc` writes its bootloader to, or postfix's mail-system mode.
    Nothing here allows a shell-out or bypasses the deny list, but it is
    package-configuration policy set by a non-admin user. Sysadmins who need
    to prevent this for a specific package should deny it; for unattended or
    hands-off runs, use `-y` or a non-TTY caller, which answers every
    question with the package's default instead.

12. **`NEEDRESTART_MODE=l` overrides an admin's `needrestart` restart
    policy**: If the sysadmin has configured `needrestart` to automatically
    restart services with stale libraries (`$nrconf{restart} = 'a'`), a
    mom-initiated run still only *lists* them — it never restarts anything on
    the caller's behalf. Services that depend on a library mom just updated
    keep running their old code until the admin (or the next reboot)
    restarts them. This is intentional: mom must not decide to restart a
    production service as a side effect of an unprivileged user's package
    install.

13. **Conffile policy always favors the admin's existing file**:
    `--force-confold` and `UCF_FORCE_CONFFOLD=1` mean a package upgrade run
    through mom never installs a new upstream default configuration file
    over one the admin has modified — mom has no way to distinguish a
    conffile change the admin actually wants from one they'd reject, so it
    always keeps what's on disk. The new version is left alongside as
    `*.dpkg-dist` (or `*.ucf-dist`) for the admin to review and merge
    manually; it does not take effect until they do.

14. **A single group member can degrade availability for everyone**: An
    interrupted dpkg run (e.g. Ctrl+C during a previous `mom install`) or a
    denied package left in any broken dpkg state blocks `install`/`update`/
    `upgrade` for every user of the system until an admin repairs the
    package database (or, for a denied broken package, removes it from the
    deny list or resolves it directly). Any group member can trigger this by
    interrupting their own operation. This is a known, accepted trade-off of
    the repair design (§13 in the threat model): the alternative — silently
    completing or reversing an interrupted operation to route around it —
    would widen what an unprivileged caller can cause a setuid binary to do.
    Denied-repair attempts are rate-limited and audit-logged like any other
    denial.

15. **Dependencies and maintainer scripts are outside the deny list**: The
    deny list is matched only against the package name(s) the caller
    requested (and, for repair, the broken package names mom itself
    discovers) — it is not applied transitively to dependencies apt/dnf
    pull in to satisfy them, nor can it inspect what a package's maintainer
    scripts (preinst/postinst/etc., which run as root) actually do. A
    dependency's maintainer script runs with the caller's TTY attached; if a
    locally installed apt hook or maintainer script were to invoke an
    interactive program of its own, the pager/helper-frontend environment
    variables (§16) mitigate the common cases (pagers, `apt-listchanges`,
    `apt-listbugs`, `ucf`, `needrestart`) but cannot cover an arbitrary
    third-party script the sysadmin has added to the system.

16. **`--no-pager` requires dpkg >= 1.19.2**: The Debian/Ubuntu targets mom
    currently packages for (Debian bookworm, Ubuntu 22.04/24.04/26.04) all
    ship a dpkg new enough to support it. If mom is ever packaged for an
    older Debian/Ubuntu release (e.g. Debian buster), confirm that release's
    dpkg version supports `--no-pager` before adding it as a target —
    passing an unsupported option makes dpkg refuse to run outright, which
    would break every mom operation on that release, not just repair.

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
| v0.2.23 | 2026-09-22 | **Fix reachable root shell via dpkg's and ucf's conffile prompts**: `--force-confdef --force-confold --no-pager` (dpkg) and `UCF_FORCE_CONFFOLD=1` (ucf) are now passed unconditionally, in every mode, on every apt-get/dpkg call, closing prompts that previously offered an interactive caller a root shell (dpkg `Z`, ucf's own shell option) or a pager shell-escape (dpkg `D`). **Fix admin-configured debconf frontend exposure**: `DEBIAN_FRONTEND` is now always a fixed constant on apt (`noninteractive`, or `dialog` when interactive) instead of being left unset, which previously let debconf fall back to the sysadmin's configured frontend (Editor → `vim :!sh` as root, or Web/Gnome/Kde). **Automatic dpkg repair**: half-installed/reinst-required packages are reinstalled (`apt-get install --reinstall`) and finished with `dpkg --configure -a` before `install`/`update`/`upgrade`, with the deny list applied to broken packages, interrupted removals never reinstalled, repair denials rate-limited like other denials, a failed pre-reinstall configure pass audit-logged, and repair's own reinstall auto-confirmed for non-TTY callers. A validated caller `TERM` is passed through in interactive runs only. **Pager/helper lockdown** in every mode: `PAGER`/`SYSTEMD_PAGER`/`MANPAGER=cat`, `LESSSECURE=1`, and (apt) `APT_LISTCHANGES_FRONTEND=none`, `APT_LISTBUGS_FRONTEND=none`, `DPKG_PAGER=cat`, `NEEDRESTART_MODE=l` (services with stale libraries are only listed, never restarted); no other caller env var reaches the child. |
| v0.2.7 | 2026-03-25 | **Open config and deny list with `O_NOFOLLOW`** to prevent symlink bypass on shared filesystems. Sync inline logrotate configs with repo source. Sanitize all syslog message fields. |
| v0.2.6 | 2026-03-25 | **Harden pipe handling**: `pipe2(O_CLOEXEC)` to prevent fd leakage; bounded 64-byte read in `run_capture`; fd cleanup on fork failure. Fix logrotate to create rotated logs as `root:mom`. Consolidate `is_installed` into single `dpkg-query` execution. |
| v0.2.5 | 2026-03-25 | **Fix `dpkg-query` config-files state**: parse `${db:Status-Abbrev}` output to distinguish `ii` (installed) from `rc` (config-files). Add SHA256SUMS to release artifacts. Restrict group name validation to ASCII. |
| v0.2.4 | 2026-03-25 | **Sanitize package names in syslog**. Add `fchmod(fd, 0o640)` to log file creation (umask fix). Forward SIGQUIT to child. Add `--locked` to all CI/release builds. Add `cargo audit` gate in release workflow. Reject whitespace in proxy URLs. |
| v0.2.3 | 2026-03-25 | **Handle `EINTR` in waitpid loop** with explicit retry + `SA_RESTART`. Validate release tag format (semver regex). Sanitize syslog `real_user` and `detail` fields. Validate config paths as absolute. Warn on 4755 permissions in `--check`. Fix RPM `%files` for man page/completions. Fix bash completion quoting. |
| v0.2.2 | 2026-03-25 | **Reject group-writable files** in `validate_file_metadata` (`0o022` check). Open audit log with `O_NOFOLLOW`. Pin all GitHub Actions to commit SHAs. Remove TOCTOU pre-execve binary existence check. Document proxy credential exposure, refresh auth bypass, fstat vs path-based stat distinction. |
| v0.2.0 | 2026-03-25 | Post-install scripts auto-configure group, setuid, permissions. |
| v0.1.0 | 2026-03-25 | Initial release with security policy and threat model. |
