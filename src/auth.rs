use anyhow::{bail, Context, Result};
use nix::unistd::{setgroups, Gid, Group, Uid, User};

/// Drop all supplemental groups.
/// Must be called immediately after startup while still running as root.
pub fn drop_supplemental_groups() -> Result<()> {
    setgroups(&[]).context("failed to drop supplemental groups")
}

/// Return the username for the given UID by reading /etc/passwd.
/// Falls back to the numeric UID string if the user is not found.
pub fn username_for_uid(uid: Uid) -> Result<String> {
    match User::from_uid(uid).context("failed to look up user by UID")? {
        Some(user) => Ok(user.name),
        None => Ok(uid.to_string()),
    }
}

/// Check that the real user (identified by `real_uid` and `real_gid`) is a
/// member of `group_name`.
///
/// Membership is determined by:
/// 1. The user's primary GID matching the group's GID.
/// 2. The user's name appearing in the group's member list in /etc/group.
///
/// This intentionally reads /etc/group at check time (after supplemental groups
/// have been dropped) so we are not relying on the inherited process credentials.
pub fn check_group_membership(real_uid: Uid, real_gid: Gid, group_name: &str) -> Result<()> {
    let group = Group::from_name(group_name)
        .with_context(|| format!("failed to look up group '{group_name}'"))?
        .with_context(|| {
            format!(
                "group '{group_name}' does not exist — sysadmin must create it with: \
                 groupadd {group_name}"
            )
        })?;

    // Fast path: primary GID matches
    if real_gid == group.gid {
        return Ok(());
    }

    // Resolve username for /etc/group member-list check
    let user = User::from_uid(real_uid)
        .context("failed to look up current user")?
        .with_context(|| format!("uid {} has no /etc/passwd entry", real_uid))?;

    if group.mem.contains(&user.name) {
        return Ok(());
    }

    bail!(
        "user '{}' (uid={}) is not a member of group '{}' — \
         ask your sysadmin to run: usermod -aG {} {}",
        user.name,
        real_uid,
        group_name,
        group_name,
        user.name,
    )
}

/// Resolve a group name to its GID.
pub fn gid_for_group(group_name: &str) -> Result<u32> {
    let group = Group::from_name(group_name)
        .with_context(|| format!("failed to look up group '{group_name}'"))?
        .with_context(|| format!("group '{group_name}' does not exist"))?;
    Ok(group.gid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_for_root() {
        // UID 0 is always root in any Unix system
        let name = username_for_uid(Uid::from_raw(0)).unwrap();
        assert_eq!(name, "root");
    }

    #[test]
    fn test_username_for_unknown_uid_returns_numeric() {
        // Use a very high UID that is unlikely to exist
        let name = username_for_uid(Uid::from_raw(99999)).unwrap();
        assert_eq!(name, "99999");
    }

    #[test]
    fn test_gid_for_nonexistent_group_errors() {
        let result = gid_for_group("__mom_nonexistent_group_xyz__");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_group_membership_nonexistent_group_errors() {
        let result = check_group_membership(
            Uid::from_raw(0),
            Gid::from_raw(0),
            "__mom_nonexistent_group_xyz__",
        );
        assert!(result.is_err());
    }
}
