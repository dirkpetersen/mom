use anyhow::{bail, Result};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum PackageManager {
    Apt,
    Dnf,
}

impl PackageManager {
    pub fn binary(&self) -> &'static str {
        match self {
            PackageManager::Apt => "/usr/bin/apt-get",
            PackageManager::Dnf => "/usr/bin/dnf",
        }
    }

    pub fn install_cmd_args(&self, packages: &[String], yes: bool) -> Vec<String> {
        let mut args = vec!["install".to_string()];
        if yes {
            args.push("-y".to_string());
        }
        args.extend_from_slice(packages);
        args
    }

    pub fn update_cmd_args(&self, packages: &[String], yes: bool) -> Vec<String> {
        match self {
            PackageManager::Apt => {
                let mut args = vec!["install".to_string(), "--only-upgrade".to_string()];
                if yes {
                    args.push("-y".to_string());
                }
                args.extend_from_slice(packages);
                args
            }
            PackageManager::Dnf => {
                let mut args = vec!["upgrade".to_string()];
                if yes {
                    args.push("-y".to_string());
                }
                args.extend_from_slice(packages);
                args
            }
        }
    }

    pub fn refresh_cmd_args(&self) -> Vec<String> {
        match self {
            PackageManager::Apt => vec!["update".to_string()],
            PackageManager::Dnf => vec!["makecache".to_string()],
        }
    }

    pub fn is_installed_cmd_args(&self, package: &str) -> Vec<String> {
        match self {
            // Use -W with status abbreviation format to distinguish truly installed
            // packages (ii) from config-files state (rc). dpkg-query --status returns
            // exit 0 for both, which would let 'mom update' operate on removed packages.
            PackageManager::Apt => vec![
                "-W".to_string(),
                "-f=${db:Status-Abbrev}".to_string(),
                package.to_string(),
            ],
            PackageManager::Dnf => vec!["-q".to_string(), package.to_string()],
        }
    }

    pub fn is_installed_binary(&self) -> &'static str {
        match self {
            PackageManager::Apt => "/usr/bin/dpkg-query",
            PackageManager::Dnf => "/usr/bin/rpm",
        }
    }
}

/// Detect which package manager is available on this system.
///
/// Detection strategy:
/// 1. Check for binary existence (/usr/bin/apt-get or /usr/bin/dnf)
/// 2. Corroborate with distro marker files (/etc/debian_version or /etc/redhat-release)
/// 3. Error if both or neither are present
pub fn detect_package_manager() -> Result<PackageManager> {
    let has_apt = Path::new("/usr/bin/apt-get").exists();
    let has_dnf = Path::new("/usr/bin/dnf").exists();

    match (has_apt, has_dnf) {
        (true, false) => {
            verify_debian_system()?;
            Ok(PackageManager::Apt)
        }
        (false, true) => {
            verify_rhel_system()?;
            Ok(PackageManager::Dnf)
        }
        (true, true) => bail!(
            "both /usr/bin/apt-get and /usr/bin/dnf found — \
             cannot determine package manager; contact your sysadmin"
        ),
        (false, false) => bail!(
            "neither /usr/bin/apt-get nor /usr/bin/dnf found — \
             mom supports Debian/Ubuntu (apt-get) and RHEL/Rocky (dnf) only"
        ),
    }
}

fn verify_debian_system() -> Result<()> {
    if !Path::new("/etc/debian_version").exists() {
        bail!(
            "/usr/bin/apt-get found but /etc/debian_version is missing — \
             this does not appear to be a Debian/Ubuntu system"
        );
    }
    Ok(())
}

fn verify_rhel_system() -> Result<()> {
    if !Path::new("/etc/redhat-release").exists() {
        bail!(
            "/usr/bin/dnf found but /etc/redhat-release is missing — \
             this does not appear to be a RHEL/Rocky/Fedora system"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apt_install_args_with_yes() {
        let pm = PackageManager::Apt;
        let args = pm.install_cmd_args(&["curl".to_string(), "wget".to_string()], true);
        assert_eq!(args, vec!["install", "-y", "curl", "wget"]);
    }

    #[test]
    fn test_apt_install_args_without_yes() {
        let pm = PackageManager::Apt;
        let args = pm.install_cmd_args(&["curl".to_string()], false);
        assert_eq!(args, vec!["install", "curl"]);
    }

    #[test]
    fn test_apt_update_args() {
        let pm = PackageManager::Apt;
        let args = pm.update_cmd_args(&["curl".to_string()], true);
        assert_eq!(args, vec!["install", "--only-upgrade", "-y", "curl"]);
    }

    #[test]
    fn test_dnf_update_args() {
        let pm = PackageManager::Dnf;
        let args = pm.update_cmd_args(&["curl".to_string()], false);
        assert_eq!(args, vec!["upgrade", "curl"]);
    }

    #[test]
    fn test_apt_refresh_args() {
        let pm = PackageManager::Apt;
        assert_eq!(pm.refresh_cmd_args(), vec!["update"]);
    }

    #[test]
    fn test_dnf_refresh_args() {
        let pm = PackageManager::Dnf;
        assert_eq!(pm.refresh_cmd_args(), vec!["makecache"]);
    }

    #[test]
    fn test_apt_is_installed_args() {
        let pm = PackageManager::Apt;
        let args = pm.is_installed_cmd_args("curl");
        assert_eq!(args, vec!["-W", "-f=${db:Status-Abbrev}", "curl"]);
    }

    #[test]
    fn test_dnf_is_installed_args() {
        let pm = PackageManager::Dnf;
        let args = pm.is_installed_cmd_args("curl");
        assert_eq!(args, vec!["-q", "curl"]);
    }

    #[test]
    fn test_binary_paths() {
        assert_eq!(PackageManager::Apt.binary(), "/usr/bin/apt-get");
        assert_eq!(PackageManager::Dnf.binary(), "/usr/bin/dnf");
    }
}
