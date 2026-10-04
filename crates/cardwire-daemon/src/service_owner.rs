//! Opt-in persistent service-role ownership inside the existing cardwired.
//!
//! Disabled unless built with `service-roles` AND `/etc/cardwire/service-roles.toml`
//! has `enabled = true`. Everything here is synchronous and runs BEFORE the tokio
//! runtime exists: systemd activation FDs must be taken single-threaded. The
//! catalog is fixed; enrolling a replacement exe/cgroup/device is a separate,
//! not yet implemented, transaction. A failure leaves legacy cardwired behavior
//! untouched and is logged; partial pinned state is retained, never auto-repaired.
use anyhow::{Context, Result, bail, ensure};
use cardwire_ebpf_userspace::{
    fdstore::{Notifier, take_namespaced_activation}, service_guard::{
        Registration, persistent::{PersistentGuard, SystemdOwner}
    }
};
use log::{error, info};
use serde::Deserialize;
use std::{
    collections::BTreeMap, fs::{self, File, OpenOptions}, os::{fd::OwnedFd, unix::fs::OpenOptionsExt}, path::{Path, PathBuf}, sync::{Arc, Mutex, OnceLock}
};

static UNIT: OnceLock<String> = OnceLock::new();

static PROFILES: OnceLock<Vec<ProfileConfig>> = OnceLock::new();

/// Configured profiles (empty unless service roles are active).
pub fn profiles() -> &'static [ProfileConfig] {
    PROFILES.get().map_or(&[], Vec::as_slice)
}

static GUARD: OnceLock<Arc<Mutex<PersistentGuard>>> = OnceLock::new();

/// The running owner, if service roles are enabled and startup succeeded.
pub fn guard() -> Option<Arc<Mutex<PersistentGuard>>> {
    GUARD.get().cloned()
}

pub const CONFIG_FILE: &str = "/etc/cardwire/service-roles.toml";
const MAX_ROLES: usize = 16;
const MAX_DEVICES: usize = 16;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    pub executable: PathBuf,
    pub cgroup: PathBuf,
    pub uid: u32,
}

/// Named complete permission set: one mask per role, bit n = catalog device n.
#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub name: String,
    pub permissions: Vec<u32>,
    /// Devices ANY process may open (bit n = catalog device n); 0 = roles only.
    #[serde(default)]
    pub default_mask: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServiceRolesConfig {
    #[serde(default)]
    pub enabled: bool,
    pub bpf_object: PathBuf,
    #[serde(default = "default_unit")]
    pub unit: String,
    #[serde(default = "default_pin_dir")]
    pub pin_dir: PathBuf,
    pub devices: Vec<PathBuf>,
    #[serde(rename = "role")]
    pub roles: Vec<RoleConfig>,
    #[serde(default, rename = "profile")]
    pub profiles: Vec<ProfileConfig>,
    /// Applied once, right after the guard is CREATED (never on adoption), so the
    /// daemon's own device probing is not caught in the initial deny-all window.
    #[serde(default)]
    pub initial_profile: Option<String>,
}

fn default_unit() -> String {
    "cardwired.service".into()
}

fn default_pin_dir() -> PathBuf {
    "/sys/fs/bpf/cardwire-service-roles".into()
}

impl ServiceRolesConfig {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("invalid service-roles.toml")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.devices.is_empty() && self.devices.len() <= MAX_DEVICES,
            "1..={MAX_DEVICES} devices required"
        );
        ensure!(
            !self.roles.is_empty() && self.roles.len() <= MAX_ROLES,
            "1..={MAX_ROLES} roles required"
        );
        let absolute = |p: &Path| p.is_absolute() && !p.components().any(|c| c.as_os_str() == "..");
        ensure!(
            self.devices
                .iter()
                .all(|p| absolute(p) && p.starts_with("/dev/")),
            "devices must be absolute /dev paths"
        );
        ensure!(
            self.roles
                .iter()
                .all(|r| absolute(&r.executable) && absolute(&r.cgroup)),
            "role paths must be absolute without .."
        );
        let valid_bits = (1u64 << self.devices.len()) - 1;
        let mut names = std::collections::BTreeSet::new();
        for profile in &self.profiles {
            ensure!(
                !profile.name.is_empty()
                    && profile.name.len() <= 32
                    && profile.name.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'-'
                        || b == b'_')
                    && names.insert(profile.name.as_str()),
                "invalid or duplicate profile name"
            );
            ensure!(
                profile.permissions.len() == self.roles.len()
                    && profile
                        .permissions
                        .iter()
                        .all(|m| u64::from(*m) & !valid_bits == 0),
                "profile {} must have one valid mask per role",
                profile.name
            );
            ensure!(
                u64::from(profile.default_mask) & !valid_bits == 0,
                "profile {} default_mask names unknown devices",
                profile.name
            );
        }
        if let Some(initial) = &self.initial_profile {
            ensure!(
                self.profiles.iter().any(|p| &p.name == initial),
                "initial_profile is not a configured profile"
            );
        }
        ensure!(
            absolute(&self.bpf_object) && absolute(&self.pin_dir),
            "bpf_object/pin_dir must be absolute"
        );
        ensure!(
            self.pin_dir.starts_with("/sys/fs/bpf/"),
            "pin_dir must be below /sys/fs/bpf"
        );
        Ok(())
    }
}

/// Read the optional opt-in config. Absent file or `enabled = false` => `None`.
pub fn load_config(path: &Path) -> Result<Option<ServiceRolesConfig>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("cannot read service-roles.toml"),
    };
    let config = ServiceRolesConfig::parse(&text)?;
    Ok(config.enabled.then_some(config))
}

fn open_path(path: &Path, flags: i32) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))
}

/// Pinned objects exist but systemd returned no FDs: never guess/repair.
fn creation_allowed(pins_exist: bool, held: &Option<BTreeMap<String, OwnedFd>>) -> Result<bool> {
    match (held.is_some(), pins_exist) {
        (true, _) => Ok(false),
        (false, false) => Ok(true),
        (false, true) => bail!("owner pins exist but no stored descriptors were passed"),
    }
}

fn build(
    config: &ServiceRolesConfig,
    held: Option<BTreeMap<String, OwnedFd>>,
) -> Result<PersistentGuard> {
    let notify = Notifier::from_environment()?;
    let owner = SystemdOwner::new(&config.unit, &notify)?;
    let create = creation_allowed(config.pin_dir.exists(), &held)?;
    let guard = if create {
        let devices = config
            .devices
            .iter()
            .map(|p| open_path(p, libc::O_PATH))
            .collect::<Result<Vec<_>>>()?;
        let roles = config
            .roles
            .iter()
            .map(|r| {
                Registration::new(
                    open_path(&r.executable, libc::O_PATH)?,
                    open_path(&r.cgroup, libc::O_DIRECTORY)?,
                    r.uid,
                    1,
                    0,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut guard =
            PersistentGuard::create(&config.bpf_object, devices, roles, &config.pin_dir, &owner)?;
        if let Some(initial) = &config.initial_profile {
            let profile = config
                .profiles
                .iter()
                .find(|p| &p.name == initial)
                .context("initial profile vanished")?;
            let prepared = guard.prepare_policy(&profile.permissions, profile.default_mask)?;
            guard.commit(prepared)?;
        }
        guard
    } else {
        let devices = config
            .devices
            .iter()
            .map(|p| open_path(p, libc::O_PATH))
            .collect::<Result<Vec<_>>>()?;
        PersistentGuard::adopt(
            held.context("no descriptors")?,
            devices,
            &config.pin_dir,
            &owner,
        )?
    };
    info!(
        "service-roles: {} generation {}",
        if create { "created" } else { "adopted" },
        guard.current_generation()
    );
    Ok(guard)
}

/// Replace one role's executable/cgroup identity (service restarted => new cgroup).
/// Root authorization is the caller's job. Returns the new policy generation.
pub fn re_enroll(index: usize, executable: &str, cgroup: &str) -> Result<u64> {
    let (executable, cgroup) = (Path::new(executable), Path::new(cgroup));
    ensure!(
        [executable, cgroup]
            .iter()
            .all(|p| p.is_absolute() && !p.components().any(|c| c.as_os_str() == "..")),
        "absolute paths without .. required"
    );
    let guard = guard().context("service roles are not active")?;
    let unit = UNIT.get().context("service roles are not active")?;
    let executable = open_path(executable, libc::O_PATH)?;
    let cgroup = open_path(cgroup, libc::O_DIRECTORY)?;
    let notify = Notifier::from_environment()?;
    let owner = SystemdOwner::new(unit, &notify)?;
    let mut guard = guard
        .lock()
        .map_err(|_| anyhow::anyhow!("owner poisoned"))?;
    guard.reenroll(index, executable, cgroup, &owner)
}

/// Single-threaded startup entry. MUST be the first thing `main` does after logging.
/// On success the guard lives for the process lifetime in [`guard()`].
pub fn start() {
    let config = match load_config(Path::new(CONFIG_FILE)) {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(e) => {
            error!("service-roles disabled: {e:#}");
            return;
        }
    };
    // SAFETY: called from the main thread before any runtime/thread is created
    // and before any other code wraps FDs 3.. .
    let held = match unsafe { take_namespaced_activation("cw-") } {
        Ok(held) => held,
        Err(e) => {
            error!("service-roles disabled: bad activation: {e:#}");
            return;
        }
    };
    match build(&config, held) {
        Ok(guard) => {
            let _ = UNIT.set(config.unit.clone());
            let _ = PROFILES.set(config.profiles.clone());
            let _ = GUARD.set(Arc::new(Mutex::new(guard)));
        }
        Err(e) => error!("service-roles disabled, legacy policy only: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
enabled = true
bpf_object = "/usr/lib/cardwire/service_guard.bpf.o"
devices = ["/dev/dri/renderD129", "/dev/nvidiactl"]
[[role]]
executable = "/usr/bin/llama-server"
cgroup = "/sys/fs/cgroup/user.slice/llama.service"
uid = 1000
"#;

    #[test]
    fn parses_defaults() {
        let c = ServiceRolesConfig::parse(GOOD).unwrap();
        assert_eq!(c.unit, "cardwired.service");
        assert_eq!(c.roles.len(), 1);
        assert!(c.pin_dir.starts_with("/sys/fs/bpf"));
    }

    #[test]
    fn rejects_bad_configs() {
        for (from, to) in [
            ("/dev/nvidiactl", "/tmp/x"),
            ("/usr/bin/llama-server", "../llama-server"),
            ("enabled = true", "enabled = true\nsurprise = 1"),
            ("/usr/lib/cardwire/service_guard.bpf.o", "rel.o"),
        ] {
            assert!(
                ServiceRolesConfig::parse(&GOOD.replace(from, to)).is_err(),
                "{to}"
            );
        }
        assert!(ServiceRolesConfig::parse(&GOOD.replace("[[role]]", "[[x]]")).is_err());
        let pin =
            format!("{GOOD}\n").replace("enabled = true", "enabled = true\npin_dir = \"/tmp/p\"");
        assert!(ServiceRolesConfig::parse(&pin).is_err());
    }

    #[test]
    fn profiles_are_validated() {
        let ok = format!(
            "{GOOD}\n[[profile]]\nname = \"gaming\"\npermissions = [3]\n[[profile]]\nname = \"work-1\"\npermissions = [0]\n"
        );
        assert_eq!(ServiceRolesConfig::parse(&ok).unwrap().profiles.len(), 2);
        for bad in [
            "name = \"Gaming\"\npermissions = [1]",
            "name = \"x\"\npermissions = [1, 1]",
            "name = \"x\"\npermissions = [4]",
            "name = \"\"\npermissions = [1]",
        ] {
            let text = format!("{GOOD}\n[[profile]]\n{bad}\n");
            assert!(ServiceRolesConfig::parse(&text).is_err(), "{bad}");
        }
        let dup = format!(
            "{GOOD}\n[[profile]]\nname = \"x\"\npermissions = [1]\n[[profile]]\nname = \"x\"\npermissions = [0]\n"
        );
        assert!(ServiceRolesConfig::parse(&dup).is_err());
    }

    #[test]
    fn generated_helper_config_parses() {
        // Shape emitted by the helper's egpu-service-roles-config.py (7 NVIDIA nodes).
        let text = r#"
enabled = true
bpf_object = "/usr/lib/cardwire/service_guard.bpf.o"
unit = "cardwired.service"
devices = ["/dev/dri/card0", "/dev/dri/renderD129", "/dev/nvidia0", "/dev/nvidiactl",
  "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools", "/dev/nvidia-modeset"]
[[role]]
executable = "/usr/bin/true"
cgroup = "/sys/fs/cgroup/user.slice"
uid = 1000
[[role]]
executable = "/usr/bin/true"
cgroup = "/sys/fs/cgroup/system.slice"
uid = 0
[[profile]]
name = "gaming-nvidia"
permissions = [127, 127]
[[profile]]
name = "work-nvidia"
permissions = [60, 79]
[[profile]]
name = "work-igpu"
permissions = [60, 0]
"#;
        let config = ServiceRolesConfig::parse(text).unwrap();
        assert_eq!(
            (
                config.devices.len(),
                config.roles.len(),
                config.profiles.len()
            ),
            (7, 2, 3)
        );
    }

    #[test]
    fn profile_default_mask_is_bounded() {
        let ok =
            format!("{GOOD}\n[[profile]]\nname = \"g\"\npermissions = [0]\ndefault_mask = 3\n");
        assert_eq!(
            ServiceRolesConfig::parse(&ok).unwrap().profiles[0].default_mask,
            3
        );
        let bad =
            format!("{GOOD}\n[[profile]]\nname = \"g\"\npermissions = [0]\ndefault_mask = 4\n");
        assert!(ServiceRolesConfig::parse(&bad).is_err());
    }

    #[test]
    fn initial_profile_must_exist() {
        // Top-level keys must precede the first table.
        let with = |name: &str| {
            GOOD.replace(
                "enabled = true",
                &format!("enabled = true\ninitial_profile = \"{name}\""),
            ) + "\n[[profile]]\nname = \"g\"\npermissions = [0]\n"
        };
        assert_eq!(
            ServiceRolesConfig::parse(&with("g"))
                .unwrap()
                .initial_profile
                .as_deref(),
            Some("g")
        );
        assert!(ServiceRolesConfig::parse(&with("nope")).is_err());
    }

    #[test]
    fn disabled_or_absent_is_none() {
        let dir = std::env::temp_dir().join(format!("cw-sr-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(load_config(&dir.join("missing.toml")).unwrap().is_none());
        let f = dir.join("off.toml");
        fs::write(&f, GOOD.replace("enabled = true", "enabled = false")).unwrap();
        assert!(load_config(&f).unwrap().is_none());
        fs::write(&f, "garbage = [").unwrap();
        assert!(load_config(&f).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn never_recreates_over_existing_pins() {
        assert!(creation_allowed(false, &None).unwrap());
        assert!(creation_allowed(true, &None).is_err());
        assert!(!creation_allowed(true, &Some(BTreeMap::new())).unwrap());
    }
}
