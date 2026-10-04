//! Experimental persistent fixed-registration owner for existing Cardwire.
//!
//! Permissions can change indefinitely without restarting admitted services.
//! Registration/device replacement is never implicit: `reenroll` is a separate
//! transaction whose commit record is the kernel-active snapshot (an old and a
//! new sealed manifest may briefly coexist; adoption picks the one matching it).
use super::*;
use crate::fdstore::Notifier;
use aya::programs::{
    links::{FdLink, PinnedLink}, loaded_programs
};
use std::{
    collections::{BTreeMap, BTreeSet}, fs::{self, DirBuilder}, io::Write, os::{
        fd::{FromRawFd, OwnedFd}, unix::fs::{DirBuilderExt, FileExt}
    }, process::Command
};

const MAGIC: &[u8; 8] = b"CWPST003";
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const MAPS: [&str; 3] = ["CW_ACTIVE", "CW_DEVICES_MAP", "CW_ROLE_TASKS"];
const LINKS: [&str; 2] = ["exec_link", "open_link"];
const MANIFEST_PREFIX: &str = "cw-manifest-";
const BYTES: usize =
    8 + 8 + 7 * 4 + size_of::<SnapshotPod>() + size_of::<InventoryPod>() + MAX_ROLES * 8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Manifest {
    /// Catalog epoch: 1 at creation, +1 per committed re-enrollment.
    epoch: u64,
    // outer/inventory/tasks map IDs, then exec link/program, open link/program.
    ids: [u32; 7],
    catalog: Snapshot,
    inventory: Inventory,
    /// Per role: `st_dev` of its executable at registration (see `Registration::from_held`).
    exe_stat_dev: [u64; MAX_ROLES],
}

fn pod_bytes<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: Pod promises initialized padding-free bytes and no invalid bits.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

fn read_pod<T: Pod>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() == size_of::<T>(), "wrong manifest field size");
    // Native ABI is intentional: FD store is only valid in this same boot/ABI.
    Ok(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        ensure!(self.epoch != 0, "zero catalog epoch");
        ensure!(
            self.ids.iter().all(|id| *id != 0),
            "zero kernel object identity"
        );
        self.inventory.validate().map_err(|e| anyhow!(e))?;
        // A catalog is identity-only: its incarnations may predate its base
        // generation (older roles) or equal base+1 (a role replaced by the next
        // generation). Normalise them for the shared structural validation.
        let mut shape = self.catalog;
        for role in &mut shape.roles[..self.catalog.role_count as usize] {
            ensure!(
                role.incarnation != 0 && role.incarnation <= self.catalog.generation + 1,
                "catalog incarnation out of range"
            );
            role.incarnation = shape.generation;
        }
        shape
            .validate(None, self.inventory.count as usize)
            .map_err(|e| anyhow!(e))?;
        ensure!(
            self.catalog.roles.iter().all(|r| r.access_mask == 0),
            "catalog must describe denied registrations"
        );
        ensure!(
            self.exe_stat_dev
                .iter()
                .enumerate()
                .all(|(n, dev)| (*dev != 0) == (n < self.catalog.role_count as usize)),
            "executable device list does not match the catalog"
        );
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.epoch.to_ne_bytes());
        bytes.extend_from_slice(pod_bytes(&self.ids));
        bytes.extend_from_slice(pod_bytes(&SnapshotPod(self.catalog)));
        bytes.extend_from_slice(pod_bytes(&InventoryPod(self.inventory)));
        bytes.extend_from_slice(pod_bytes(&self.exe_stat_dev));
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == BYTES && bytes.get(..8) == Some(MAGIC.as_slice()),
            "invalid owner manifest"
        );
        let split = 44 + size_of::<SnapshotPod>();
        let inventory_end = split + size_of::<InventoryPod>();
        let result = Self {
            epoch: u64::from_ne_bytes(bytes[8..16].try_into()?),
            ids: read_pod(&bytes[16..44])?,
            catalog: read_pod::<SnapshotPod>(&bytes[44..split])?.0,
            inventory: read_pod::<InventoryPod>(&bytes[split..inventory_end])?.0,
            exe_stat_dev: read_pod(&bytes[inventory_end..])?,
        };
        result.validate()?;
        Ok(result)
    }

    // Deduplicate references by immutable identity, not the provided file name.
    fn exe_slot(&self, n: usize) -> usize {
        let r = &self.catalog.roles[n];
        (0..n)
            .find(|i| {
                let p = &self.catalog.roles[*i];
                p.executable_device == r.executable_device
                    && p.executable_inode == r.executable_inode
            })
            .unwrap_or(n)
    }

    fn cg_slot(&self, n: usize) -> usize {
        (0..n)
            .find(|i| self.catalog.roles[*i].cgroup_id == self.catalog.roles[n].cgroup_id)
            .unwrap_or(n)
    }

    // Reference names embed the slot role's incarnation: a re-enrolled role
    // never reuses a name, so old and new references can coexist briefly.
    fn exe_name(&self, n: usize) -> String {
        let slot = self.exe_slot(n);
        format!("cw-exe-{slot}-{}", self.catalog.roles[slot].incarnation)
    }

    fn cg_name(&self, n: usize) -> String {
        let slot = self.cg_slot(n);
        format!("cw-cg-{slot}-{}", self.catalog.roles[slot].incarnation)
    }

    fn name(&self) -> String {
        format!("{MANIFEST_PREFIX}{}", self.epoch)
    }

    fn names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::from([self.name()]);
        // Device nodes are deliberately NOT stored in systemd: SELinux may forbid
        // init_t ioctl on them and the identity check re-opens configured paths.
        for n in 0..self.catalog.role_count as usize {
            names.insert(self.exe_name(n));
            names.insert(self.cg_name(n));
        }
        names
    }

    fn check_policy(&self, policy: &Snapshot) -> Result<()> {
        if *policy != self.catalog {
            policy
                .validate(Some(&self.catalog), self.inventory.count as usize)
                .map_err(|e| anyhow!(e))?;
        }
        ensure!(
            policy.role_count == self.catalog.role_count,
            "registration count changed"
        );
        for (role, expected) in policy.roles.iter().zip(&self.catalog.roles) {
            ensure!(
                Role {
                    access_mask: 0,
                    ..*role
                } == *expected,
                "unowned registration in active policy"
            );
        }
        Ok(())
    }
}

/// Store verification belongs to the existing owning systemd service, not a
/// second resident GPU manager. Only its current MainPID can create/adopt state.
pub struct SystemdOwner<'a> {
    unit: &'a str,
    notify: &'a Notifier,
}

impl<'a> SystemdOwner<'a> {
    pub fn new(unit: &'a str, notify: &'a Notifier) -> Result<Self> {
        ensure!(
            unit.ends_with(".service")
                && !unit.starts_with('-')
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b)),
            "invalid owner unit"
        );
        Ok(Self { unit, notify })
    }

    fn property(&self, name: &str) -> Result<String> {
        let output = Command::new("systemctl")
            .args(["--system", "show", self.unit, "-p", name, "--value"])
            .output()?;
        ensure!(
            output.status.success(),
            "cannot inspect owning systemd service"
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }

    fn check(&self, count: usize, capacity: usize) -> Result<()> {
        ensure!(
            self.property("MainPID")?.parse::<u32>()? == std::process::id(),
            "not the owning service MainPID"
        );
        ensure!(
            self.property("FileDescriptorStorePreserve")? == "yes",
            "owner store must survive stop/failure"
        );
        ensure!(
            self.property("FileDescriptorStoreMax")?.parse::<usize>()? >= capacity,
            "owner FD store too small"
        );
        ensure!(
            self.property("NFileDescriptorStore")?.parse::<usize>()? == count,
            "unexpected owner FD store count"
        );
        Ok(())
    }
}

fn check_pin_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "canonical absolute pin directory required"
    );
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "private root-owned pin directory required"
    );
    let directory = File::open(path)?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(directory.as_raw_fd(), &mut info) } == 0
            && info.f_type == 0xcafe4a11,
        "bpffs pin directory required"
    );
    Ok(())
}

fn sealed(bytes: &[u8]) -> Result<File> {
    let fd = unsafe {
        libc::memfd_create(
            c"cardwire-service-owner".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    ensure!(
        fd >= 0,
        "cannot create owner manifest: {}",
        io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } == 0,
        "cannot seal owner manifest"
    );
    Ok(file)
}

fn inspect_maps(base: &Path) -> Result<[u32; 3]> {
    let mut ids = [0; 3];
    for (n, (kind, value, max, flags)) in
        [(12, 4, 1, 0), (2, 72, 1, READONLY_PROGRAM), (29, 16, 0, 1)]
            .into_iter()
            .enumerate()
    {
        let info = MapData::from_pin(base.join(MAPS[n]))?.info()?;
        ensure!(
            info.map_type()? as u32 == kind
                && info.key_size() == 4
                && info.value_size() == value
                && info.max_entries() == max
                && info.map_flags() == flags,
            "invalid map ABI: {}",
            MAPS[n]
        );
        ids[n] = info.id();
    }
    Ok(ids)
}

fn inspect_links(base: &Path, maps: &[u32; 3]) -> Result<[u32; 4]> {
    let mut ids = [0; 4];
    for (n, name) in LINKS.into_iter().enumerate() {
        let link: FdLink = PinnedLink::from_pin(base.join(name))?.into();
        let info = link.info()?;
        let program = loaded_programs()
            .filter_map(Result::ok)
            .find(|p| p.id() == info.program_id())
            .context("attached program not found")?;
        let mut actual = program.map_ids()?.context("attached map IDs unavailable")?;
        let mut expected = if n == 0 {
            vec![maps[0], maps[2]]
        } else {
            maps.to_vec()
        };
        actual.sort_unstable();
        expected.sort_unstable();
        ensure!(actual == expected, "attached program uses foreign maps");
        ids[n * 2] = info.id();
        ids[n * 2 + 1] = info.program_id();
    }
    Ok(ids)
}

fn verify_frozen<T: Pod>(array: &mut Array<MapData, T>, value: T) -> Result<()> {
    let error = match array.set(0, value, 0) {
        Ok(()) => anyhow::bail!("owner map is not frozen"),
        Err(error) => error,
    };
    ensure!(
        matches!(error, aya::maps::MapError::SyscallError(ref e)
        if e.io_error.raw_os_error() == Some(libc::EPERM)),
        "unexpected immutable map result: {error}"
    );
    Ok(())
}

fn read_manifests(held: &BTreeMap<String, OwnedFd>) -> Result<Vec<Manifest>> {
    let mut found = Vec::new();
    for (name, fd) in held {
        let Some(epoch) = name.strip_prefix(MANIFEST_PREFIX) else {
            continue;
        };
        let file = File::from(fd.try_clone()?);
        ensure!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "unsealed owner manifest"
        );
        ensure!(
            file.metadata()?.len() == BYTES as u64,
            "wrong owner manifest length"
        );
        let mut bytes = [0u8; BYTES];
        file.read_exact_at(&mut bytes, 0)?;
        let manifest = Manifest::decode(&bytes)?;
        ensure!(
            epoch.parse::<u64>().ok() == Some(manifest.epoch) && manifest.name() == *name,
            "manifest name does not match its epoch"
        );
        found.push(manifest);
    }
    found.sort_by_key(|m| m.epoch);
    ensure!(
        matches!(found.len(), 1 | 2) && (found.len() == 1 || found[1].epoch == found[0].epoch + 1),
        "missing, extra or non-consecutive owner manifests"
    );
    Ok(found)
}

/// Exactly one stored catalog must describe the active registrations.
fn select_manifest(candidates: Vec<Manifest>, active: &Snapshot) -> Result<Manifest> {
    let mut matching: Vec<_> = candidates
        .into_iter()
        .filter(|m| m.check_policy(active).is_ok())
        .collect();
    ensure!(
        matching.len() == 1,
        "active policy does not match exactly one stored catalog"
    );
    Ok(matching.remove(0))
}

/// Names that may be removed during adoption: leftover references of an
/// interrupted re-enrollment (new, uncommitted) or its interrupted cleanup (old).
/// Anything else not in the expected set is a foreign descriptor and an error.
fn stale_names<'a>(
    held: impl Iterator<Item = &'a String>,
    expected: &BTreeSet<String>,
    generation: u64,
) -> Result<Vec<String>> {
    let mut stale = Vec::new();
    for name in held.filter(|n| !expected.contains(*n)) {
        let numbers = |rest: &str| -> Option<(u64, u64)> {
            let (slot, inc) = rest.split_once('-')?;
            Some((slot.parse().ok()?, inc.parse().ok()?))
        };
        let plausible = if let Some(rest) = name
            .strip_prefix("cw-exe-")
            .or_else(|| name.strip_prefix("cw-cg-"))
        {
            numbers(rest).is_some_and(|(slot, inc)| {
                slot < MAX_ROLES as u64 && inc != 0 && inc <= generation.saturating_add(1)
            })
        } else if let Some(epoch) = name.strip_prefix(MANIFEST_PREFIX) {
            epoch.parse::<u64>().is_ok_and(|e| e != 0)
        } else {
            false
        };
        ensure!(plausible, "foreign owner descriptor {name}");
        stale.push(name.clone());
    }
    Ok(stale)
}

/// A prepared immutable replacement. Dropping it has no policy effect.
pub struct PreparedPermissions {
    owner_map_id: u32,
    based_on: u64,
    snapshot: Snapshot,
    inner: Array<MapData, SnapshotPod>,
}

/// Persistent guard over a fixed validated registration/device catalog.
/// Drop closes local handles, NEVER unpins or cleans PID1's object references.
pub struct PersistentGuard {
    outer: ArrayOfMaps<MapData, Array<MapData, SnapshotPod>>,
    manifest: Manifest,
    current: Snapshot,
    held: BTreeMap<String, OwnedFd>,
    /// Pinned task-storage map holding per-process admission tickets.
    tasks: MapData,
}

/// Real/effective uid of a process from `/proc/<pid>/status` text.
fn status_uid(text: &str) -> Result<u32> {
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .context("no Uid line")?;
    let ids: Vec<u32> = line
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(ids.len() >= 2, "short Uid line");
    ensure!(ids[0] == ids[1], "real and effective uid differ");
    Ok(ids[0])
}

/// cgroup v2 path of a process from `/proc/<pid>/cgroup` text.
fn cgroup_v2_path(text: &str) -> Result<&str> {
    let mut found = text.lines().filter_map(|l| l.strip_prefix("0::"));
    let path = found.next().context("no cgroup v2 entry")?;
    ensure!(
        found.next().is_none() && path.starts_with('/') && !path.split('/').any(|c| c == ".."),
        "unexpected cgroup path"
    );
    Ok(path)
}

impl PersistentGuard {
    /// Initial activation is deny-all. A separate explicit permission commit is
    /// required after complete persistence verification. Partial bootstrap state
    /// is deliberately retained and rejected, never repaired by guessing names.
    pub fn create(
        object: &Path,
        devices: Vec<File>,
        registrations: Vec<Registration>,
        base: &Path,
        owner: &SystemdOwner<'_>,
    ) -> Result<Self> {
        ensure!(!base.exists(), "refusing existing owner pins");
        let adoption_devices = devices
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        let mut guard = ServiceGuard::attach(object, devices)?;
        let roles = registrations
            .iter()
            .map(|r| r.with_access(0))
            .collect::<Result<Vec<_>>>()?;
        guard.publish(1, roles)?;
        let mut manifest = Manifest {
            epoch: 1,
            ids: [1; 7],
            catalog: guard.current.context("no initial catalog")?,
            inventory: guard.inventory,
            exe_stat_dev: {
                let mut devs = [0u64; MAX_ROLES];
                for (slot, registration) in devs.iter_mut().zip(&registrations) {
                    *slot = registration.stat_dev;
                }
                devs
            },
        };
        manifest.validate()?;
        let mut held = BTreeMap::new();
        for (n, registration) in registrations.iter().enumerate() {
            if manifest.exe_slot(n) == n {
                held.insert(
                    manifest.exe_name(n),
                    registration.executable.as_fd().try_clone_to_owned()?,
                );
            }
            if manifest.cg_slot(n) == n {
                held.insert(
                    manifest.cg_name(n),
                    registration.cgroup.as_fd().try_clone_to_owned()?,
                );
            }
        }
        let capacity = held.len() + 1;
        owner.check(0, capacity)?;
        for (name, fd) in &held {
            owner.notify.store(name, fd.as_fd())?;
        }
        owner.notify.barrier()?;
        owner.check(held.len(), capacity)?;
        // Once hooks are pinned, object references already belong to PID1.
        DirBuilder::new().mode(0o700).create(base)?;
        check_pin_directory(base)?;
        for name in MAPS {
            guard
                .ebpf
                .map(name)
                .context("missing guard map")?
                .pin(base.join(name))?;
        }
        let exec: &mut BtfTracePoint = guard
            .ebpf
            .program_mut("service_exec")
            .context("exec program")?
            .try_into()?;
        let link: FdLink = exec
            .take_link(guard.exec_link.take().context("missing exec link")?)?
            .into();
        link.pin(base.join(LINKS[0]))?;
        let open: &mut Lsm = guard
            .ebpf
            .program_mut("service_open")
            .context("open program")?
            .try_into()?;
        let link: FdLink = open
            .take_link(guard.open_link.take().context("missing open link")?)?
            .into();
        link.pin(base.join(LINKS[1]))?;
        let maps = inspect_maps(base)?;
        manifest.ids[..3].copy_from_slice(&maps);
        manifest.ids[3..].copy_from_slice(&inspect_links(base, &maps)?);
        let file = sealed(&manifest.encode()?)?;
        owner.notify.store(&manifest.name(), file.as_fd())?;
        owner.notify.barrier()?;
        held.insert(manifest.name(), file.into());
        owner.check(held.len(), capacity)?;
        // Creation and restart use exactly the same complete adoption checks.
        Self::adopt(held, adoption_devices, base, owner)
    }

    /// `devices`: the configured protected nodes, re-opened by the caller; their
    /// device numbers must equal the stored inventory (identity, not retention).
    pub fn adopt(
        mut held: BTreeMap<String, OwnedFd>,
        devices: Vec<File>,
        base: &Path,
        owner: &SystemdOwner<'_>,
    ) -> Result<Self> {
        check_pin_directory(base)?;
        owner.check(held.len(), held.len())?;
        let candidates = read_manifests(&held)?;
        let maps = inspect_maps(base)?;
        let links = inspect_links(base, &maps)?;
        for candidate in &candidates {
            ensure!(
                candidate.ids[..3] == maps,
                "pinned maps differ from stored identities"
            );
            ensure!(
                candidate.ids[3..] == links,
                "pinned links differ from stored identities"
            );
            ensure!(
                candidate.inventory == candidates[0].inventory,
                "stored manifests disagree on the device inventory"
            );
        }
        let mut inventory = Array::<_, InventoryPod>::try_from(Map::from_map_data(
            MapData::from_pin(base.join(MAPS[1]))?,
        )?)?;
        ensure!(
            inventory.get(&0, 0)?.0 == candidates[0].inventory,
            "inventory differs from manifest"
        );
        verify_frozen(&mut inventory, InventoryPod(candidates[0].inventory))?;
        let outer = ArrayOfMaps::<_, Array<MapData, SnapshotPod>>::try_from(Map::from_map_data(
            MapData::from_pin(base.join(MAPS[0]))?,
        )?)?;
        let mut inner = outer.get(&0, 0)?;
        let info = inner.map().info()?;
        ensure!(
            info.key_size() == 4
                && info.value_size() == size_of::<SnapshotPod>() as u32
                && info.max_entries() == 1
                && info.map_flags() == READONLY_PROGRAM,
            "invalid active policy ABI"
        );
        let current = inner.get(&0, 0)?.0;
        verify_frozen(&mut inner, SnapshotPod(current))?;
        // The kernel-active snapshot is the commit record of any re-enrollment:
        // exactly one stored catalog may describe its registrations.
        let manifest = select_manifest(candidates, &current)?;
        let expected = manifest.names();
        let stale = stale_names(held.keys(), &expected, current.generation)?;
        for name in &stale {
            owner.notify.remove(name)?;
            held.remove(name);
        }
        if !stale.is_empty() {
            owner.notify.barrier()?;
        }
        ensure!(
            held.keys().cloned().collect::<BTreeSet<_>>() == expected,
            "incomplete/foreign owner descriptor set"
        );
        owner.check(held.len(), held.len())?;
        ensure!(
            devices.len() == manifest.inventory.count as usize,
            "configured device count differs from the stored inventory"
        );
        for (n, device) in devices.iter().enumerate() {
            let meta = device.metadata()?;
            ensure!(
                meta.file_type().is_char_device()
                    && kernel_dev(meta.rdev())? == manifest.inventory.devices[n],
                "device identity differs"
            );
        }
        for n in 0..manifest.catalog.role_count as usize {
            let expected = manifest.catalog.roles[n];
            let role = Registration::from_held(
                File::from(held[&manifest.exe_name(n)].try_clone()?),
                File::from(held[&manifest.cg_name(n)].try_clone()?),
                &expected,
                manifest.exe_stat_dev[n],
            )?;
            ensure!(
                role.rule == expected,
                "stored registration differs from manifest"
            );
        }
        Ok(Self {
            outer,
            manifest,
            current,
            held,
            tasks: MapData::from_pin(base.join(MAPS[2]))?,
        })
    }

    /// Admit an ALREADY RUNNING process (thread-group leader) to a catalog role, as
    /// the exec hook would have: used when enrollment could not precede its exec
    /// (e.g. the desktop compositor). The process must match the role's exact
    /// executable inode, uid and cgroup right now; the kernel re-checks all three on
    /// every protected open, so a later change of any of them revokes access.
    pub fn admit_process(&self, pid: u32, role_index: usize) -> Result<()> {
        ensure!(role_index < self.role_count(), "unknown role");
        let role = self.current.roles[role_index];
        // SAFETY: plain syscall; the result is wrapped immediately.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        ensure!(
            raw >= 0,
            "cannot open pidfd for {pid} (not a thread-group leader?): {}",
            io::Error::last_os_error()
        );
        // SAFETY: freshly returned, owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
        let exe = File::open(proc.join("exe"))?.metadata()?;
        ensure!(
            exe.ino() == role.executable_inode
                && exe.dev() == self.manifest.exe_stat_dev[role_index],
            "process executable is not the role's executable"
        );
        ensure!(
            status_uid(&fs::read_to_string(proc.join("status"))?)? == role.uid,
            "process uid is not the role's uid"
        );
        let cgroup = fs::read_to_string(proc.join("cgroup"))?;
        let group =
            Path::new("/sys/fs/cgroup").join(cgroup_v2_path(&cgroup)?.trim_start_matches('/'));
        ensure!(
            fs::metadata(&group)?.ino() == role.cgroup_id,
            "process cgroup is not the role's cgroup"
        );
        // The pidfd was opened before /proc was read: if the process exited in
        // between, signal 0 fails and nothing is written.
        // SAFETY: valid pidfd, null siginfo, no flags.
        ensure!(
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), 0, 0, 0) } == 0,
            "process vanished during verification"
        );
        let key = pidfd.as_raw_fd();
        let ticket = cardwire_policy::service_roles::Ticket {
            incarnation: role.incarnation,
            role_index: role_index as u32,
            reserved: 0,
        };
        // bpf_attr for BPF_MAP_UPDATE_ELEM: map_fd, pad, key, value, flags.
        let attr: [u64; 4] = [
            u64::from(self.tasks.fd().as_fd().as_raw_fd() as u32),
            (&key as *const i32) as u64,
            (&ticket as *const _) as u64,
            0,
        ];
        // SAFETY: attr/key/ticket are live and sized for the kernel's reads.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                2u32,
                attr.as_ptr(),
                size_of::<[u64; 4]>() as u32,
            )
        };
        ensure!(
            result == 0,
            "cannot record the admission ticket: {}",
            io::Error::last_os_error()
        );
        Ok(())
    }

    /// Catalog uid of one role (re-enrollment keeps it).
    pub fn role_uid(&self, index: usize) -> Result<u32> {
        ensure!(index < self.role_count(), "unknown role");
        Ok(self.current.roles[index].uid)
    }

    /// Replace one role's executable/cgroup identity (e.g. after a service
    /// restart recreated its cgroup) as ONE committed transaction. The caller must
    /// be root-authenticated. New references are stored in the FD store first, the
    /// kernel snapshot swap is the commit record, old references are removed last;
    /// any interruption is resolved by [`PersistentGuard::adopt`]. The role keeps
    /// its current permission mask. References shared with other roles
    /// (deduplicated executable/cgroup) cannot be re-enrolled.
    pub fn reenroll(
        &mut self,
        index: usize,
        executable: File,
        cgroup: File,
        owner: &SystemdOwner<'_>,
    ) -> Result<u64> {
        ensure!(index < self.role_count(), "unknown role");
        let generation = self
            .current
            .generation
            .checked_add(1)
            .context("policy generation exhausted")?;
        let old = self.current.roles[index];
        let registration =
            Registration::new(executable, cgroup, old.uid, generation, old.access_mask)?;
        ensure!(
            !registration.rule.same_identity(&old),
            "registration is unchanged"
        );
        let mut snapshot = self.current;
        snapshot.generation = generation;
        snapshot.roles[index] = registration.rule;
        snapshot
            .validate(Some(&self.current), self.manifest.inventory.count as usize)
            .map_err(|e| anyhow!(e))?;
        let mut catalog = self.manifest.catalog;
        catalog.generation = self.current.generation;
        catalog.roles[index] = Role {
            access_mask: 0,
            ..registration.rule
        };
        let next = Manifest {
            epoch: self
                .manifest
                .epoch
                .checked_add(1)
                .context("catalog epoch exhausted")?,
            catalog,
            exe_stat_dev: {
                let mut devs = self.manifest.exe_stat_dev;
                devs[index] = registration.stat_dev;
                devs
            },
            ..self.manifest.clone()
        };
        next.validate()?;
        next.check_policy(&snapshot)?;
        let old_names = self.manifest.names();
        let new_names = next.names();
        let added: Vec<String> = new_names.difference(&old_names).cloned().collect();
        let allowed = [next.name(), next.exe_name(index), next.cg_name(index)];
        ensure!(
            added.iter().all(|name| allowed.contains(name)),
            "role shares executable/cgroup references with other roles"
        );
        let manifest_file = sealed(&next.encode()?)?;
        let capacity = self.held.len() + added.len();
        owner.check(self.held.len(), capacity)?;
        for name in &added {
            let fd = if *name == next.name() {
                manifest_file.as_fd()
            } else if *name == next.exe_name(index) {
                registration.executable.as_fd()
            } else {
                registration.cgroup.as_fd()
            };
            owner.notify.store(name, fd)?;
        }
        owner.notify.barrier()?;
        owner.check(capacity, capacity)?;
        ensure!(
            self.outer.get(&0, 0)?.get(&0, 0)?.0 == self.current,
            "policy changed outside this owner"
        );
        let mut inner = Array::<MapData, SnapshotPod>::create(1, READONLY_PROGRAM)?;
        inner.set(0, SnapshotPod(snapshot), 0)?;
        freeze(inner.map().fd().as_fd())?;
        // The single kernel swap commits the new registration. Everything after
        // it is idempotent cleanup that adoption can finish after a crash.
        self.outer.set(0, &inner, 0)?;
        self.current = snapshot;
        for name in &added {
            let source = if *name == next.name() {
                manifest_file.as_fd()
            } else if *name == next.exe_name(index) {
                registration.executable.as_fd()
            } else {
                registration.cgroup.as_fd()
            };
            self.held.insert(name.clone(), source.try_clone_to_owned()?);
        }
        self.manifest = next;
        let stale: Vec<String> = old_names.difference(&new_names).cloned().collect();
        let cleanup = (|| -> Result<()> {
            // Sorted: references first, old manifest last.
            for name in &stale {
                owner.notify.remove(name)?;
            }
            owner.notify.barrier()?;
            owner.check(new_names.len(), new_names.len())
        })();
        for name in &stale {
            self.held.remove(name);
        }
        if let Err(error) = cleanup {
            log::warn!("re-enrollment committed; stale FD cleanup deferred to adoption: {error:#}");
        }
        Ok(generation)
    }

    pub fn current_generation(&self) -> u64 {
        self.current.generation
    }

    /// Number of fixed catalog roles; one permission mask is required per role.
    pub fn role_count(&self) -> usize {
        self.current.role_count as usize
    }

    /// Current per-role permission masks (bit n = catalog device n).
    pub fn permissions(&self) -> Vec<u32> {
        self.current.roles[..self.role_count()]
            .iter()
            .map(|role| role.access_mask)
            .collect()
    }

    /// Live registrations as (incarnation, cgroup id, executable inode, uid), catalog order.
    pub fn role_identities(&self) -> Vec<(u64, u64, u64, u32)> {
        self.current.roles[..self.role_count()]
            .iter()
            .map(|r| (r.incarnation, r.cgroup_id, r.executable_inode, r.uid))
            .collect()
    }

    /// Devices any process may open (non-role processes included).
    pub fn default_mask(&self) -> u32 {
        self.current.default_mask
    }

    /// Replace role masks, keeping the current default mask.
    pub fn prepare_permissions(&self, masks: &[u32]) -> Result<PreparedPermissions> {
        self.prepare_policy(masks, self.current.default_mask)
    }

    /// Replace role masks AND the default (non-role) mask as one generation.
    pub fn prepare_policy(&self, masks: &[u32], default_mask: u32) -> Result<PreparedPermissions> {
        ensure!(
            masks.len() == self.current.role_count as usize,
            "wrong permission count"
        );
        let mut snapshot = self.current;
        snapshot.generation = snapshot
            .generation
            .checked_add(1)
            .context("policy generation exhausted")?;
        for (role, mask) in snapshot.roles.iter_mut().zip(masks) {
            role.access_mask = *mask;
        }
        snapshot.default_mask = default_mask;
        snapshot
            .validate(Some(&self.current), self.manifest.inventory.count as usize)
            .map_err(|e| anyhow!(e))?;
        self.manifest.check_policy(&snapshot)?;
        let mut inner = Array::<MapData, SnapshotPod>::create(1, READONLY_PROGRAM)?;
        inner.set(0, SnapshotPod(snapshot), 0)?;
        freeze(inner.map().fd().as_fd())?;
        Ok(PreparedPermissions {
            owner_map_id: self.manifest.ids[0],
            based_on: self.current.generation,
            snapshot,
            inner,
        })
    }

    pub fn commit(&mut self, prepared: PreparedPermissions) -> Result<()> {
        ensure!(
            prepared.owner_map_id == self.manifest.ids[0],
            "permission transaction belongs to another owner"
        );
        ensure!(
            prepared.based_on == self.current.generation,
            "stale prepared permission transaction"
        );
        self.manifest.check_policy(&prepared.snapshot)?;
        ensure!(
            self.outer.get(&0, 0)?.get(&0, 0)?.0 == self.current,
            "policy changed outside this owner"
        );
        // This one kernel operation is the durable commit record. The frozen
        // snapshot and fixed catalog are sufficient to adopt either side of a
        // crash; no second userspace marker must be updated afterwards.
        self.outer.set(0, &prepared.inner, 0)?;
        self.current = prepared.snapshot;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Manifest {
        let mut catalog = Snapshot::empty(1);
        catalog.role_count = 2;
        for n in 0..2 {
            catalog.roles[n] = Role {
                incarnation: 1,
                cgroup_id: 40 + n as u64,
                executable_inode: 20,
                executable_device: 30,
                uid: 1000,
                ..Role::default()
            };
        }
        let mut inventory = Inventory {
            count: 2,
            ..Inventory::default()
        };
        inventory.devices[..2].copy_from_slice(&[42, 43]);
        Manifest {
            epoch: 1,
            ids: [1, 2, 3, 4, 5, 6, 7],
            catalog,
            inventory,
            exe_stat_dev: {
                let mut devs = [0u64; MAX_ROLES];
                devs[..2].copy_from_slice(&[58, 58]);
                devs
            },
        }
    }
    #[test]
    fn manifest_is_bounded_and_deduplicates_reference_names() {
        let manifest = sample();
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), BYTES);
        assert_eq!(Manifest::decode(&bytes).unwrap(), manifest);
        assert_eq!(manifest.names().len(), 4); // manifest, 1 exe, 2 cgroups
        for n in 0..bytes.len() {
            assert!(Manifest::decode(&bytes[..n]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Manifest::decode(&extra).is_err());
        let mut invalid = bytes;
        invalid[0] = 0;
        assert!(Manifest::decode(&invalid).is_err());
    }
    #[test]
    fn proc_text_parsers_are_strict() {
        assert_eq!(
            status_uid("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n").unwrap(),
            1000
        );
        assert!(status_uid("Uid:\t1000\t0\t0\t0\n").is_err()); // setuid-style mismatch
        assert!(status_uid("Name:\tx\n").is_err());
        assert!(status_uid("Uid:\t1000\n").is_err());
        assert_eq!(
            cgroup_v2_path("0::/system.slice/a.service\n").unwrap(),
            "/system.slice/a.service"
        );
        assert!(cgroup_v2_path("1:cpu:/x\n").is_err());
        assert!(cgroup_v2_path("0::/a/../b\n").is_err());
        assert!(cgroup_v2_path("0::/a\n0::/b\n").is_err());
    }

    #[test]
    fn catalog_accepts_only_permission_changes() {
        let manifest = sample();
        let mut active = manifest.catalog;
        active.generation = 2;
        active.roles[0].access_mask = 3;
        assert!(manifest.check_policy(&active).is_ok());
        active.roles[0].uid = 1001;
        assert!(manifest.check_policy(&active).is_err());
        active = manifest.catalog;
        active.generation = 2;
        active.roles[0].incarnation = 2;
        assert!(manifest.check_policy(&active).is_err());
        active = manifest.catalog;
        active.generation = 2;
        active.roles[0].access_mask = 4;
        assert!(manifest.check_policy(&active).is_err());
    }

    fn replaced(manifest: &Manifest, index: usize, generation: u64) -> (Manifest, Snapshot) {
        let mut catalog = manifest.catalog;
        catalog.generation = generation - 1;
        catalog.roles[index].cgroup_id = 900;
        catalog.roles[index].incarnation = generation;
        let next = Manifest {
            epoch: manifest.epoch + 1,
            catalog,
            ..manifest.clone()
        };
        let mut active = next.catalog;
        active.generation = generation;
        active.roles[index].access_mask = 3;
        (next, active)
    }

    #[test]
    fn reenrolled_catalog_is_valid_and_names_do_not_collide() {
        let old = sample();
        // Role 1 has its own cgroup (41) but shares executable with role 0.
        let (next, active) = replaced(&old, 1, 2);
        next.validate().unwrap();
        assert!(next.check_policy(&active).is_ok());
        assert!(old.check_policy(&active).is_err());
        assert_eq!(next.decode_roundtrip(), next);
        let added: Vec<_> = next.names().difference(&old.names()).cloned().collect();
        assert_eq!(
            added,
            vec!["cw-cg-1-2".to_owned(), "cw-manifest-2".to_owned()]
        );
    }

    #[test]
    fn adoption_selects_the_catalog_matching_the_active_snapshot() {
        let old = sample();
        let (next, committed) = replaced(&old, 1, 2);
        // Crash before commit: kernel still has the old registration.
        let mut before = old.catalog;
        before.generation = 1;
        let chosen = select_manifest(vec![old.clone(), next.clone()], &before).unwrap();
        assert_eq!(chosen.epoch, 1);
        // Crash after commit, before cleanup: both manifests are still stored.
        let chosen = select_manifest(vec![old.clone(), next.clone()], &committed).unwrap();
        assert_eq!(chosen.epoch, 2);
        // A snapshot matching neither catalog is never guessed.
        let mut foreign = committed;
        foreign.roles[0].uid = 4242;
        assert!(select_manifest(vec![old, next], &foreign).is_err());
    }

    #[test]
    fn only_re_enrollment_leftovers_are_garbage() {
        let old = sample();
        let (next, _) = replaced(&old, 1, 2);
        let mut held: BTreeSet<String> = next.names();
        // Interrupted cleanup left old references and the old manifest.
        held.extend(old.names().difference(&next.names()).cloned());
        let stale = stale_names(held.iter(), &next.names(), 2).unwrap();
        assert_eq!(
            stale,
            vec!["cw-cg-1-1".to_owned(), "cw-manifest-1".to_owned()]
        );
        // Foreign / implausible names are an error, not garbage.
        for bad in [
            "cw-dev-0",
            "evil",
            "cw-exe-99-1",
            "cw-exe-0-0",
            "cw-exe-0-9",
            "cw-manifest-x",
        ] {
            let mut set = next.names();
            set.insert(bad.to_owned());
            assert!(stale_names(set.iter(), &next.names(), 2).is_err(), "{bad}");
        }
    }

    impl Manifest {
        fn decode_roundtrip(&self) -> Manifest {
            Manifest::decode(&self.encode().unwrap()).unwrap()
        }
    }
}
