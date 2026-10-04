//! Opt-in candidate backend; not invoked by cardwired or a desktop installer.
//! Publication is serialized by `&mut self` and swaps one immutable inner map.
//! All retired identities are conservatively retained until guard teardown.
//! Persistent-owner/FD-store adoption must be integrated before desktop use.
use anyhow::{Context, Result, anyhow, ensure};
use aya::{
    Btf, Ebpf, EbpfLoader, Pod, maps::{Array, ArrayOfMaps, IterableMap, Map, MapData}, programs::{BtfTracePoint, Lsm}
};
use cardwire_policy::service_roles::{Inventory, MAX_DEVICES, MAX_ROLES, Role, Snapshot};
use std::{
    fs::File, io, os::{
        fd::{AsFd, AsRawFd, BorrowedFd}, unix::fs::{FileTypeExt, MetadataExt}
    }, path::Path
};

pub mod persistent;

const READONLY_PROGRAM: u32 = 1 << 7;
const MAX_GENERATIONS: usize = 256; // Explicit bound; no unsafe identity eviction.

#[repr(transparent)]
#[derive(Clone, Copy)]
struct SnapshotPod(Snapshot);
// ABI tests cover each fully initialized integer field and absence of padding.
unsafe impl Pod for SnapshotPod {}
#[repr(transparent)]
#[derive(Clone, Copy)]
struct InventoryPod(Inventory);
unsafe impl Pod for InventoryPod {}

fn kernel_dev(dev: u64) -> Result<u32> {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    ensure!(
        major < 4096 && minor < (1 << 20),
        "unsupported device number"
    );
    Ok(((major << 20) | minor) as u32)
}

fn freeze(fd: BorrowedFd<'_>) -> Result<()> {
    let raw = fd.as_raw_fd() as u32;
    // BPF_MAP_FREEZE=22, bpf_attr.map_fd at offset 0. The kernel zero-fills the
    // remainder of this four-byte attribute. No buffer is read beyond its size.
    let result = unsafe { libc::syscall(libc::SYS_bpf, 22u32, &raw, size_of::<u32>()) };
    ensure!(
        result == 0,
        "cannot freeze policy map: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

/// Exact registration backed by held kernel object references, not names/PIDs.
pub struct Registration {
    rule: Role,
    executable: File,
    cgroup: File,
}

impl Registration {
    pub fn new(
        executable: File,
        cgroup: File,
        uid: u32,
        incarnation: u64,
        access_mask: u32,
    ) -> Result<Self> {
        let exe = executable.metadata()?;
        let cg = cgroup.metadata()?;
        ensure!(
            exe.is_file() && exe.mode() & 0o111 != 0 && cg.is_dir(),
            "invalid role object type"
        );
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(cgroup.as_raw_fd(), &mut stat) } == 0
                && stat.f_type == libc::CGROUP2_SUPER_MAGIC,
            "cgroup v2 object required"
        );
        let rule = Role {
            incarnation,
            cgroup_id: cg.ino(),
            executable_inode: exe.ino(),
            executable_device: kernel_dev(exe.dev())?,
            uid,
            access_mask,
            reserved: 0,
        };
        Ok(Self {
            rule,
            executable,
            cgroup,
        })
    }

    /// Permission change retains registration identity and original object FDs.
    pub fn with_access(&self, access_mask: u32) -> Result<Self> {
        Ok(Self {
            rule: Role {
                access_mask,
                ..self.rule
            },
            executable: self.executable.try_clone()?,
            cgroup: self.cgroup.try_clone()?,
        })
    }
}

struct Published {
    _map: Array<MapData, SnapshotPod>,
    _registrations: Vec<Registration>,
}

pub struct ServiceGuard {
    // Declared first so hooks detach before identity references drop. This is
    // a disposable unpinned owner; persistent lifecycle is a separate next gate.
    ebpf: Ebpf,
    exec_link: Option<aya::programs::tp_btf::BtfTracePointLinkId>,
    open_link: Option<aya::programs::lsm::LsmLinkId>,
    inventory: Inventory,
    _devices: Vec<File>,
    current: Option<Snapshot>,
    retained: Vec<Published>,
}

impl ServiceGuard {
    /// Attach to an explicit protected inventory, initially deny all its nodes.
    /// No device discovery, default-mode selection, or session mutation occurs.
    pub fn attach(object: &Path, devices: Vec<File>) -> Result<Self> {
        ensure!(
            !devices.is_empty() && devices.len() <= MAX_DEVICES,
            "invalid inventory size"
        );
        let mut inventory = Inventory {
            count: devices.len() as u32,
            ..Inventory::default()
        };
        for (slot, device) in inventory.devices.iter_mut().zip(&devices) {
            let meta = device.metadata()?;
            ensure!(
                meta.file_type().is_char_device(),
                "protected node must be a character device"
            );
            *slot = kernel_dev(meta.rdev())?;
        }
        inventory.validate().map_err(|e| anyhow!(e))?;
        let mut ebpf = EbpfLoader::new()
            .allow_unsupported_maps()
            .load_file(object)?;
        let map = ebpf
            .map_mut("CW_DEVICES_MAP")
            .context("missing inventory")?;
        let mut array = Array::<_, InventoryPod>::try_from(map)?;
        array.set(0, InventoryPod(inventory), 0)?;
        freeze(array.map().fd().as_fd())?;
        // Freeze even the deny-all initial template. All later inner maps are
        // fresh frozen instances, never writes to an active array value.
        match ebpf.map("CW_TEMPLATE").context("missing template")? {
            Map::Array(template) => freeze(template.fd().as_fd())?,
            _ => anyhow::bail!("invalid policy template"),
        }
        let btf = Btf::from_sys_fs()?;
        let exec: &mut BtfTracePoint = ebpf
            .program_mut("service_exec")
            .context("exec hook")?
            .try_into()?;
        exec.load("sched_process_exec", &btf)?;
        let exec_link = exec.attach()?;
        let open: &mut Lsm = ebpf
            .program_mut("service_open")
            .context("open hook")?
            .try_into()?;
        open.load("file_open", &btf)?;
        let open_link = open.attach()?;
        Ok(Self {
            ebpf,
            exec_link: Some(exec_link),
            open_link: Some(open_link),
            inventory,
            _devices: devices,
            current: None,
            retained: Vec::new(),
        })
    }

    /// Validate and prepare everything first, then atomically replace one pointer.
    /// Failed validation/allocation/freeze/update leaves the previous policy live.
    pub fn publish(&mut self, generation: u64, registrations: Vec<Registration>) -> Result<()> {
        ensure!(registrations.len() <= MAX_ROLES, "too many service roles");
        ensure!(
            self.retained.len() < MAX_GENERATIONS,
            "retained generation bound reached"
        );
        let mut snapshot = Snapshot::empty(generation);
        snapshot.role_count = registrations.len() as u32;
        for (dst, registration) in snapshot.roles.iter_mut().zip(&registrations) {
            *dst = registration.rule;
        }
        snapshot
            .validate(self.current.as_ref(), self.inventory.count as usize)
            .map_err(|e| anyhow!(e))?;
        let mut inner = Array::<MapData, SnapshotPod>::create(1, READONLY_PROGRAM)?;
        inner.set(0, SnapshotPod(snapshot), 0)?;
        freeze(inner.map().fd().as_fd())?;
        // Reserve before the commit point so post-publication book-keeping
        // cannot fail allocation and release the new role's object references.
        self.retained.try_reserve(1)?;
        let mut outer = ArrayOfMaps::<_, Array<MapData, SnapshotPod>>::try_from(
            self.ebpf
                .map_mut("CW_ACTIVE")
                .context("missing policy pointer")?,
        )?;
        outer.set(0, &inner, 0)?;
        self.retained.push(Published {
            _map: inner,
            _registrations: registrations,
        });
        self.current = Some(snapshot);
        Ok(())
    }

    pub fn current_generation(&self) -> Option<u64> {
        self.current.map(|s| s.generation)
    }

    /// Non-mutating freeze verification used by the VM regression. The attempted
    /// write is byte-identical and must still be rejected by the kernel.
    pub fn verify_current_frozen(&mut self) -> Result<()> {
        let current = self.current.context("no published policy")?;
        let outer = ArrayOfMaps::<_, Array<MapData, SnapshotPod>>::try_from(
            self.ebpf
                .map("CW_ACTIVE")
                .context("missing policy pointer")?,
        )?;
        let mut map = outer.get(&0, 0)?;
        ensure!(
            map.get(&0, 0)?.0 == current,
            "current policy differs from owner state"
        );
        let error = match map.set(0, SnapshotPod(current), 0) {
            Ok(()) => anyhow::bail!("published policy was not frozen"),
            Err(error) => error,
        };
        ensure!(
            matches!(error, aya::maps::MapError::SyscallError(ref e)
                        if e.io_error.raw_os_error() == Some(libc::EPERM)),
            "unexpected freeze error: {error}"
        );
        Ok(())
    }
}
