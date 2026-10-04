//! Isolated service-owner handover test, NOT the production Cardwire daemon.
//! No automatic repair/adoption of partial or unowned pinned state.
use anyhow::{Context, Result, ensure};
use aya::{
    maps::{Array, Map, MapData}, programs::{
        links::{FdLink, PinnedLink}, loaded_programs
    }
};
use cardwire_ebpf_userspace::fdstore::{Notifier, take_activation};
use std::{
    collections::BTreeMap, fs::{self, File, OpenOptions}, io::Write, os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd}, unix::fs::{FileExt, MetadataExt, OpenOptionsExt}
    }, path::Path, process::Command, thread
};

#[path = "service-role-vm.rs"]
#[allow(dead_code)]
mod fixture;

const UNIT: &str = "cardwire-role-owner-vm.service";
const BASE: &str = "/sys/fs/bpf/cardwire_role_vm";
const EXE: &str = "/tmp/cardwire-role-worker";
const CGROUP: &str = "/sys/fs/cgroup/cardwire-role-vm";
const NAMES: [&str; 3] = ["role-executable", "role-cgroup", "role-manifest"];
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

fn property(name: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .args(["show", UNIT, "-p", name, "--value"])
        .output()?;
    ensure!(output.status.success(), "cannot inspect owner unit");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn state(executable: &File, cgroup: &File) -> Result<String> {
    let base = Path::new(BASE);
    let names = ["VM_ROLE_CONFIG", "VM_ROLE_CGROUP", "VM_ROLE_TASKS"];
    let mut ids = Vec::new();
    let mut snapshot = String::from("CARDWIRE_ROLE_VM_OWNER_V1\n");
    for (name, ty, value_size, max_entries, flags) in [
        (names[0], 2, 40, 1, 0),
        (names[1], 8, 4, 1, 0),
        (names[2], 29, 8, 0, 1),
    ] {
        let map = MapData::from_pin(base.join(name))?;
        let info = map.info()?;
        ensure!(
            info.map_type()? as u32 == ty
                && info.key_size() == 4
                && info.value_size() == value_size
                && info.max_entries() == max_entries
                && info.map_flags() == flags,
            "wrong map ABI: {name}"
        );
        ids.push(info.id());
        snapshot += &format!("map {name} {}\n", info.id());
    }
    let map = MapData::from_pin(base.join(names[0]))?;
    let array = Array::<_, fixture::RoleConfig>::try_from(Map::from_map_data(map)?)?;
    let config = array.get(&0, 0)?;
    let exe = executable.metadata()?;
    let cg = cgroup.metadata()?;
    ensure!(exe.is_file() && cg.is_dir(), "wrong retained object type");
    ensure!(
        config
            == fixture::RoleConfig {
                generation: 1,
                cgroup_id: cg.ino(),
                executable_inode: exe.ino(),
                executable_device: fixture::kernel_dev(exe.dev())?,
                uid: 0,
                protected_rdev: fixture::kernel_dev(fs::metadata("/dev/dri/renderD129")?.rdev())?,
                active: 1,
            },
        "retained executable/cgroup do not match pinned policy"
    );
    snapshot += &format!("config {config:?}\ncgroup-device {}\n", cg.dev());
    ids.sort_unstable();
    for name in ["exec_link", "open_link"] {
        let link: FdLink = PinnedLink::from_pin(base.join(name))?.into();
        let info = link.info()?;
        ensure!(info.id() != 0 && info.program_id() != 0, "detached link");
        let program = loaded_programs()
            .filter_map(Result::ok)
            .find(|program| program.id() == info.program_id())
            .context("linked program information unavailable")?;
        let mut maps = program.map_ids()?.context("program map IDs unavailable")?;
        maps.sort_unstable();
        ensure!(maps == ids, "link references other policy maps");
        snapshot += &format!(
            "link {name} {} {} {:?}\n",
            info.id(),
            info.program_id(),
            info.link_type()?
        );
    }
    Ok(snapshot)
}

fn sealed_manifest(bytes: &[u8]) -> Result<File> {
    // SAFETY: constant NUL-terminated name, result owned only on syscall success.
    let fd = unsafe {
        libc::memfd_create(
            c"cardwire-role-manifest".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    ensure!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } == 0,
        "cannot seal owner manifest"
    );
    Ok(file)
}

fn retained(map: &mut BTreeMap<String, OwnedFd>, name: &str) -> Result<File> {
    Ok(File::from(map.remove(name).context("missing retained FD")?))
}

fn main() -> Result<()> {
    // SAFETY: first action at single-threaded startup; no Rust FD owners exist.
    let inherited = unsafe { take_activation(&NAMES)? };
    fixture::vm_guard()?;
    ensure!(
        property("MainPID")?.parse::<u32>()? == std::process::id(),
        "fixture owner unit only"
    );
    ensure!(
        property("FileDescriptorStorePreserve")? == "yes",
        "store must survive stop/failure"
    );
    ensure!(
        property("FileDescriptorStoreMax")?.parse::<u32>()? >= 3,
        "insufficient FD store"
    );
    let notify = Notifier::from_environment()?;
    let (executable, cgroup, manifest) = if let Some(mut inherited) = inherited {
        let executable = retained(&mut inherited, NAMES[0])?;
        let cgroup = retained(&mut inherited, NAMES[1])?;
        let manifest = retained(&mut inherited, NAMES[2])?;
        ensure!(
            unsafe { libc::fcntl(manifest.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "owner manifest must be immutable"
        );
        let expected = state(&executable, &cgroup)?;
        ensure!(
            manifest.metadata()?.len() == expected.len() as u64,
            "manifest length mismatch"
        );
        let mut bytes = vec![0u8; expected.len()];
        manifest.read_exact_at(&mut bytes, 0)?;
        ensure!(
            bytes == expected.as_bytes(),
            "pinned guard differs from retained manifest"
        );
        println!("ADOPTED: verified stored objects, map ABI/IDs and link/program identities");
        (executable, cgroup, manifest)
    } else {
        ensure!(
            !Path::new(BASE).exists(),
            "refusing pins without retained ownership state"
        );
        let executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
            .open(EXE)?;
        let cgroup = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(CGROUP)?;
        // Retain object identity BEFORE installing enforcement. A crash after
        // this point leaves explicit partial state; a restart must refuse it.
        notify.store(NAMES[0], executable.as_fd())?;
        notify.store(NAMES[1], cgroup.as_fd())?;
        notify.barrier()?;
        ensure!(
            property("NFileDescriptorStore")? == "2",
            "identity FDs were not stored"
        );
        let loader = std::env::var("CARDWIRE_VM_ELF_LOADER")?;
        let status = Command::new(loader)
            .args([
                "/tmp/cardwire-role-loader",
                "/tmp/cardwire-role-guard.bpf.o",
                CGROUP,
                EXE,
                BASE,
            ])
            .env_remove("NOTIFY_SOCKET")
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_FDNAMES")
            .status()?;
        ensure!(
            status.success(),
            "guard installation failed; retaining partial ownership"
        );
        let manifest = sealed_manifest(state(&executable, &cgroup)?.as_bytes())?;
        notify.store(NAMES[2], manifest.as_fd())?;
        notify.barrier()?;
        println!("CREATED: registered guard with systemd-owned object references");
        (executable, cgroup, manifest)
    };
    ensure!(
        property("NFileDescriptorStore")? == "3",
        "incomplete retained state"
    );
    notify.ready()?;
    // These remain alive as well as systemd's copies. No unpin-on-exit: an
    // explicit future profile deactivation transaction must own that operation.
    let _held = (executable, cgroup, manifest);
    loop {
        thread::park();
    }
}
