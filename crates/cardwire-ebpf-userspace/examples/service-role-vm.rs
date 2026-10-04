//! VM-only loader for nix/service-role-guard.bpf.c. Never used by cardwired.
//! Loads through the project's pinned Aya, including CO-RE relocation.
use anyhow::{Context, Result, bail, ensure};
use aya::{
    Btf, EbpfLoader, Pod, maps::{Array, CgroupArray, Map, MapData}, programs::{BtfTracePoint, Lsm, links::FdLink}
};
use std::{
    fs::{self, File}, os::{
        fd::AsRawFd, unix::fs::{FileTypeExt, MetadataExt}
    }, path::{Path, PathBuf}
};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RoleConfig {
    pub generation: u64,
    pub cgroup_id: u64,
    pub executable_inode: u64,
    pub executable_device: u32,
    pub uid: u32,
    pub protected_rdev: u32,
    pub active: u32,
}
// All fields are integer POD, fully initialized before an update.
unsafe impl Pod for RoleConfig {}

pub(crate) fn vm_guard() -> Result<()> {
    ensure!(std::env::consts::ARCH == "x86_64", "x86_64 VM only");
    ensure!(
        Path::new("/run/cardwire-lifecycle-vm-only").is_file(),
        "missing VM marker"
    );
    ensure!(
        fs::read_to_string("/sys/class/dmi/id/product_name")?.starts_with("Standard PC"),
        "QEMU only"
    );
    for card in ["card0", "card1"] {
        let device = PathBuf::from("/sys/class/drm").join(card).join("device");
        ensure!(
            fs::canonicalize(device.join("driver"))?
                == Path::new("/sys/bus/pci/drivers/virtio-pci"),
            "virtio PCI only"
        );
        ensure!(
            fs::read_to_string(device.join("vendor"))?.trim() == "0x1af4",
            "virtio vendor only"
        );
        ensure!(
            fs::read_to_string(device.join("device"))?.trim() == "0x1050",
            "virtio GPU only"
        );
    }
    Ok(())
}

pub(crate) fn kernel_dev(dev: u64) -> Result<u32> {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    ensure!(
        major < 4096 && minor < (1 << 20),
        "device outside kernel dev_t range"
    );
    Ok(((major << 20) | minor) as u32)
}

// If loading fails part way through, undo this loader's own pins only.
struct Pins {
    files: Vec<PathBuf>,
    keep: bool,
}
impl Drop for Pins {
    fn drop(&mut self) {
        if !self.keep {
            for path in self.files.iter().rev() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn main() -> Result<()> {
    vm_guard()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "--inspect-pinned" {
        let base = PathBuf::from(&args[1]);
        ensure!(
            base == Path::new("/sys/fs/bpf/cardwire_role_vm"),
            "fixture pins only"
        );
        let map = MapData::from_pin(base.join("VM_ROLE_CONFIG"))?;
        let array = Array::<_, RoleConfig>::try_from(Map::from_map_data(map)?)?;
        let rule = array.get(&0, 0)?;
        ensure!(
            rule.active == 1 && rule.generation == 1,
            "unexpected role generation"
        );
        println!("INSPECTED: pinned role generation {}", rule.generation);
        return Ok(());
    }
    if args.len() != 4 {
        bail!("VM loader: OBJECT CGROUP EXECUTABLE /sys/fs/bpf/cardwire_role_vm");
    }
    let object = PathBuf::from(&args[0]);
    let cg_path = fs::canonicalize(PathBuf::from(&args[1]))?;
    ensure!(
        cg_path == Path::new("/sys/fs/cgroup/cardwire-role-vm"),
        "fixture cgroup only"
    );
    let executable = File::open(PathBuf::from(&args[2]))?;
    let executable_meta = executable.metadata()?;
    ensure!(
        executable_meta.is_file(),
        "executable must be a regular file"
    );
    let cgroup = File::open(cg_path)?;
    let node = fs::metadata("/dev/dri/renderD129")?;
    ensure!(
        node.file_type().is_char_device(),
        "GPU character node required"
    );
    let base = PathBuf::from(&args[3]);
    ensure!(
        base == Path::new("/sys/fs/bpf/cardwire_role_vm"),
        "fixture pins only"
    );
    fs::create_dir(&base).context("pin directory must not already exist")?;
    let mut pins = Pins {
        files: Vec::new(),
        keep: false,
    };
    // Aya creates this kernel map but has no typed TASK_STORAGE wrapper.
    // Only the VM candidate uses this explicit opt-in; default daemon unchanged.
    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .load_file(object)?;
    CgroupArray::try_from(ebpf.map_mut("VM_ROLE_CGROUP").context("cgroup map")?)?.set(
        0,
        cgroup.as_raw_fd(),
        0,
    )?;
    Array::try_from(ebpf.map_mut("VM_ROLE_CONFIG").context("config map")?)?.set(
        0,
        RoleConfig {
            generation: 1,
            cgroup_id: cgroup.metadata()?.ino(),
            executable_inode: executable_meta.ino(),
            executable_device: kernel_dev(executable_meta.dev())?,
            uid: 0,
            protected_rdev: kernel_dev(node.rdev())?,
            active: 1,
        },
        0,
    )?;
    let btf = Btf::from_sys_fs()?;
    let exec: &mut BtfTracePoint = ebpf
        .program_mut("role_exec")
        .context("exec program")?
        .try_into()?;
    exec.load("sched_process_exec", &btf)?;
    let exec_id = exec.attach()?;
    let exec_link: FdLink = exec.take_link(exec_id)?.into();
    let open: &mut Lsm = ebpf
        .program_mut("role_open")
        .context("open program")?
        .try_into()?;
    open.load("file_open", &btf)?;
    let open_id = open.attach()?;
    let open_link: FdLink = open.take_link(open_id)?.into();
    for (name, link) in [("exec_link", exec_link), ("open_link", open_link)] {
        let path = base.join(name);
        link.pin(&path)?;
        pins.files.push(path);
    }
    for name in ["VM_ROLE_CONFIG", "VM_ROLE_CGROUP", "VM_ROLE_TASKS"] {
        let path = base.join(name);
        ebpf.map(name).context("pin map")?.pin(&path)?;
        pins.files.push(path);
    }
    pins.keep = true;
    println!("PINNED: exact executable/cgroup role; loader now exits");
    // The VM controller retains separate executable/cgroup references. A real
    // daemon handover must supply its own verified object-lifetime protocol.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn config_matches_c_and_python_abi_without_padding() {
        assert_eq!(size_of::<RoleConfig>(), 40);
        assert_eq!(align_of::<RoleConfig>(), 8);
        assert_eq!(offset_of!(RoleConfig, generation), 0);
        assert_eq!(offset_of!(RoleConfig, cgroup_id), 8);
        assert_eq!(offset_of!(RoleConfig, executable_inode), 16);
        assert_eq!(offset_of!(RoleConfig, executable_device), 24);
        assert_eq!(offset_of!(RoleConfig, uid), 28);
        assert_eq!(offset_of!(RoleConfig, protected_rdev), 32);
        assert_eq!(offset_of!(RoleConfig, active), 36);
    }

    #[test]
    fn linux_userspace_dev_converts_to_kernel_encoding() {
        assert_eq!(kernel_dev(0).unwrap(), 0);
        assert_eq!(kernel_dev(0xe281).unwrap(), (226 << 20) | 129);
        // Userspace encodes the high minor bits above bit 19.
        assert_eq!(kernel_dev(0xabcb_cdde).unwrap(), (0xbcd << 20) | 0xabcde);
        assert_eq!(kernel_dev(0xffff_ffff).unwrap(), u32::MAX);
    }

    #[test]
    fn out_of_range_device_numbers_are_not_truncated() {
        assert!(kernel_dev(0x0000_1000_0000_0000).is_err()); // major 4096
        assert!(kernel_dev(0x0000_0001_0000_0000).is_err()); // minor 1 << 20
    }
}
