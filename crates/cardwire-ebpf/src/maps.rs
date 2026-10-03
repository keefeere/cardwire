use aya_ebpf::{
    btf_maps::RingBuf, macros::{btf_map, map}, maps::{Array, HashMap}
};

use crate::models::{InodeKey, InodeState};

/*
    A single entry array used to store cardwired pid
*/
#[map]
pub static CW_DAEMON_PID: Array<u32> = Array::<u32>::with_max_entries(1, 0);

/*
    A single entry array used to store the current cardwired mode
    List of possible values:
    0 - Integrated
    1 - Hybrid
    2 - Manual
    3 - Smart
*/
#[map]
pub static CW_MODE: Array<u8> = Array::<u8>::with_max_entries(1, 0);

/*
    Hashmap containing cardwired exp_nvidia setting
    0 - Exp_nvidia_setting
*/
#[map]
pub static CW_SETTINGS: HashMap<u8, bool> = HashMap::<u8, bool>::with_max_entries(255, 0);

/*
   Map used to store blocked inodes sent from userspace
   Key = (superblock device id, inode)
   Value = associated GPU and block state
*/
#[map]
pub static CW_BLOCKED_INO: HashMap<InodeKey, InodeState> =
    HashMap::<InodeKey, InodeState>::with_max_entries(16384, 0);

/*
   Map used to store blocked inodes from exp_nvidia
   Key = (superblock device id, inode)
   Value = 0, not used because exp files can be shared by multiple devices (nvidiactl)
*/
#[map]
pub static CW_EXP_BLK_INO: HashMap<InodeKey, u32> =
    HashMap::<InodeKey, u32>::with_max_entries(4096, 0);

// One atomic value per PID, encoded by cardwire-policy. Keep the combined
// capacity of the former 16K Allow and 16K Force maps.
#[map]
pub static CW_PID_POLICY: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32768, 0);

/*
    Map used to store a list of whitelist comm, some comm needs to have access to the GPUs, preventing that access can cause crash or instability
    Eg. udev on pci rescan, pacman on nvidia driver update
*/
#[map]
pub static CW_ALLOWED_COMM: HashMap<[u8; 16], u8> =
    HashMap::<[u8; 16], u8>::with_max_entries(1024, 0);

#[map]
pub static CW_DIRENT: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[repr(C, align(8))]
#[allow(dead_code)]
pub struct ExecEvent {
    pub pid: u32,
    pub mode: u8,
    pub _padding: [u8; 3],
}

#[btf_map]
pub static CW_EXEC_EVENTS: RingBuf<ExecEvent, 262144> = RingBuf::new();

#[repr(C)]
#[repr(align(8))]
#[allow(dead_code)]
pub struct ReportEvent {
    pub pid: u32,
    pub gpu_id: u32,
    pub comm: [u8; 16],
}

#[btf_map]
pub static CW_REPORT_EVENTS: RingBuf<ReportEvent, 262144> = RingBuf::new();
