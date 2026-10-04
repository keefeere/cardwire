use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes, bpf_probe_write_user, generated::bpf_get_current_task
};
use cardwire_policy::{FileLayout, ProcessPolicy};

use crate::{
    CardwiredSetting, DAEMON_INDEX, HYBRID, INTEGRATED, MANUAL, MODE_INDEX, SMART, maps::{
        CW_ALLOWED_COMM, CW_BLOCKED_INO, CW_DAEMON_PID, CW_EXP_BLK_INO, CW_FILE_LAYOUT, CW_MODE, CW_PID_POLICY, CW_REPORT_EVENTS, CW_SETTINGS, CW_TASK_LAYOUT, InodeKey, ReportEvent
    }
};

use crate::vmlinux::linux_dirent64;

/// Outcome of building a block-map key from a dentry or an inode
pub enum KeyBuild {
    /// A usable key
    Key(InodeKey),
    /// No name to key on: null dentry/inode, or an anonymous inode (epoll fds,
    /// eventfds, dma-bufs). Expected while processes run, callers should skip
    /// silently
    Unnamed,
    /// Kernel memory could not be read. Unexpected, callers should log it
    ProbeFailed,
}

#[inline(always)]
fn file_layout() -> Option<FileLayout> {
    let layout = *CW_FILE_LAYOUT.get(0)?;
    if layout.is_valid() {
        Some(layout)
    } else {
        None
    }
}

/// Build the key using validated runtime offsets, never a generated kernel
/// struct dereference. All pointer targets are read through safe probe helpers.
#[inline(always)]
unsafe fn dentry_key(d: *const u8, layout: FileLayout) -> KeyBuild {
    if d.is_null() {
        return KeyBuild::Unnamed;
    }

    let inode_ptr: *const u8 =
        match unsafe { bpf_probe_read_kernel(d.wrapping_add(layout.dentry_inode as usize).cast()) }
        {
            Ok(inode_ptr) => inode_ptr,
            Err(_) => return KeyBuild::ProbeFailed,
        };
    if inode_ptr.is_null() {
        return KeyBuild::Unnamed;
    }

    let name_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel(d.wrapping_add(layout.dentry_name as usize).cast())
    } {
        Ok(name_ptr) => name_ptr,
        Err(_) => return KeyBuild::ProbeFailed,
    };
    if name_ptr.is_null() {
        return KeyBuild::Unnamed;
    }

    let ino: u64 = match unsafe {
        bpf_probe_read_kernel(inode_ptr.wrapping_add(layout.inode_number as usize).cast())
    } {
        Ok(ino) => ino,
        Err(_) => return KeyBuild::ProbeFailed,
    };

    let mut name = [0u8; 64];
    if unsafe { bpf_probe_read_kernel_str_bytes(name_ptr, &mut name) }.is_err() {
        return KeyBuild::ProbeFailed;
    }

    KeyBuild::Key(InodeKey { name, ino })
}

/// Build the block-map key for an inode, keying on the entry's name and inode
#[inline(always)]
pub unsafe fn inode_key(inode_ptr: *const u8) -> KeyBuild {
    if inode_ptr.is_null() {
        return KeyBuild::Unnamed;
    }

    let Some(layout) = file_layout() else {
        return KeyBuild::ProbeFailed;
    };
    let alias: *const u8 = match unsafe {
        bpf_probe_read_kernel(inode_ptr.wrapping_add(layout.inode_alias as usize).cast())
    } {
        Ok(alias) => alias,
        Err(_) => return KeyBuild::ProbeFailed,
    };
    if alias.is_null() {
        // Anonymous inode (epoll, eventfd, dma-buf, ...): no name by design
        return KeyBuild::Unnamed;
    }

    let d = alias.wrapping_sub(layout.dentry_alias as usize);

    unsafe { dentry_key(d, layout) }
}

#[inline(always)]
pub unsafe fn file_key(file: *const u8) -> KeyBuild {
    if file.is_null() {
        return KeyBuild::Unnamed;
    }
    let Some(layout) = file_layout() else {
        return KeyBuild::ProbeFailed;
    };
    let d: *const u8 = match unsafe {
        bpf_probe_read_kernel(file.wrapping_add(layout.file_dentry as usize).cast())
    } {
        Ok(d) => d,
        Err(_) => return KeyBuild::ProbeFailed,
    };
    unsafe { dentry_key(d, layout) }
}

#[inline(always)]
pub unsafe fn path_key(path: *const u8) -> KeyBuild {
    if path.is_null() {
        return KeyBuild::Unnamed;
    }
    let Some(layout) = file_layout() else {
        return KeyBuild::ProbeFailed;
    };
    let d: *const u8 = match unsafe {
        bpf_probe_read_kernel(path.wrapping_add(layout.path_dentry as usize).cast())
    } {
        Ok(d) => d,
        Err(_) => return KeyBuild::ProbeFailed,
    };
    unsafe { dentry_key(d, layout) }
}

/// Verify if the file is inside CW_BLOCKED_INO or not
#[inline(always)]
pub unsafe fn is_inode_blocked(key: InodeKey) -> bool {
    let mut tracked: bool = false;
    let mut ino_gpu_id: u32 = 0;
    let mut blocked: bool = false;

    'inode_check: {
        // Check if the file is in the blocked list
        if let Some(v) = unsafe { CW_BLOCKED_INO.get(key) } {
            tracked = true;
            ino_gpu_id = v.gpu_id;
            blocked = v.blocked == 1;
            break 'inode_check;
        }
        // We didn't match any inode, try with nvidia inodes
        if unsafe { is_nvidia_setting_enabled() }
            && let Some(v) = unsafe { CW_EXP_BLK_INO.get(key) }
        {
            tracked = true;
            ino_gpu_id = *v;
            // Nvidia experimental inodes are considered globally blocked for now if in map
            blocked = true;
            break 'inode_check;
        }
    }

    'end: {
        if !tracked {
            // exit and return success
            break 'end;
        }

        // Get the current mode used
        let mode = match CW_MODE.get(MODE_INDEX) {
            Some(mode) => mode,
            // If we can't get the mode, just exit the block and return success
            None => break 'end,
        };

        // If everything ok, read the pid
        let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;

        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

        if *mode == INTEGRATED && blocked {
            // if integrated, block and report
            report_event(pid, ino_gpu_id, comm);
            return true;
        }

        if *mode == MANUAL {
            let ppid = get_task_ppid().unwrap_or(u32::MAX);

            let own = unsafe { CW_PID_POLICY.get(pid).copied() }.unwrap_or(ProcessPolicy::NONE);
            let parent = unsafe { CW_PID_POLICY.get(ppid).copied() }.unwrap_or(ProcessPolicy::NONE);
            let policy = ProcessPolicy::manual_encoded(own, parent);
            if policy <= u32::MAX as u64 {
                // If forced GPU ID matches the inode's GPU ID, allow access
                match policy == ino_gpu_id as u64 {
                    true => break 'end,
                    false => {
                        report_event(pid, ino_gpu_id, comm);
                        return true;
                    }
                }
            }

            // Normal process behavior: block access if its blocked
            if blocked {
                report_event(pid, ino_gpu_id, comm);
                return true;
            } else {
                break 'end;
            }
        }

        // 0 = iGPU
        // 1 = dGPU
        if *mode == SMART {
            let ppid = get_task_ppid().unwrap_or(u32::MAX);

            // Copy each complete value once: concurrent replacement cannot
            // make this lookup observe both an Allow and a Force for one PID.
            let own = unsafe { CW_PID_POLICY.get(pid).copied() }.unwrap_or(ProcessPolicy::NONE);
            let parent = unsafe { CW_PID_POLICY.get(ppid).copied() }.unwrap_or(ProcessPolicy::NONE);
            let policy = ProcessPolicy::smart_encoded(own, parent);
            if policy == ProcessPolicy::Allowed.encode() {
                break 'end;
            }
            if policy <= u32::MAX as u64 {
                // We match the ino_gpu_id with the pid_gpu_id
                // If they match, that means the ino is owned by the said GPU id, and we want to
                // force the process to use said GPU id
                match policy == ino_gpu_id as u64 {
                    // The process should be allowed to see the inode
                    true => break 'end,
                    // Process should only be allowed to see the said GPU id
                    false => {
                        // Report the event to the daemon
                        report_event(pid, ino_gpu_id, comm);
                        return true;
                    }
                }
            }

            // Check if inode gpu id matches 0, the iGPU.
            // iGPU should always be 0
            if ino_gpu_id == 0 {
                // allow the iGPU
                break 'end;
            }

            // Report the event to the daemon
            report_event(pid, ino_gpu_id, comm);

            // End of smart mode check, block if it didnt get allowed earlier
            return true;
        }
    }

    false
}

#[inline(always)]
fn report_event(pid: u32, gpu_id: u32, comm: [u8; 16]) {
    if let Some(mut ring_buf) = CW_REPORT_EVENTS.reserve(0) {
        let event: ReportEvent = ReportEvent { pid, gpu_id, comm };
        // write to the map
        ring_buf.write(event);
        // submit
        ring_buf.submit(0);
    };
}

#[inline(always)]
fn get_task_ppid() -> Option<u32> {
    let layout = *CW_TASK_LAYOUT.get(0)?;
    if !layout.is_valid() {
        return None;
    }
    let task = unsafe { bpf_get_current_task() as *const u8 };
    if task.is_null() {
        return None;
    }

    // Sanity-check the runtime layout against an independent kernel helper.
    // Never dereference the generated, kernel-config-specific task_struct.
    let own_tgid: i32 =
        unsafe { bpf_probe_read_kernel(task.wrapping_add(layout.tgid as usize).cast()).ok()? };
    if own_tgid <= 0 || own_tgid as u32 != (bpf_get_current_pid_tgid() >> 32) as u32 {
        return None;
    }
    let real_parent: *const u8 = unsafe {
        bpf_probe_read_kernel(task.wrapping_add(layout.real_parent as usize).cast()).ok()?
    };
    if real_parent.is_null() {
        return None;
    }

    let ppid: i32 = unsafe {
        bpf_probe_read_kernel(real_parent.wrapping_add(layout.tgid as usize).cast()).ok()?
    };
    if ppid > 0 { Some(ppid as u32) } else { None }
}

/// Verify if the proc is whitelisted, returns false if not
#[inline(always)]
pub fn is_comm_whitelisted() -> bool {
    if let Ok(comm) = bpf_get_current_comm()
        && unsafe { CW_ALLOWED_COMM.get(comm).is_some() }
    {
        return true;
    }
    false
}

/// Verify if the proc is cardwired, returns None if the map fails
#[inline(always)]
pub fn is_cardwired() -> Option<bool> {
    let proc_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    CW_DAEMON_PID.get(DAEMON_INDEX).map(|pid| proc_pid == *pid)
}

/// Verify if the current device mode is hybrid, returns None if the map fails
#[inline(always)]
pub unsafe fn is_hybrid() -> Option<bool> {
    CW_MODE.get(MODE_INDEX).map(|mode| *mode == HYBRID)
}

/// Verify if the current device mode is smart, returns None if the map fails
#[inline(always)]
pub unsafe fn is_smart() -> Option<bool> {
    CW_MODE.get(MODE_INDEX).map(|mode| *mode == SMART)
}

/// Verify if the current device mode is manual, returns None if the map fails
#[inline(always)]
pub unsafe fn is_manual() -> Option<bool> {
    CW_MODE.get(MODE_INDEX).map(|mode| *mode == MANUAL)
}

#[inline(always)]
pub unsafe fn is_nvidia_setting_enabled() -> bool {
    match unsafe { CW_SETTINGS.get(CardwiredSetting::EXP_NVIDIA) } {
        Some(setting) => *setting,
        None => false,
    }
}

/// The scan ran to completion (or hit a non-fatal stop condition)
pub const SCAN_OK: u32 = 0;
/// A dirent header could not be read, the syscall result must not be trusted
pub const SCAN_READ_FAILED: u32 = 1;
/// A hidden entry could not be merged into the previous one, the scan stopped
pub const SCAN_WRITE_FAILED: u32 = 2;

/// Largest getdents64 return value the hook scans
const GETDENTS_BUF_MAX: u64 = 32768;

/// Iteration bound for the dirent scan
///
/// One buffer holds at most GETDENTS_BUF_MAX / sizeof(linux_dirent64)
/// header-sized records, plus one iteration to observe the bounds-check miss
/// that ends the scan, so the bound can never truncate a buffer silently
pub const MAX_DIRENTS: u32 =
    (GETDENTS_BUF_MAX / core::mem::size_of::<linux_dirent64>() as u64) as u32 + 1;

/// State shared between the getdents64 exit hook and the bpf_loop callback
#[repr(C)]
pub struct ScanCtx {
    /// Cursor: address of the dirent currently being inspected
    pub dirent_ptr: u64,
    /// First address past the getdents64 buffer (base + retval)
    pub end: u64,
    /// Address of the last visible entry before the cursor, 0 if none yet
    pub prev_ptr: u64,
    /// d_reclen of prev_ptr, updated when hidden entries are merged into it
    pub prev_reclen: u16,
    /// One of the SCAN_* constants
    pub status: u32,
    /// Kernel return code of the failed write, valid when status is
    /// SCAN_WRITE_FAILED
    pub errno: i32,
}

/// One iteration of the getdents64 buffer scan
/// Returns 0 to continue the scan, 1 to stop it
pub unsafe extern "C" fn scan_dirent(_index: u32, scan: *mut ScanCtx) -> u64 {
    let scan = unsafe { &mut *scan };

    // Check before reading
    if scan
        .dirent_ptr
        .wrapping_add(core::mem::size_of::<linux_dirent64>() as u64)
        > scan.end
    {
        return 1;
    }

    let dirent = match unsafe { bpf_probe_read_user(scan.dirent_ptr as *const linux_dirent64) } {
        Ok(dirent) => dirent,
        Err(_) => return 1,
    };

    let reclen = dirent.d_reclen;

    // Malformed: a record shorter than its own header can't be valid, and
    // advancing by it would also break the MAX_DIRENTS bound
    if (reclen as usize) < core::mem::size_of::<linux_dirent64>() || reclen > 512 {
        return 1;
    }

    let name_pos = scan
        .dirent_ptr
        .wrapping_add(core::mem::offset_of!(linux_dirent64, d_name) as u64)
        as *const u8;
    let mut name = [0u8; 64];
    if unsafe { bpf_probe_read_user_str_bytes(name_pos, &mut name) }.is_err() {
        scan.status = SCAN_READ_FAILED;
        return 1;
    }

    let blocked = unsafe {
        is_inode_blocked(InodeKey {
            name,
            ino: dirent.d_ino,
        })
    };
    if blocked {
        // We can't hide the first entry
        if scan.prev_ptr != 0 {
            let new_reclen = scan.prev_reclen.wrapping_add(reclen);

            let reclen_ptr = scan
                .prev_ptr
                .wrapping_add(core::mem::offset_of!(linux_dirent64, d_reclen) as u64)
                as *mut u16;
            if let Err(err) = unsafe { bpf_probe_write_user(reclen_ptr, &new_reclen) } {
                scan.status = SCAN_WRITE_FAILED;
                scan.errno = err;
                return 1;
            }

            scan.prev_reclen = new_reclen;
        }
    } else {
        scan.prev_ptr = scan.dirent_ptr;
        scan.prev_reclen = reclen;
    }

    scan.dirent_ptr = scan.dirent_ptr.wrapping_add(reclen as u64);

    0
}
