//! Disposable VM service fixture for the reusable persistent guard backend.
//! Never a desktop daemon; production ownership belongs inside cardwired.
use anyhow::{Context, Result, bail, ensure};
use cardwire_ebpf_userspace::{
    fdstore::{Notifier, take_namespaced_activation}, service_guard::{
        Registration, persistent::{PersistentGuard, PreparedPermissions, SystemdOwner}
    }
};
use std::{
    fs::{self, OpenOptions, Permissions}, io::{BufRead, BufReader, Read, Write}, os::{
        fd::AsRawFd, unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt}, net::UnixListener
        }
    }, path::Path, time::Duration
};

#[path = "service-role-vm.rs"]
#[allow(dead_code)]
mod fixture;
const UNIT: &str = "cardwire-snapshot-owner-vm.service";
const BASE: &str = "/sys/fs/bpf/cardwire_snapshots_vm";
const SOCKET: &str = "/run/cardwire-snapshot-owner-vm.sock";

fn registration(group: &str) -> Result<Registration> {
    let exe = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open("/tmp/cardwire-role-worker")?;
    let cg = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(group)?;
    Registration::new(exe, cg, 0, 1, 0)
}

fn main() -> Result<()> {
    // SAFETY: first action, before opening/wrapping any other startup FDs.
    let inherited = unsafe { take_namespaced_activation("cw-")? };
    fixture::vm_guard()?;
    let notify = Notifier::from_environment()?;
    let owner = SystemdOwner::new(UNIT, &notify)?;
    let mut guard = if let Some(held) = inherited {
        let devices = ["/dev/dri/renderD129", "/dev/dri/card1"]
            .iter()
            .map(|path| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                    .open(path)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let guard = PersistentGuard::adopt(held, devices, Path::new(BASE), &owner)?;
        println!("ADOPTED generation {}", guard.current_generation());
        guard
    } else {
        let devices = ["/dev/dri/renderD129", "/dev/dri/card1"]
            .iter()
            .map(|path| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                    .open(path)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let roles = [
            "/sys/fs/cgroup/cardwire-persistent-a",
            "/sys/fs/cgroup/cardwire-persistent-b",
        ]
        .iter()
        .map(|path| registration(path))
        .collect::<Result<Vec<_>>>()?;
        let guard = PersistentGuard::create(
            Path::new("/tmp/cardwire-service-guard.bpf.o"),
            devices,
            roles,
            Path::new(BASE),
            &owner,
        )?;
        println!("CREATED generation {}", guard.current_generation());
        guard
    };
    if let Ok(meta) = fs::symlink_metadata(SOCKET) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
            "foreign fixture control path"
        );
        fs::remove_file(SOCKET)?;
    }
    // Only VM root may send fixture commands; none is exposed on the host.
    unsafe {
        libc::umask(0o077);
    }
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, Permissions::from_mode(0o600))?;
    notify.ready()?;
    let mut prepared: Option<PreparedPermissions> = None;
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut length,
                )
            } == 0
                && peer.uid == 0,
            "VM root only"
        );
        let mut line = String::new();
        BufReader::new(stream.try_clone()?)
            .take(256)
            .read_line(&mut line)?;
        let outcome = (|| -> Result<()> {
            ensure!(
                line.ends_with('\n') && line.len() < 256,
                "invalid fixture request"
            );
            let words: Vec<_> = line.split_whitespace().collect();
            if words == ["status"] {
                return Ok(());
            }
            if words == ["commit"] {
                return guard.commit(prepared.take().context("no prepared transaction")?);
            }
            ensure!(words.len() == 3, "expected command and two masks");
            let masks = [words[1].parse()?, words[2].parse()?];
            let replacement = guard.prepare_permissions(&masks)?;
            match words[0] {
                "prepare" => prepared = Some(replacement),
                "apply" => guard.commit(replacement)?,
                "crash-before" => {
                    unsafe {
                        libc::raise(libc::SIGKILL);
                    }
                    bail!("SIGKILL returned");
                }
                "crash-after" => {
                    guard.commit(replacement)?;
                    unsafe {
                        libc::raise(libc::SIGKILL);
                    }
                    bail!("SIGKILL returned");
                }
                _ => bail!("unknown fixture command"),
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => writeln!(stream, "OK {}", guard.current_generation())?,
            Err(error) => writeln!(stream, "REJECTED {} {error}", guard.current_generation())?,
        }
    }
    Ok(())
}
