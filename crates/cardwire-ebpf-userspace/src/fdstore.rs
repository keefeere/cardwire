//! Explicit systemd FD-store transport for a future persistent policy owner.
//!
//! Nothing here attaches BPF, changes policy or runs automatically in cardwired.
//! A barrier proves message processing, NOT successful storage. The caller must
//! verify the configured store and validate every inherited object's identity.
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet}, env, io::{self, Read}, os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd}, linux::net::SocketAddrExt, unix::{
            ffi::OsStrExt, net::{SocketAddr, UnixDatagram, UnixStream}
        }
    }, sync::atomic::{AtomicBool, Ordering}, time::Duration
};

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn activation_names(
    pid: Option<&str>,
    count: Option<&str>,
    names: Option<&str>,
    current_pid: u32,
    expected: &[&str],
) -> Result<Option<Vec<String>>> {
    if pid.is_none() && count.is_none() && names.is_none() {
        return Ok(None);
    }
    ensure!(
        pid.context("missing LISTEN_PID")?.parse::<u32>()? == current_pid,
        "FD activation belongs to another PID"
    );
    let count = count.context("missing LISTEN_FDS")?.parse::<usize>()?;
    ensure!(
        count > 0 && count <= 64 && count == expected.len(),
        "unexpected FD count"
    );
    let names: Vec<_> = names
        .context("missing LISTEN_FDNAMES")?
        .split(':')
        .map(str::to_owned)
        .collect();
    ensure!(
        names.len() == count && names.iter().all(|n| valid_name(n)),
        "invalid FD names"
    );
    let actual: BTreeSet<_> = names.iter().map(String::as_str).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    ensure!(
        actual.len() == count && actual == expected,
        "missing, duplicate or unknown FD name"
    );
    Ok(Some(names))
}

/// Take the dedicated unit's named activation descriptors exactly once.
///
/// # Safety
/// Call during single-threaded process startup, before wrapping/opening any
/// activation descriptors elsewhere. FDs 3..3+LISTEN_FDS must be unowned by Rust
/// and owned exclusively by this activation protocol. Environment is supplied
/// by the trusted service manager. Failure must abort owner startup.
pub unsafe fn take_activation(expected: &[&str]) -> Result<Option<BTreeMap<String, OwnedFd>>> {
    // SAFETY: forwarded startup-only ownership contract.
    unsafe { take_checked_activation(Some(expected), None) }
}

/// Take a bounded named set whose exact inventory is validated by a sealed
/// manifest afterwards. Unknown/duplicate/malformed names still fail startup.
///
/// # Safety
/// Same startup-only FD ownership contract as [`take_activation`]. The caller
/// must validate the COMPLETE set against its manifest before using any object.
pub unsafe fn take_namespaced_activation(
    prefix: &str,
) -> Result<Option<BTreeMap<String, OwnedFd>>> {
    ensure!(valid_name(prefix), "invalid activation namespace");
    // SAFETY: forwarded startup-only ownership contract.
    unsafe { take_checked_activation(None, Some(prefix)) }
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

unsafe fn take_checked_activation(
    expected: Option<&[&str]>,
    prefix: Option<&str>,
) -> Result<Option<BTreeMap<String, OwnedFd>>> {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    ensure!(
        !TAKEN.swap(true, Ordering::SeqCst),
        "activation already consumed"
    );
    let pid = optional_env("LISTEN_PID")?;
    let count = optional_env("LISTEN_FDS")?;
    let names = optional_env("LISTEN_FDNAMES")?;
    let dynamic: Vec<_> = names.as_deref().unwrap_or("").split(':').collect();
    if let (Some(prefix), Some(_)) = (prefix, names.as_ref()) {
        ensure!(
            dynamic.iter().all(|name| name.starts_with(prefix)),
            "unknown activation namespace"
        );
    }
    let Some(names) = activation_names(
        pid.as_deref(),
        count.as_deref(),
        names.as_deref(),
        std::process::id(),
        expected.unwrap_or(&dynamic),
    )?
    else {
        return Ok(None);
    };
    let mut result = BTreeMap::new();
    for (index, name) in names.into_iter().enumerate() {
        // SAFETY: the caller guarantees exclusive ownership of this activation range.
        let fd = unsafe { OwnedFd::from_raw_fd(3 + index as i32) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        ensure!(
            flags >= 0,
            "invalid activation FD: {}",
            io::Error::last_os_error()
        );
        ensure!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
            "cannot set activation CLOEXEC: {}",
            io::Error::last_os_error()
        );
        result.insert(name, fd);
    }
    Ok(Some(result))
}

pub struct Notifier(UnixDatagram);

impl Notifier {
    pub fn from_environment() -> Result<Self> {
        let path = env::var_os("NOTIFY_SOCKET").context("NOTIFY_SOCKET required")?;
        let bytes = path.as_os_str().as_bytes();
        let address = if let Some(name) = bytes.strip_prefix(b"@") {
            SocketAddr::from_abstract_name(name)?
        } else {
            ensure!(
                bytes.starts_with(b"/"),
                "absolute or abstract notify socket required"
            );
            SocketAddr::from_pathname(path)?
        };
        let socket = UnixDatagram::unbound()?;
        socket.connect_addr(&address)?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self(socket))
    }

    fn send_fd(&self, message: &str, fd: BorrowedFd<'_>) -> Result<()> {
        // Aligned, initialized storage; one SCM_RIGHTS descriptor per datagram.
        let mut control = [0usize; 8];
        let size = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
        ensure!(size <= size_of_val(&control), "ancillary buffer too small");
        let mut iov = libc::iovec {
            iov_base: message.as_ptr().cast_mut().cast(),
            iov_len: message.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size;
        // SAFETY: all buffers are aligned, sized and live for the sendmsg call;
        // SCM_RIGHTS duplicates a borrowed descriptor without taking ownership.
        let sent = unsafe {
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
            std::ptr::write(
                libc::CMSG_DATA(header).cast::<libc::c_int>(),
                fd.as_raw_fd(),
            );
            libc::sendmsg(self.0.as_raw_fd(), &msg, libc::MSG_NOSIGNAL)
        };
        ensure!(
            sent == message.len() as isize,
            "notify sendmsg failed: {}",
            io::Error::last_os_error()
        );
        Ok(())
    }

    /// Send one named object reference. The caller keeps its own descriptor.
    /// Polling is disabled: removing a cgroup must not silently drop its identity.
    pub fn store(&self, name: &str, fd: BorrowedFd<'_>) -> Result<()> {
        ensure!(valid_name(name), "invalid stored FD name");
        self.send_fd(&format!("FDSTORE=1\nFDPOLL=0\nFDNAME={name}"), fd)
    }

    /// Drop one stored descriptor by name (idempotent for absent names).
    pub fn remove(&self, name: &str) -> Result<()> {
        ensure!(valid_name(name), "invalid stored FD name");
        let message = format!("FDSTOREREMOVE=1\nFDNAME={name}");
        ensure!(
            self.0.send(message.as_bytes())? == message.len(),
            "short FD store removal message"
        );
        Ok(())
    }

    /// Wait for systemd to process prior messages; not a storage success receipt.
    pub fn barrier(&self) -> Result<()> {
        let (mut reader, writer) = UnixStream::pair()?;
        reader.set_read_timeout(Some(Duration::from_secs(5)))?;
        self.send_fd("BARRIER=1", writer.as_fd())?;
        drop(writer);
        let mut byte = [0u8];
        ensure!(reader.read(&mut byte)? == 0, "invalid barrier reply");
        Ok(())
    }

    /// Publish readiness only after the caller verifies stored state/identities.
    pub fn ready(&self) -> Result<()> {
        ensure!(self.0.send(b"READY=1")? == 7, "short readiness message");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_activation_is_distinct_from_malformed_activation() {
        assert!(
            activation_names(None, None, None, 42, &["exe"])
                .unwrap()
                .is_none()
        );
        for args in [
            (Some("42"), None, None),
            (None, Some("1"), Some("exe")),
            (Some("42"), Some("1"), None),
            (Some("41"), Some("1"), Some("exe")),
            (Some("42"), Some("0"), Some("")),
            (Some("42"), Some("65"), Some("exe")),
        ] {
            assert!(activation_names(args.0, args.1, args.2, 42, &["exe"]).is_err());
        }
    }

    #[test]
    fn names_are_complete_unique_and_order_independent() {
        assert_eq!(
            activation_names(Some("42"), Some("2"), Some("cg:exe"), 42, &["exe", "cg"])
                .unwrap()
                .unwrap(),
            vec!["cg", "exe"]
        );
        for names in ["exe:exe", "exe:other", "exe", "exe:cg:", "exe:cg\nREADY=1"] {
            assert!(
                activation_names(Some("42"), Some("2"), Some(names), 42, &["exe", "cg"]).is_err()
            );
        }
    }

    #[test]
    fn notification_names_cannot_inject_fields() {
        for name in ["", "a:b", "a\nREADY=1", "a=b", "a\0b", "роль"] {
            assert!(!valid_name(name));
        }
        assert!(!valid_name(&"a".repeat(65)));
        assert!(valid_name("role_01-executable"));
    }
}
