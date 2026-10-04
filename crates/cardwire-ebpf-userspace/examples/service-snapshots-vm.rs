//! Explicit disposable-VM frontend to the actual experimental snapshot backend.
use anyhow::{Result, bail, ensure};
use cardwire_ebpf_userspace::service_guard::{Registration, ServiceGuard};
use std::{
    fs::OpenOptions, io::{self, BufRead, Write}, os::unix::fs::OpenOptionsExt, path::Path
};

#[path = "service-role-vm.rs"]
#[allow(dead_code)]
mod fixture;

fn registration(group: &str, incarnation: u64, mask: u32) -> Result<Registration> {
    let executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open("/tmp/cardwire-role-worker")?;
    let cgroup = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(group)?;
    Registration::new(executable, cgroup, 0, incarnation, mask)
}

fn main() -> Result<()> {
    fixture::vm_guard()?;
    let devices = ["/dev/dri/renderD129", "/dev/dri/card1"]
        .iter()
        .map(|path| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(path)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut a = registration("/sys/fs/cgroup/cardwire-snapshot-a", 1, 3)?;
    let mut b = registration("/sys/fs/cgroup/cardwire-snapshot-b", 1, 1)?;
    let mut guard = ServiceGuard::attach(Path::new("/tmp/cardwire-service-guard.bpf.o"), devices)?;
    println!("ATTACHED deny-all");
    io::stdout().flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let words: Vec<_> = line.split_whitespace().collect();
        if words == ["stop"] {
            break;
        }
        let outcome = (|| -> Result<()> {
            ensure!(!words.is_empty(), "missing command");
            if words == ["frozen"] {
                return guard.verify_current_frozen();
            }
            ensure!(words.len() >= 2, "missing generation");
            let generation = words[1].parse()?;
            if words[0] == "clear" {
                ensure!(words.len() == 2, "unexpected arguments");
                return guard.publish(generation, Vec::new());
            }
            ensure!(words.len() == 4, "need two masks");
            let mask_a = words[2].parse()?;
            let mask_b = words[3].parse()?;
            match words[0] {
                "publish" => guard.publish(
                    generation,
                    vec![a.with_access(mask_a)?, b.with_access(mask_b)?],
                ),
                "duplicate" => guard.publish(
                    generation,
                    vec![a.with_access(mask_a)?, a.with_access(mask_b)?],
                ),
                "rebind-a" => {
                    let new_a =
                        registration("/sys/fs/cgroup/cardwire-snapshot-a", generation, mask_a)?;
                    guard.publish(
                        generation,
                        vec![new_a.with_access(mask_a)?, b.with_access(mask_b)?],
                    )?;
                    a = new_a;
                    Ok(())
                }
                "rebind-all" => {
                    let new_a =
                        registration("/sys/fs/cgroup/cardwire-snapshot-a", generation, mask_a)?;
                    let new_b =
                        registration("/sys/fs/cgroup/cardwire-snapshot-b", generation, mask_b)?;
                    guard.publish(
                        generation,
                        vec![new_a.with_access(mask_a)?, new_b.with_access(mask_b)?],
                    )?;
                    a = new_a;
                    b = new_b;
                    Ok(())
                }
                _ => bail!("unknown command"),
            }
        })();
        match outcome {
            Ok(()) => println!("OK {}", guard.current_generation().unwrap_or(0)),
            Err(error) => println!(
                "REJECTED {} {error}",
                guard.current_generation().unwrap_or(0)
            ),
        }
        io::stdout().flush()?;
    }
    Ok(())
}
