//! Versioned immutable service-policy ABI. Not a replacement for legacy app policy.
//! The owner must retain executable/cgroup objects for every published identity.
pub const MAGIC: u32 = 0x5053_5743; // CWSP in little endian
pub const VERSION: u32 = 1;
pub const MAX_ROLES: usize = 16;
pub const MAX_DEVICES: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Role {
    /// Stable while this slot names the same registration, not the policy generation.
    pub incarnation: u64,
    pub cgroup_id: u64,
    pub executable_inode: u64,
    pub executable_device: u32,
    pub uid: u32,
    pub access_mask: u32,
    pub reserved: u32,
}

impl Role {
    pub fn same_identity(&self, other: &Self) -> bool {
        self.cgroup_id == other.cgroup_id
            && self.executable_inode == other.executable_inode
            && self.executable_device == other.executable_device
            && self.uid == other.uid
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub magic: u32,
    pub version: u32,
    pub generation: u64,
    pub role_count: u32,
    pub reserved: u32,
    pub roles: [Role; MAX_ROLES],
}

impl Snapshot {
    pub fn empty(generation: u64) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            generation,
            role_count: 0,
            reserved: 0,
            roles: [Role::default(); MAX_ROLES],
        }
    }

    /// Validate a whole proposed replacement before any publication syscall.
    /// A new/replaced registration gets this generation as its incarnation;
    /// permission-only updates preserve its ticket, and can still revoke opens.
    pub fn validate(
        &self,
        previous: Option<&Self>,
        device_count: usize,
    ) -> Result<(), &'static str> {
        if self.magic != MAGIC
            || self.version != VERSION
            || self.reserved != 0
            || self.generation == 0
            || self.role_count as usize > MAX_ROLES
            || device_count == 0
            || device_count > MAX_DEVICES
        {
            return Err("invalid policy header or inventory size");
        }
        if previous.is_some_and(|p| self.generation <= p.generation) {
            return Err("policy generation must increase");
        }
        let valid_mask = (1u32 << device_count) - 1;
        for (index, role) in self.roles.iter().enumerate() {
            if index >= self.role_count as usize {
                if *role != Role::default() {
                    return Err("nonzero unused role");
                }
                continue;
            }
            if role.incarnation == 0
                || role.cgroup_id == 0
                || role.executable_inode == 0
                || role.reserved != 0
                || role.access_mask & !valid_mask != 0
            {
                return Err("invalid role or device permissions");
            }
            for earlier in &self.roles[..index] {
                if role.same_identity(earlier) {
                    return Err("ambiguous role identity");
                }
            }
            let old = previous
                .filter(|p| index < p.role_count as usize)
                .map(|p| &p.roles[index]);
            let unchanged =
                old.is_some_and(|p| role.same_identity(p) && role.incarnation == p.incarnation);
            if !unchanged && role.incarnation != self.generation {
                return Err("new registration needs a fresh incarnation");
            }
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    pub count: u32,
    pub reserved: u32,
    pub devices: [u32; MAX_DEVICES],
}

impl Inventory {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.count == 0 || self.count as usize > MAX_DEVICES || self.reserved != 0 {
            return Err("invalid protected device count");
        }
        for (index, dev) in self.devices.iter().enumerate() {
            if index < self.count as usize {
                if *dev == 0 || self.devices[..index].contains(dev) {
                    return Err("invalid or duplicate protected device");
                }
            } else if *dev != 0 {
                return Err("nonzero unused device");
            }
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ticket {
    pub incarnation: u64,
    pub role_index: u32,
    pub reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    fn sample() -> Snapshot {
        let mut s = Snapshot::empty(1);
        s.role_count = 2;
        for index in 0..2 {
            s.roles[index] = Role {
                incarnation: 1,
                cgroup_id: 10 + index as u64,
                executable_inode: 20,
                executable_device: 30,
                uid: 1000,
                access_mask: 3,
                reserved: 0,
            };
        }
        s
    }

    #[test]
    fn c_abi_is_explicit_and_padding_free() {
        assert_eq!((size_of::<Role>(), align_of::<Role>()), (40, 8));
        assert_eq!(offset_of!(Role, access_mask), 32);
        assert_eq!(offset_of!(Snapshot, roles), 24);
        assert_eq!(size_of::<Snapshot>(), 664);
        assert_eq!(size_of::<Inventory>(), 72);
        assert_eq!(size_of::<Ticket>(), 16);
    }

    #[test]
    fn permission_updates_preserve_live_service_identity() {
        let old = sample();
        assert!(old.validate(None, 2).is_ok());
        let mut next = old;
        next.generation = 2;
        next.roles[0].access_mask = 0;
        assert!(next.validate(Some(&old), 2).is_ok());
        assert_eq!(next.roles[1], old.roles[1]); // Inference is untouched.
    }

    #[test]
    fn replaced_removed_or_reordered_roles_cannot_reuse_old_tickets() {
        let old = sample();
        let mut next = old;
        next.generation = 2;
        next.roles[0].cgroup_id += 10;
        assert!(next.validate(Some(&old), 2).is_err());
        next.roles[0].incarnation = 2;
        assert!(next.validate(Some(&old), 2).is_ok());
        let empty = Snapshot::empty(2);
        let mut again = old;
        again.generation = 3;
        assert!(again.validate(Some(&empty), 2).is_err());
        again.roles[0].incarnation = 3;
        again.roles[1].incarnation = 3;
        assert!(again.validate(Some(&empty), 2).is_ok());
        let mut reordered = old;
        reordered.generation = 2;
        reordered.roles.swap(0, 1);
        assert!(reordered.validate(Some(&old), 2).is_err());
    }

    #[test]
    fn malformed_or_ambiguous_replacements_fail() {
        let old = sample();
        assert!(old.validate(Some(&old), 2).is_err());
        for device_count in [0, 17, usize::MAX] {
            assert!(old.validate(None, device_count).is_err());
        }
        let mut bad = old;
        bad.roles[1] = bad.roles[0];
        assert!(bad.validate(None, 2).is_err());
        bad = old;
        bad.roles[0].access_mask = 4;
        assert!(bad.validate(None, 2).is_err());
        bad = old;
        bad.roles[15].uid = 1;
        assert!(bad.validate(None, 2).is_err());
        for mutate in [
            |s: &mut Snapshot| s.role_count = 17,
            |s: &mut Snapshot| s.magic = 0,
            |s: &mut Snapshot| s.version = 2,
            |s: &mut Snapshot| s.reserved = 1,
            |s: &mut Snapshot| s.generation = 0,
        ] {
            bad = old;
            mutate(&mut bad);
            assert!(bad.validate(None, 2).is_err());
        }
    }

    #[test]
    fn inventories_require_unique_nonzero_devices() {
        let mut inv = Inventory {
            count: 2,
            ..Inventory::default()
        };
        inv.devices[0] = 0xe200081;
        inv.devices[1] = 0xe200001;
        assert!(inv.validate().is_ok());
        inv.devices[1] = inv.devices[0];
        assert!(inv.validate().is_err());
        assert!(Inventory::default().validate().is_err());
    }
}
