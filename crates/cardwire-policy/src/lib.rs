#![no_std]

//! Shared userspace/eBPF policy encoding. A PID has exactly one map entry.
//! Updating one u64 replaces the complete policy; there is no delete/insert gap.

pub mod service_roles;

/// Runtime kernel layout, resolved from vmlinux BTF before any hook is attached.
/// All supported targets use 64-bit kernel pointers; there is no implicit padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskLayout {
    pub size: u32,
    pub real_parent: u32,
    pub tgid: u32,
}

impl TaskLayout {
    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        // Bounds precede subtraction/addition so malformed map values never
        // overflow, including in the eBPF build with overflow checks enabled.
        self.size >= 8
            && self.size <= 65536
            && self.real_parent > 0
            && self.real_parent <= self.size - 8
            && self.real_parent & 7 == 0
            && self.tgid > 0
            && self.tgid <= self.size - 4
            && self.tgid & 3 == 0
            && (self.tgid + 4 <= self.real_parent || self.real_parent + 8 <= self.tgid)
    }
}

/// BTF-resolved fields used by the file/inode LSM hooks on 64-bit kernels.
/// Offsets of nested members are relative to the outer object, not a pointer
/// target. The dentry alias is an embedded 16-byte hlist_node.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileLayout {
    pub inode_size: u32,
    pub inode_number: u32,
    pub inode_alias: u32,
    pub dentry_size: u32,
    pub dentry_inode: u32,
    pub dentry_name: u32,
    pub dentry_alias: u32,
    pub file_size: u32,
    pub file_dentry: u32,
    pub path_size: u32,
    pub path_dentry: u32,
}

impl FileLayout {
    #[inline(always)]
    const fn slot(size: u32, offset: u32, width: u32) -> bool {
        size >= width && size <= 65536 && offset <= size - width && offset & 7 == 0
    }

    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        Self::slot(self.inode_size, self.inode_number, 8)
            && Self::slot(self.inode_size, self.inode_alias, 8)
            && Self::slot(self.dentry_size, self.dentry_inode, 8)
            && Self::slot(self.dentry_size, self.dentry_name, 8)
            && Self::slot(self.dentry_size, self.dentry_alias, 16)
            && Self::slot(self.file_size, self.file_dentry, 8)
            && Self::slot(self.path_size, self.path_dentry, 8)
            // All additions below are bounded by the successful slot checks.
            && (self.inode_number + 8 <= self.inode_alias || self.inode_alias + 8 <= self.inode_number)
            && (self.dentry_inode + 8 <= self.dentry_name || self.dentry_name + 8 <= self.dentry_inode)
            && (self.dentry_inode + 8 <= self.dentry_alias || self.dentry_alias + 16 <= self.dentry_inode)
            && (self.dentry_name + 8 <= self.dentry_alias || self.dentry_alias + 16 <= self.dentry_name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessPolicy {
    Allowed,
    /// Administrative Smart-mode allow for this TGID only, not its children.
    AllowedExact,
    Forced(u32),
}

impl ProcessPolicy {
    const ALLOWED: u64 = 1 << 32;
    const ALLOWED_EXACT: u64 = 2 << 32;
    /// Missing or invalid map entry; disjoint from every valid encoding.
    pub const NONE: u64 = u64::MAX;

    #[inline(always)]
    pub const fn encode(self) -> u64 {
        match self {
            Self::Allowed => Self::ALLOWED,
            Self::AllowedExact => Self::ALLOWED_EXACT,
            Self::Forced(gpu) => gpu as u64,
        }
    }

    #[inline(always)]
    pub const fn decode(raw: u64) -> Option<Self> {
        if raw == Self::ALLOWED {
            Some(Self::Allowed)
        } else if raw == Self::ALLOWED_EXACT {
            Some(Self::AllowedExact)
        } else if raw <= u32::MAX as u64 {
            Some(Self::Forced(raw as u32))
        } else {
            None
        }
    }

    /// Scalar decision for eBPF: every branch returns a fully initialized u64.
    /// Do not merge Option<ProcessPolicy> payloads in the kernel path: LLVM can
    /// leave the unused enum payload undefined, which the BPF verifier rejects.
    /// Unknown encodings have the same semantics as a missing map entry.
    #[inline(always)]
    pub const fn smart_encoded(own: u64, parent: u64) -> u64 {
        if own == Self::ALLOWED || own == Self::ALLOWED_EXACT || parent == Self::ALLOWED {
            Self::ALLOWED
        } else {
            Self::manual_encoded(own, parent)
        }
    }

    /// Manual mode honors only Forced entries. This also implements the
    /// Forced-only fallback in Smart; an Exact parent is never inherited.
    #[inline(always)]
    pub const fn manual_encoded(own: u64, parent: u64) -> u64 {
        if own <= u32::MAX as u64 {
            own
        } else if parent <= u32::MAX as u64 {
            parent
        } else {
            Self::NONE
        }
    }

    /// Preserve legacy parent Allow precedence, but never inherit Exact.
    /// The result is an effective decision, not the stored policy: a local
    /// Exact allow normalizes to Allowed for the eBPF enforcement path.
    #[inline(always)]
    pub fn smart(own: Option<Self>, parent: Option<Self>) -> Option<Self> {
        if matches!(own, Some(Self::Allowed | Self::AllowedExact))
            || matches!(parent, Some(Self::Allowed))
        {
            Some(Self::Allowed)
        } else if matches!(parent, Some(Self::AllowedExact)) {
            own
        } else {
            own.or(parent)
        }
    }

    /// Manual mode historically honors only Forced, not Allow, entries.
    #[inline(always)]
    pub fn manual(own: Option<Self>, parent: Option<Self>) -> Option<Self> {
        if matches!(own, Some(Self::Forced(_))) {
            own
        } else if matches!(parent, Some(Self::Forced(_))) {
            parent
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileLayout, ProcessPolicy::{self, Allowed, AllowedExact, Forced}, TaskLayout
    };

    #[test]
    fn task_layout_is_shared_padding_free_and_rejects_uninitialized_values() {
        assert_eq!(core::mem::size_of::<TaskLayout>(), 12);
        assert_eq!(core::mem::align_of::<TaskLayout>(), 4);
        assert!(
            !TaskLayout {
                size: 0,
                real_parent: 0,
                tgid: 0
            }
            .is_valid()
        );
        assert!(
            !TaskLayout {
                size: u32::MAX,
                real_parent: u32::MAX,
                tgid: u32::MAX
            }
            .is_valid()
        );
        assert!(
            TaskLayout {
                size: 4032,
                real_parent: 1936,
                tgid: 1924
            }
            .is_valid()
        );
        assert!(
            TaskLayout {
                size: 6144,
                real_parent: 2944,
                tgid: 2932
            }
            .is_valid()
        );
        assert!(
            !TaskLayout {
                size: 4032,
                real_parent: 1936,
                tgid: 1940
            }
            .is_valid()
        );
    }

    #[test]
    fn encoding_is_disjoint_for_all_gpu_id_boundaries() {
        for policy in [
            Allowed,
            AllowedExact,
            Forced(0),
            Forced(1),
            Forced(u32::MAX),
        ] {
            assert_eq!(ProcessPolicy::decode(policy.encode()), Some(policy));
        }
        assert_eq!(ProcessPolicy::decode((1 << 32) + 1), None);
        assert_eq!(ProcessPolicy::decode((2 << 32) + 1), None);
        assert_eq!(ProcessPolicy::decode(u64::MAX), None);
    }

    #[test]
    fn file_layout_is_padding_free_and_validates_every_slot() {
        assert_eq!(core::mem::size_of::<FileLayout>(), 44);
        assert_eq!(core::mem::align_of::<FileLayout>(), 4);
        let good = FileLayout {
            inode_size: 608,
            inode_number: 64,
            inode_alias: 304,
            dentry_size: 192,
            dentry_inode: 48,
            dentry_name: 40,
            dentry_alias: 176,
            file_size: 256,
            file_dentry: 72,
            path_size: 16,
            path_dentry: 8,
        };
        assert!(good.is_valid());
        for invalid in [
            FileLayout {
                inode_size: 0,
                ..good
            },
            FileLayout {
                inode_number: u32::MAX,
                ..good
            },
            FileLayout {
                inode_alias: 64,
                ..good
            },
            FileLayout {
                dentry_size: u32::MAX,
                ..good
            },
            FileLayout {
                dentry_inode: 40,
                ..good
            },
            FileLayout {
                dentry_name: 176,
                ..good
            },
            FileLayout {
                dentry_alias: 48,
                ..good
            },
            FileLayout {
                dentry_alias: 184,
                ..good
            },
            FileLayout {
                file_size: 0,
                ..good
            },
            FileLayout {
                file_dentry: 73,
                ..good
            },
            FileLayout {
                path_size: 0,
                ..good
            },
            FileLayout {
                path_dentry: 16,
                ..good
            },
        ] {
            assert!(!invalid.is_valid(), "{invalid:?}");
        }
    }

    #[test]
    fn smart_preserves_parent_allow_precedence_and_own_force_precedence() {
        assert_eq!(
            ProcessPolicy::smart(Some(Forced(0)), Some(Allowed)),
            Some(Allowed)
        );
        assert_eq!(
            ProcessPolicy::smart(Some(Allowed), Some(Forced(0))),
            Some(Allowed)
        );
        assert_eq!(
            ProcessPolicy::smart(Some(Forced(1)), Some(Forced(0))),
            Some(Forced(1))
        );
        assert_eq!(ProcessPolicy::smart(None, Some(Forced(0))), Some(Forced(0)));
        assert_eq!(ProcessPolicy::smart(None, None), None);
    }

    #[test]
    fn manual_preserves_forced_only_behavior() {
        assert_eq!(
            ProcessPolicy::manual(Some(Allowed), Some(Forced(0))),
            Some(Forced(0))
        );
        assert_eq!(
            ProcessPolicy::manual(Some(Forced(1)), Some(Allowed)),
            Some(Forced(1))
        );
        assert_eq!(ProcessPolicy::manual(Some(Allowed), Some(Allowed)), None);
        assert_eq!(ProcessPolicy::manual(None, None), None);
    }

    #[test]
    fn exact_allow_is_local_even_when_the_parent_is_forced() {
        for parent in [
            None,
            Some(Allowed),
            Some(AllowedExact),
            Some(Forced(0)),
            Some(Forced(1)),
        ] {
            assert_eq!(
                ProcessPolicy::smart(Some(AllowedExact), parent),
                Some(Allowed)
            );
        }
    }

    #[test]
    fn exact_parent_is_not_an_exception_for_its_child() {
        assert_eq!(ProcessPolicy::smart(None, Some(AllowedExact)), None);
        for own in [Some(Forced(0)), Some(Forced(1)), Some(Allowed)] {
            assert_eq!(ProcessPolicy::smart(own, Some(AllowedExact)), own);
        }
    }

    #[test]
    fn exact_entries_do_not_change_manual_mode_semantics() {
        assert_eq!(ProcessPolicy::manual(Some(AllowedExact), None), None);
        assert_eq!(ProcessPolicy::manual(None, Some(AllowedExact)), None);
        assert_eq!(
            ProcessPolicy::manual(Some(AllowedExact), Some(AllowedExact)),
            None
        );
        assert_eq!(
            ProcessPolicy::manual(Some(AllowedExact), Some(Forced(1))),
            Some(Forced(1))
        );
        assert_eq!(
            ProcessPolicy::manual(Some(Forced(0)), Some(AllowedExact)),
            Some(Forced(0))
        );
    }

    #[test]
    fn complete_smart_policy_matrix_never_leaks_exact_to_children() {
        let entries = [
            None,
            Some(Allowed),
            Some(AllowedExact),
            Some(Forced(0)),
            Some(Forced(1)),
        ];
        for own in entries {
            for parent in entries {
                let expected = match (own, parent) {
                    (Some(Allowed | AllowedExact), _) | (_, Some(Allowed)) => Some(Allowed),
                    (Some(Forced(gpu)), _) => Some(Forced(gpu)),
                    (None, Some(Forced(gpu))) => Some(Forced(gpu)),
                    _ => None,
                };
                assert_eq!(
                    ProcessPolicy::smart(own, parent),
                    expected,
                    "{own:?}, {parent:?}"
                );
            }
        }
    }

    #[test]
    fn scalar_decisions_match_typed_reference_including_invalid_entries() {
        let values = [
            ProcessPolicy::NONE,
            Allowed.encode(),
            AllowedExact.encode(),
            0,
            1,
            15,
            u32::MAX as u64 - 1,
            u32::MAX as u64,
            Allowed.encode() + 1,
            AllowedExact.encode() - 1,
            AllowedExact.encode() + 1,
            u64::MAX - 1,
        ];
        for own in values {
            for parent in values {
                let own_decoded = ProcessPolicy::decode(own);
                let parent_decoded = ProcessPolicy::decode(parent);
                let smart = ProcessPolicy::smart(own_decoded, parent_decoded)
                    .map(ProcessPolicy::encode)
                    .unwrap_or(ProcessPolicy::NONE);
                let manual = ProcessPolicy::manual(own_decoded, parent_decoded)
                    .map(ProcessPolicy::encode)
                    .unwrap_or(ProcessPolicy::NONE);
                assert_eq!(
                    ProcessPolicy::smart_encoded(own, parent),
                    smart,
                    "Smart: own={own:#x}, parent={parent:#x}"
                );
                assert_eq!(
                    ProcessPolicy::manual_encoded(own, parent),
                    manual,
                    "Manual: own={own:#x}, parent={parent:#x}"
                );
            }
        }
    }

    #[test]
    fn scalar_exact_grant_does_not_allow_child_and_is_not_truncated_to_gpu_zero() {
        assert_eq!(
            ProcessPolicy::smart_encoded(AllowedExact.encode(), Forced(0).encode()),
            Allowed.encode()
        );
        assert_eq!(
            ProcessPolicy::smart_encoded(ProcessPolicy::NONE, AllowedExact.encode()),
            ProcessPolicy::NONE
        );
        assert_eq!(
            ProcessPolicy::manual_encoded(AllowedExact.encode(), AllowedExact.encode()),
            ProcessPolicy::NONE
        );
        assert_eq!(
            ProcessPolicy::smart_encoded(Forced(u32::MAX).encode(), AllowedExact.encode()),
            u32::MAX as u64
        );
    }
}
