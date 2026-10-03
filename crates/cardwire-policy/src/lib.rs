#![no_std]

//! Shared userspace/eBPF policy encoding. A PID has exactly one map entry.
//! Updating one u64 replaces the complete policy; there is no delete/insert gap.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessPolicy {
    Allowed,
    Forced(u32),
}

impl ProcessPolicy {
    const ALLOWED: u64 = 1 << 32;

    #[inline(always)]
    pub const fn encode(self) -> u64 {
        match self {
            Self::Allowed => Self::ALLOWED,
            Self::Forced(gpu) => gpu as u64,
        }
    }

    #[inline(always)]
    pub const fn decode(raw: u64) -> Option<Self> {
        if raw == Self::ALLOWED {
            Some(Self::Allowed)
        } else if raw <= u32::MAX as u64 {
            Some(Self::Forced(raw as u32))
        } else {
            None
        }
    }

    /// Preserve Smart's existing direct-parent Allow precedence.
    #[inline(always)]
    pub fn smart(own: Option<Self>, parent: Option<Self>) -> Option<Self> {
        if matches!(own, Some(Self::Allowed)) || matches!(parent, Some(Self::Allowed)) {
            Some(Self::Allowed)
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
    use super::ProcessPolicy::{self, Allowed, Forced};

    #[test]
    fn encoding_is_disjoint_for_all_gpu_id_boundaries() {
        for policy in [Allowed, Forced(0), Forced(1), Forced(u32::MAX)] {
            assert_eq!(ProcessPolicy::decode(policy.encode()), Some(policy));
        }
        assert_eq!(ProcessPolicy::decode((1 << 32) + 1), None);
        assert_eq!(ProcessPolicy::decode(u64::MAX), None);
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
}
