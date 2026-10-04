//! Root-only D-Bus control of the persistent service-role owner (opt-in feature).
//!
//! The catalog (devices, executables, cgroups) is fixed at owner creation; only
//! per-role device permission masks can change, as one atomic generation swap.
use super::smart::authorize_process_request;
use crate::service_owner;
use zbus::{Connection, fdo, interface, message::Header};

pub struct ServiceRolesInterface;

fn owner() -> fdo::Result<
    std::sync::Arc<
        std::sync::Mutex<cardwire_ebpf_userspace::service_guard::persistent::PersistentGuard>,
    >,
> {
    service_owner::guard().ok_or_else(|| fdo::Error::Failed("service roles are not active".into()))
}

#[interface(name = "org.opengamingcollective.cardwire.ServiceRoles")]
impl ServiceRolesInterface {
    /// Current policy generation.
    #[zbus(property)]
    fn generation(&self) -> fdo::Result<u64> {
        let guard = owner()?;
        let guard = guard
            .lock()
            .map_err(|_| fdo::Error::Failed("owner poisoned".into()))?;
        Ok(guard.current_generation())
    }

    /// Current per-role masks in catalog order (bit n = catalog device n).
    #[zbus(property)]
    fn permissions(&self) -> fdo::Result<Vec<u32>> {
        let guard = owner()?;
        let guard = guard
            .lock()
            .map_err(|_| fdo::Error::Failed("owner poisoned".into()))?;
        Ok(guard.permissions())
    }

    /// Names of the profiles configured in service-roles.toml.
    #[zbus(property)]
    fn profiles(&self) -> Vec<String> {
        service_owner::profiles()
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }

    /// Profile whose masks equal the live policy, or empty. Derived from the
    /// kernel-committed snapshot, so it cannot drift after a crash.
    #[zbus(property)]
    fn current_profile(&self) -> fdo::Result<String> {
        let guard = owner()?;
        let guard = guard
            .lock()
            .map_err(|_| fdo::Error::Failed("owner poisoned".into()))?;
        let live = guard.permissions();
        Ok(service_owner::profiles()
            .iter()
            .find(|p| p.permissions == live)
            .map(|p| p.name.clone())
            .unwrap_or_default())
    }

    /// Apply a configured profile atomically (root only); returns the generation.
    async fn apply_profile(
        &self,
        name: String,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<u64> {
        authorize_process_request(connection, &header).await?;
        let profile = service_owner::profiles()
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| fdo::Error::InvalidArgs("unknown profile".into()))?;
        let guard = owner()?;
        let mut guard = guard
            .lock()
            .map_err(|_| fdo::Error::Failed("owner poisoned".into()))?;
        let prepared = guard
            .prepare_permissions(&profile.permissions)
            .map_err(|e| fdo::Error::InvalidArgs(format!("{e:#}")))?;
        guard
            .commit(prepared)
            .map_err(|e| fdo::Error::Failed(format!("{e:#}")))?;
        Ok(guard.current_generation())
    }

    /// Re-enroll one role after its service was restarted (new cgroup / replaced
    /// executable), keeping its permission mask (root only). Returns the generation.
    async fn re_enroll_role(
        &self,
        index: u32,
        executable: String,
        cgroup: String,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<u64> {
        authorize_process_request(connection, &header).await?;
        tokio::task::spawn_blocking(move || {
            service_owner::re_enroll(index as usize, &executable, &cgroup)
        })
        .await
        .map_err(|e| fdo::Error::Failed(e.to_string()))?
        .map_err(|e| fdo::Error::Failed(format!("{e:#}")))
    }

    /// Atomically replace ALL role masks (root only). Wrong length, unknown
    /// device bits or a concurrent change reject the call and keep old policy.
    async fn set_permissions(
        &self,
        masks: Vec<u32>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<u64> {
        authorize_process_request(connection, &header).await?;
        let guard = owner()?;
        let mut guard = guard
            .lock()
            .map_err(|_| fdo::Error::Failed("owner poisoned".into()))?;
        let prepared = guard
            .prepare_permissions(&masks)
            .map_err(|e| fdo::Error::InvalidArgs(format!("{e:#}")))?;
        guard
            .commit(prepared)
            .map_err(|e| fdo::Error::Failed(format!("{e:#}")))?;
        Ok(guard.current_generation())
    }
}
