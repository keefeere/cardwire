use aya::maps::{HashMap as AyaHashMap, MapError as AyaMapError};
use cardwire_ebpf_userspace::EbpfBlocker;
use cardwire_policy::ProcessPolicy;
use std::{
    collections::HashMap, path::Path, sync::{Arc, OnceLock}
};

use tokio::sync::{Mutex, RwLock};
use zbus::{Connection, fdo, interface, message::Header, object_server::SignalEmitter};

use crate::file::{CardwireDatabase, DbusAppMetadata, GpuPolicy};

fn require_administrator(uid: Option<u32>) -> fdo::Result<()> {
    if uid == Some(0) {
        Ok(())
    } else {
        Err(fdo::Error::AccessDenied(
            "Changing a PID's GPU policy requires root".into(),
        ))
    }
}

async fn authorize_process_request(
    connection: &Connection,
    header: &Header<'_>,
) -> fdo::Result<()> {
    // The bus supplies the unique sender and authenticates its UID. Never
    // derive authority from the target PID, client arguments or environment.
    let sender = header
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("Missing D-Bus sender".into()))?;
    let bus = fdo::DBusProxy::new(connection)
        .await
        .map_err(|_| fdo::Error::AccessDenied("Cannot authenticate D-Bus caller".into()))?;
    let uid = bus
        .get_connection_unix_user(sender.clone().into())
        .await
        .map_err(|_| fdo::Error::AccessDenied("Cannot authenticate D-Bus caller".into()))?;
    require_administrator(Some(uid))
}

fn requested_policy(policy: &str, value: u32) -> fdo::Result<Option<ProcessPolicy>> {
    match policy {
        "Default" => Ok(None),
        "Allow_dGPU" => Ok(Some(ProcessPolicy::Allowed)),
        "Force_dGPU" | "Force_GPU" => Ok(Some(ProcessPolicy::Forced(value))),
        _ => Err(fdo::Error::InvalidArgs(format!("invalid arg: {policy}"))),
    }
}

fn policy_status(raw: Option<u64>) -> fdo::Result<(String, Option<u32>)> {
    match raw {
        None => Ok((String::new(), None)),
        Some(raw) => match ProcessPolicy::decode(raw) {
            Some(ProcessPolicy::Allowed) => Ok(("Allowed".into(), Some(0))),
            Some(ProcessPolicy::Forced(gpu)) => Ok(("Forced".into(), Some(gpu))),
            None => Err(fdo::Error::Failed("Invalid process policy encoding".into())),
        },
    }
}

#[derive(Clone, Debug)]
pub struct SmartPolicyInterface {
    process_policies: Arc<RwLock<AyaHashMap<aya::maps::MapData, u32, u64>>>,
    pub database: CardwireDatabase,
    policy_lock: Arc<Mutex<()>>,
    pub new_app_signal: Arc<OnceLock<SignalEmitter<'static>>>,
}

impl SmartPolicyInterface {
    pub fn build(blocker: &mut EbpfBlocker, db: CardwireDatabase) -> Self {
        Self {
            process_policies: Arc::clone(&blocker.process_policies),
            database: db,
            policy_lock: Arc::new(Mutex::new(())),
            new_app_signal: Arc::new(OnceLock::new()),
        }
    }
}

#[interface(name = "org.opengamingcollective.cardwire.SmartPolicy")]
impl SmartPolicyInterface {
    /// Administratively authorize a PID to access a specific GPU (root only).
    /// policy should be:
    ///     Default (does nothing)
    ///     Allow_dGPU
    ///     Force_dGPU
    ///     Force_GPU
    /// value:
    /// if allow/force dGPU: use 0 or 1 (bool)
    /// if Force_GPU: use the target GPU id
    pub async fn request_process_access(
        &self,
        pid: u32,
        policy: String,
        value: u32,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), fdo::Error> {
        authorize_process_request(connection, &header).await?;
        // Check if the process exists, leave if it doesnt
        if !Path::new(&format!("/proc/{}", pid)).exists() {
            return Err(fdo::Error::Failed("process doesn't exist".to_string()));
        }
        let Some(policy) = requested_policy(&policy, value)? else {
            return Ok(());
        };
        // A single BPF_ANY update is the complete transition. Concurrent API,
        // analyzer and exec/exit cleanup operations cannot create a dual state.
        // If update fails, the old policy remains; no delete or rollback needed.
        self.process_policies
            .write()
            .await
            .insert(pid, policy.encode(), 0)
            .map_err(|err| fdo::Error::Failed(err.to_string()))
    }

    /// Read the same single policy value used by eBPF enforcement.
    /// Return the map type with the gpu_id associed
    pub async fn get_process_status(&self, pid: u32) -> Result<(String, Option<u32>), fdo::Error> {
        match self.process_policies.read().await.get(&pid, 0) {
            Ok(raw) => policy_status(Some(raw)),
            Err(AyaMapError::KeyNotFound) => policy_status(None),
            Err(err) => Err(fdo::Error::Failed(format!(
                "Couldn't read process policy: {err}"
            ))),
        }
    }

    /// Get the list of app inside the internal cardwire database
    pub async fn get_app_policies(&self) -> fdo::Result<HashMap<String, DbusAppMetadata>> {
        let db_clone = self.database.clone();

        tokio::task::spawn_blocking(move || {
            db_clone
                .read_db()
                .map_err(|err| fdo::Error::Failed(err.to_string()))
        })
        .await
        .map_err(|err| fdo::Error::Failed(err.to_string()))?
    }

    /// Set the policy of an app using the app_id
    pub async fn set_app_policy(&self, app_id: String, policy: i32) -> Result<(), fdo::Error> {
        let gpu_policy = GpuPolicy::try_from_i32(policy)
            .ok_or_else(|| fdo::Error::InvalidArgs(format!("invalid policy: {}", policy)))?;

        if !self.database.cache.read().await.contains_key(&app_id) {
            return Err(fdo::Error::UnknownObject(format!(
                "app not found: {}",
                app_id
            )));
        }

        let db_clone = self.database.clone();
        let app_id_clone = app_id.clone();

        let _policy_guard = self.policy_lock.lock().await;
        tokio::task::spawn_blocking(move || db_clone.update_policy(&app_id_clone, policy))
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;

        self.database.cache.write().await.insert(app_id, gpu_policy);

        Ok(())
    }

    #[zbus(signal)]
    /// Signal when cardwire discovered a new app
    pub async fn new_app_added(
        emitter: &SignalEmitter<'_>,
        new_app: (String, DbusAppMetadata),
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_mutation_requires_authenticated_root() {
        assert!(require_administrator(Some(0)).is_ok());
        for uid in [None, Some(1), Some(1000), Some(u32::MAX)] {
            assert!(matches!(
                require_administrator(uid),
                Err(fdo::Error::AccessDenied(_))
            ));
        }
    }

    #[test]
    fn request_values_keep_the_existing_wire_semantics() {
        assert_eq!(requested_policy("Default", 1).unwrap(), None);
        assert_eq!(
            requested_policy("Allow_dGPU", 0).unwrap(),
            Some(ProcessPolicy::Allowed)
        );
        assert_eq!(
            requested_policy("Allow_dGPU", 1).unwrap(),
            Some(ProcessPolicy::Allowed)
        );
        assert_eq!(
            requested_policy("Force_dGPU", 0).unwrap(),
            Some(ProcessPolicy::Forced(0))
        );
        assert_eq!(
            requested_policy("Force_GPU", 15).unwrap(),
            Some(ProcessPolicy::Forced(15))
        );
        assert!(matches!(
            requested_policy("unknown", 0),
            Err(fdo::Error::InvalidArgs(_))
        ));
    }

    #[test]
    fn status_decodes_the_same_value_as_enforcement() {
        assert_eq!(policy_status(None).unwrap(), (String::new(), None));
        assert_eq!(
            policy_status(Some(ProcessPolicy::Allowed.encode())).unwrap(),
            ("Allowed".into(), Some(0))
        );
        for gpu in [0, 1, 15, u32::MAX] {
            assert_eq!(
                policy_status(Some(ProcessPolicy::Forced(gpu).encode())).unwrap(),
                ("Forced".into(), Some(gpu))
            );
        }
    }

    #[test]
    fn invalid_map_value_is_not_reported_as_unclassified() {
        assert!(matches!(
            policy_status(Some(u64::MAX)),
            Err(fdo::Error::Failed(_))
        ));
    }
}
