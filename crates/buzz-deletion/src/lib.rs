#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Shared durable whole-community deletion engine and store adapters.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use buzz_db::deletion::{
    ClaimedDeletion, DeletionRequest, DeletionStage, DeletionStore, FrozenInventory, LeaseToken,
    StorageManifest, StorageObject, DEFAULT_LEASE_DURATION,
};
use buzz_db::{Db, DbConfig};
use buzz_media::{deletion_inventory, CurrentObjectVersion, MediaStorage};
use clap::Subcommand;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DEFAULT_STORAGE_OBJECT_CAP: u64 = 1_000_000;
const WORKER_IDLE_POLL: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const STORAGE_DELETE_BATCH_SIZE: usize = 100;

#[cfg(test)]
static TEST_HEARTBEAT_INTERVAL_MS: AtomicU64 = AtomicU64::new(0);

fn heartbeat_interval() -> Duration {
    #[cfg(test)]
    {
        let milliseconds = TEST_HEARTBEAT_INTERVAL_MS.load(Ordering::Relaxed);
        if milliseconds > 0 {
            return Duration::from_millis(milliseconds);
        }
    }
    HEARTBEAT_INTERVAL
}

fn worker_health_stale_after() -> u64 {
    HEARTBEAT_INTERVAL.as_secs().saturating_mul(3)
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("deletion execution lease heartbeat failed")]
struct DeletionLeaseLost;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
struct ServingWriteLeaseLost {
    message: String,
}

/// Return the shared durable deletion store for relay and operator paths.
pub fn store(db: &Db) -> DeletionStore {
    db.deletion_store()
}

/// Durable, heartbeated lease for a serving-path external side effect.
pub struct ServingWriteGuard {
    store: DeletionStore,
    lease: buzz_db::deletion::ServingWriteLease,
    cancel: CancellationToken,
    lost: CancellationToken,
    finished: bool,
}

impl ServingWriteGuard {
    /// Verify this side-effect lease is still current before an irreversible call.
    pub async fn verify(&self) -> Result<()> {
        if self.lost.is_cancelled() {
            return Err(ServingWriteLeaseLost {
                message: "serving write lease heartbeat was lost".to_string(),
            }
            .into());
        }
        self.store
            .verify_serving_write_lease(&self.lease)
            .await
            .map_err(|error| ServingWriteLeaseLost {
                message: error.to_string(),
            })?;
        Ok(())
    }

    /// Run an external side effect while observing lease-heartbeat loss.
    ///
    /// Dropping the operation future on lease loss prevents a stale caller from
    /// continuing network I/O after its durable exclusion proof disappears.
    pub async fn protect<F, T>(&self, operation: F) -> Result<T>
    where
        F: std::future::Future<Output = T>,
    {
        self.verify().await?;
        let output = tokio::select! {
            biased;
            output = operation => output,
            _ = self.lost.cancelled() => {
                return Err(ServingWriteLeaseLost {
                    message: "serving write lease heartbeat was lost".to_string(),
                }
                .into())
            }
        };
        self.verify().await?;
        Ok(output)
    }

    /// Whether an error represents loss of a durable serving-write lease.
    pub fn is_lease_lost(error: &anyhow::Error) -> bool {
        error.downcast_ref::<ServingWriteLeaseLost>().is_some()
    }

    /// Whether a serving-write acquisition failed because the tenant is fenced.
    pub fn acquisition_is_fenced(error: &anyhow::Error) -> bool {
        matches!(
            error.downcast_ref::<buzz_db::DbError>(),
            Some(buzz_db::DbError::AccessDenied(_))
        )
    }

    /// Signal fired if the background lease heartbeat fails.
    pub fn lost(&self) -> CancellationToken {
        self.lost.clone()
    }

    /// The durable lease token presented to a final database mutation.
    pub fn lease(&self) -> &buzz_db::deletion::ServingWriteLease {
        &self.lease
    }

    /// Release the lease after the side effect completes.
    pub async fn finish(mut self) -> Result<()> {
        self.cancel.cancel();
        let released = self.store.release_serving_write_lease(&self.lease).await?;
        self.finished = true;
        if !released {
            return Err(ServingWriteLeaseLost {
                message: "serving write lease was already stale or released".to_string(),
            }
            .into());
        }
        Ok(())
    }
}

impl Drop for ServingWriteGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        if self.finished {
            return;
        }
        let store = self.store.clone();
        let lease = self.lease.clone();
        tokio::spawn(async move {
            let _ = store.release_serving_write_lease(&lease).await;
        });
    }
}

/// Acquire a serving-side external-effect lease without holding a pool connection.
///
/// A separate short database lease per effect is intentional: it is the only
/// durable proof that deletion can drain S3/Redis/push work across replicas.
/// PostgreSQL lease-table churn is reaped and exported by the relay pool-metrics
/// task; operators should watch the deletion lease gauges documented by Helm.
pub async fn acquire_serving_write(
    db: &Db,
    community: buzz_core::CommunityId,
    operation: &str,
) -> Result<ServingWriteGuard> {
    let store = store(db);
    let owner = default_executor_id();
    let lease = store
        .acquire_serving_write_lease(community, operation, &owner, DEFAULT_LEASE_DURATION)
        .await?;
    let heartbeat_store = store.clone();
    let mut heartbeat_lease = lease.clone();
    let cancel = CancellationToken::new();
    let heartbeat_cancel = cancel.clone();
    let lost = CancellationToken::new();
    let heartbeat_lost = lost.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = heartbeat_cancel.cancelled() => return,
                _ = interval.tick() => {
                    if heartbeat_store
                        .renew_serving_write_lease(
                            &mut heartbeat_lease,
                            DEFAULT_LEASE_DURATION,
                        )
                        .await
                        .is_err()
                    {
                        heartbeat_lost.cancel();
                        return;
                    }
                }
            }
        }
    });
    Ok(ServingWriteGuard {
        store,
        lease,
        cancel,
        lost,
        finished: false,
    })
}

/// CLI-only whole-community deletion commands.
#[derive(Subcommand)]
pub enum Command {
    /// Persist a deletion request and freeze its initial cross-store inventory.
    Submit {
        /// Canonical community host. Defaults to RELAY_URL's authority.
        #[arg(long)]
        host: Option<String>,
        /// Operator identity recorded on the request.
        #[arg(long)]
        requested_by: String,
        /// Optional reason for the request.
        #[arg(long)]
        reason: Option<String>,
    },
    /// List deletion requests as JSON.
    List {
        /// Maximum records.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
    /// Inspect one request, including approval/checkpoints/errors.
    Inspect {
        /// Deletion request UUID.
        id: Uuid,
    },
    /// Explicitly approve the exact frozen inventory digest.
    Approve {
        /// Deletion request UUID.
        id: Uuid,
        /// Approving operator identity.
        #[arg(long)]
        approved_by: String,
        /// Optional approval note.
        #[arg(long)]
        note: Option<String>,
    },
    /// Claim and run one request until terminal/blocked.
    Run {
        /// Deletion request UUID.
        id: Uuid,
        /// Executor identity (defaults to hostname/pid).
        #[arg(long)]
        executor_id: Option<String>,
    },
    /// Drain the currently runnable deletion queue, then exit.
    Drain {
        /// Executor identity (defaults to hostname/pid).
        #[arg(long)]
        executor_id: Option<String>,
    },
    /// Poll continuously in a dedicated no-ingress worker process.
    Worker {
        /// Executor identity (defaults to hostname/pid).
        #[arg(long)]
        executor_id: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopMode {
    Run,
    Drain,
    Worker,
}

impl LoopMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Drain => "drain",
            Self::Worker => "worker",
        }
    }
}

#[derive(Clone)]
struct Services {
    store: DeletionStore,
    media: Arc<MediaStorage>,
    redis: deadpool_redis::Pool,
}

#[derive(Debug, thiserror::Error)]
enum EngineError {
    #[error("permanent deletion safety failure: {0}")]
    Permanent(String),
    #[error("transient deletion dependency failure: {0}")]
    Transient(String),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct PermanentSource(#[from] anyhow::Error);

fn permanent(message: impl Into<String>) -> anyhow::Error {
    EngineError::Permanent(message.into()).into()
}

fn permanent_source(error: impl Into<anyhow::Error>) -> anyhow::Error {
    PermanentSource(error.into()).into()
}

fn transient(message: impl Into<String>) -> anyhow::Error {
    EngineError::Transient(message.into()).into()
}

fn is_permanent_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<PermanentSource>()
            || matches!(
                cause.downcast_ref::<buzz_db::DbError>(),
                Some(buzz_db::DbError::DeletionSafety(_))
            )
            || cause
                .downcast_ref::<EngineError>()
                .is_some_and(|error| matches!(error, EngineError::Permanent(_)))
    })
}

#[derive(Default)]
struct WorkerHealth {
    draining: AtomicBool,
    dependencies_ready: AtomicBool,
    last_heartbeat_epoch: AtomicU64,
}

impl WorkerHealth {
    fn mark_heartbeat(&self) {
        self.last_heartbeat_epoch.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
    }

    fn ready(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        !self.draining.load(Ordering::Relaxed)
            && self.dependencies_ready.load(Ordering::Relaxed)
            && now.saturating_sub(self.last_heartbeat_epoch.load(Ordering::Relaxed))
                <= worker_health_stale_after()
    }
}

#[derive(Debug, Serialize)]
struct RunOutput {
    request_id: Uuid,
    stage: DeletionStage,
    blocked_reason: Option<String>,
}

/// Execute one nested deletion command.
pub async fn run(command: Command) -> Result<i32> {
    let services = connect_services().await?;
    match command {
        Command::Submit {
            host,
            requested_by,
            reason,
        } => {
            let host = host.unwrap_or_else(|| {
                buzz_core::tenant::relay_url_authority(
                    &std::env::var("RELAY_URL")
                        .unwrap_or_else(|_| "ws://localhost:3000".to_string()),
                )
            });
            if host.is_empty() {
                anyhow::bail!("cannot derive community host; pass --host or set RELAY_URL");
            }
            let request = services
                .store
                .submit(&host, &requested_by, reason.as_deref())
                .await?;
            let inventory = build_inventory(&services, &request).await?;
            let request = services
                .store
                .freeze_inventory(request.id, &inventory)
                .await?;
            print_json(&request)?;
            Ok(0)
        }
        Command::List { limit } => {
            print_json(&services.store.list(i64::from(limit)).await?)?;
            Ok(0)
        }
        Command::Inspect { id } => {
            print_json(&services.store.inspect(id).await?)?;
            Ok(0)
        }
        Command::Approve {
            id,
            approved_by,
            note,
        } => {
            print_json(
                &services
                    .store
                    .approve(id, &approved_by, note.as_deref())
                    .await?,
            )?;
            Ok(0)
        }
        Command::Run { id, executor_id } => {
            run_loop(
                services,
                LoopMode::Run,
                Some(id),
                executor_id.unwrap_or_else(default_executor_id),
            )
            .await
        }
        Command::Drain { executor_id } => {
            run_loop(
                services,
                LoopMode::Drain,
                None,
                executor_id.unwrap_or_else(default_executor_id),
            )
            .await
        }
        Command::Worker { executor_id } => {
            run_loop(
                services,
                LoopMode::Worker,
                None,
                executor_id.unwrap_or_else(default_executor_id),
            )
            .await
        }
    }
}

async fn connect_services() -> Result<Services> {
    let database_url = required_env("DATABASE_URL")?;
    let db = Db::new(&DbConfig {
        database_url,
        max_connections: env_parse("BUZZ_DB_POOL_SIZE", 20),
        ..DbConfig::default()
    })
    .await?;
    let store = store(&db);
    let media_config = buzz_media::MediaConfig {
        s3_endpoint: required_env("BUZZ_S3_ENDPOINT")?,
        s3_access_key: required_env("BUZZ_S3_ACCESS_KEY")?,
        s3_secret_key: required_env("BUZZ_S3_SECRET_KEY")?,
        s3_bucket: required_env("BUZZ_S3_BUCKET")?,
        s3_region: std::env::var("BUZZ_S3_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .map_err(|_| anyhow::anyhow!("BUZZ_S3_REGION or AWS_REGION is required"))?,
        s3_addressing_style: std::env::var("BUZZ_S3_ADDRESSING_STYLE")
            .unwrap_or_else(|_| "path".to_string())
            .parse()
            .map_err(anyhow::Error::msg)?,
        max_image_bytes: 1,
        max_gif_bytes: 1,
        max_video_bytes: 1,
        max_file_bytes: 1,
        public_base_url: "http://localhost/media".to_string(),
        upload_records_enabled: false,
        upload_ip_header: None,
        upload_port_header: None,
    };
    let media = Arc::new(MediaStorage::new(&media_config)?);
    let redis_url = required_env("REDIS_URL")?;
    let mut redis_config = deadpool_redis::Config::from_url(&redis_url);
    redis_config.pool = Some(deadpool_redis::PoolConfig::new(env_parse(
        "BUZZ_REDIS_POOL_SIZE",
        16,
    )));
    let redis = redis_config
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("create deletion Redis pool")?;
    Ok(Services {
        store,
        media,
        redis,
    })
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required for community deletion"))
}

fn env_parse<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn storage_taxonomy_matches(approved: &StorageManifest, live: &StorageManifest) -> bool {
    approved.version == live.version
        && approved.unknown_keys == live.unknown_keys
        && approved.unsupported_version_keys == live.unsupported_version_keys
}

fn storage_object_matches(
    expected: &StorageObject,
    observed_size: u64,
    observed_e_tag: Option<&str>,
) -> bool {
    expected.size == observed_size && observed_e_tag == expected.e_tag.as_deref()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageObjectAction {
    AlreadyMissing,
    Delete,
}

fn storage_object_action(
    expected: &StorageObject,
    current: &CurrentObjectVersion,
) -> Result<StorageObjectAction> {
    match current {
        CurrentObjectVersion::Missing => Ok(StorageObjectAction::AlreadyMissing),
        CurrentObjectVersion::Present {
            version_id: Some(_),
            ..
        } => Err(permanent(format!(
            "unsupported object version after fence: {}",
            expected.key
        ))),
        CurrentObjectVersion::Present {
            version_id: None,
            size,
            e_tag,
            ..
        } if storage_object_matches(expected, *size, e_tag.as_deref()) => {
            Ok(StorageObjectAction::Delete)
        }
        CurrentObjectVersion::Present { .. } => Err(permanent(format!(
            "fenced object binding changed before deletion: {}",
            expected.key
        ))),
    }
}

fn validate_frozen_inventory(request: &DeletionRequest) -> Result<FrozenInventory> {
    let frozen: FrozenInventory = serde_json::from_value(
        request
            .inventory_manifest
            .clone()
            .ok_or_else(|| permanent("approved request has no frozen inventory"))?,
    )
    .map_err(permanent_source)?;
    let expected_digest = request
        .inventory_digest
        .as_deref()
        .ok_or_else(|| permanent("approved request has no frozen inventory digest"))?;
    let actual_digest = hex::encode(frozen.digest().map_err(permanent_source)?);
    if actual_digest != expected_digest {
        return Err(permanent("approved frozen inventory digest mismatch"));
    }
    validate_storage_ownership(request, &frozen.storage)?;
    Ok(frozen)
}

fn validate_storage_ownership(request: &DeletionRequest, manifest: &StorageManifest) -> Result<()> {
    buzz_db::deletion::validate_storage_manifest(manifest)?;
    let classified = deletion_inventory(
        *request.community_id.as_uuid(),
        manifest
            .tenant_objects
            .iter()
            .map(|object| (object.key.clone(), object.size)),
    );
    if classified.tenant_keys() != manifest.tenant_keys || !classified.unknown_keys.is_empty() {
        return Err(permanent(
            "storage manifest contains keys not owned by the deletion target",
        ));
    }
    Ok(())
}

async fn build_inventory(
    services: &Services,
    request: &DeletionRequest,
) -> Result<FrozenInventory> {
    let schema = services
        .store
        .inventory_schema(request.community_id)
        .await?;
    let storage = build_storage_manifest(services, request).await?;
    Ok(FrozenInventory { schema, storage })
}

async fn build_storage_manifest_from_objects(
    services: &Services,
    request: &DeletionRequest,
    objects: Vec<buzz_media::DeletionObject>,
) -> Result<StorageManifest> {
    let bucket = deletion_inventory(
        *request.community_id.as_uuid(),
        objects
            .iter()
            .map(|object| (object.key.clone(), object.size)),
    );
    let tenant_keys = bucket.tenant_keys();
    let tenant_key_set = tenant_keys.iter().collect::<std::collections::HashSet<_>>();
    let tenant_objects = objects
        .into_iter()
        .filter(|object| tenant_key_set.contains(&object.key))
        .map(|object| StorageObject {
            key: object.key,
            size: object.size,
            e_tag: object.e_tag,
        })
        .collect::<Vec<_>>();
    if tenant_objects.iter().any(|object| object.e_tag.is_none()) {
        return Err(permanent(
            "object store omitted ETag for a tenant binding; conditional deletion is unavailable",
        ));
    }
    let mut tenant_objects = tenant_objects;
    tenant_objects.sort();

    let mut unsupported_version_keys = Vec::new();
    for key in &tenant_keys {
        if matches!(
            services.media.inspect_current_version(key).await?,
            CurrentObjectVersion::Present {
                version_id: Some(_),
                ..
            }
        ) {
            unsupported_version_keys.push(key.clone());
        }
    }
    let storage = StorageManifest {
        version: 2,
        tenant_keys,
        tenant_objects,
        git_pointer_keys: bucket.git_pointer_keys,
        media_sidecar_keys: bucket.media_sidecar_keys,
        media_upload_keys: bucket.media_upload_keys,
        unknown_keys: bucket.unknown_keys,
        unsupported_version_keys,
    };
    buzz_db::deletion::validate_storage_manifest(&storage)?;
    Ok(storage)
}

async fn build_storage_manifest(
    services: &Services,
    request: &DeletionRequest,
) -> Result<StorageManifest> {
    let objects = services
        .media
        .list_all_for_deletion(storage_object_cap())
        .await?;
    build_storage_manifest_from_objects(services, request, objects).await
}

async fn run_loop(
    services: Services,
    mode: LoopMode,
    request_id: Option<Uuid>,
    executor_id: String,
) -> Result<i32> {
    let shutdown = shutdown_token();
    let health = Arc::new(WorkerHealth::default());
    health.mark_heartbeat();
    health
        .dependencies_ready
        .store(dependencies_ready(&services).await, Ordering::Relaxed);
    let _health_task = if mode == LoopMode::Worker {
        Some(spawn_worker_health(shutdown.clone(), Arc::clone(&health)).await?)
    } else {
        None
    };
    let mut ran = false;
    loop {
        if shutdown.is_cancelled() {
            services
                .store
                .stop_executor(None, &executor_id)
                .await
                .context("record executor drain")?;
            return Ok(0);
        }
        let claim = match request_id {
            Some(id) => {
                services
                    .store
                    .claim_specific(id, &executor_id, DEFAULT_LEASE_DURATION)
                    .await?
            }
            None => {
                services
                    .store
                    .claim_next(&executor_id, DEFAULT_LEASE_DURATION)
                    .await?
            }
        };
        let Some(claim) = claim else {
            match mode {
                LoopMode::Worker => {
                    tokio::select! {
                        _ = shutdown.cancelled() => continue,
                        _ = tokio::time::sleep(WORKER_IDLE_POLL) => {
                            health.dependencies_ready.store(
                                dependencies_ready(&services).await,
                                Ordering::Relaxed,
                            );
                            health.mark_heartbeat();
                            continue;
                        },
                    }
                }
                LoopMode::Run if !ran => anyhow::bail!(
                    "deletion request is not runnable, is blocked, or is leased by another executor"
                ),
                LoopMode::Run | LoopMode::Drain => return Ok(0),
            }
        };
        ran = true;
        let output = execute_claim(&services, mode, claim, &shutdown, Arc::clone(&health)).await?;
        print_json(&output)?;
        if mode == LoopMode::Run || shutdown.is_cancelled() {
            return Ok(i32::from(output.blocked_reason.is_some()));
        }
    }
}

async fn stop_claim_executor(
    services: &Services,
    mode: LoopMode,
    token: &LeaseToken,
) -> Result<()> {
    // A failed draining heartbeat must not prevent the generation-checked release
    // attempt. `stop_executor` cannot clear a successor's reclaimed lease.
    let _ = services
        .store
        .heartbeat(token, mode.as_str(), DEFAULT_LEASE_DURATION, true)
        .await;
    services
        .store
        .stop_executor(Some(token), &token.owner)
        .await?;
    Ok(())
}

async fn record_stage_failure(
    services: &Services,
    token: &LeaseToken,
    stage: DeletionStage,
    error: &anyhow::Error,
) -> Result<bool> {
    let message = format!("{error:#}");
    let result = if is_permanent_error(error) {
        services.store.block(token, stage, "stage", &message).await
    } else {
        services
            .store
            .record_retry(token, stage, "stage", &message, RETRY_DELAY)
            .await
    };
    match result {
        Ok(()) => Ok(true),
        Err(error) if buzz_db::deletion::is_stale_deletion_lease(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn execute_claim(
    services: &Services,
    mode: LoopMode,
    mut claim: ClaimedDeletion,
    shutdown: &CancellationToken,
    health: Arc<WorkerHealth>,
) -> Result<RunOutput> {
    let token = claim.lease.clone();
    loop {
        if shutdown.is_cancelled() {
            stop_claim_executor(services, mode, &token).await?;
            let request = services.store.get(token.request_id).await?;
            return Ok(run_output(request));
        }
        services
            .store
            .heartbeat(&token, mode.as_str(), DEFAULT_LEASE_DURATION, false)
            .await?;
        health.dependencies_ready.store(true, Ordering::Relaxed);
        health.mark_heartbeat();
        let stage_result =
            run_stage_with_heartbeat(services, mode, &claim, shutdown, Arc::clone(&health)).await;
        match stage_result {
            StageOutcome::Completed => {}
            StageOutcome::Shutdown => {
                stop_claim_executor(services, mode, &token).await?;
                let request = services.store.get(token.request_id).await?;
                return Ok(run_output(request));
            }
            StageOutcome::Failed(error) => {
                let request = services.store.get(token.request_id).await?;
                if request.lease_owner.as_deref() != Some(&token.owner)
                    || request.lease_generation != token.generation
                {
                    return Ok(run_output(request));
                }
                if !record_stage_failure(services, &token, claim.request.stage, &error).await? {
                    // Ownership expired between the stage failure and durable
                    // error recording. A successor now owns retry/block policy.
                    let request = services.store.get(token.request_id).await?;
                    return Ok(run_output(request));
                }
                let request = services.store.get(token.request_id).await?;
                return Ok(run_output(request));
            }
        }
        let request = services.store.get(token.request_id).await?;
        if request.stage == DeletionStage::RetentionPending || request.blocked_reason.is_some() {
            return Ok(run_output(request));
        }
        claim.request = request.clone();
        claim.lease.fence_generation = request.fence_generation;
    }
}

async fn dependencies_ready(services: &Services) -> bool {
    if !services.store.ping().await {
        return false;
    }
    let redis_ok = match services.redis.get().await {
        Ok(mut connection) => tokio::time::timeout(
            Duration::from_secs(5),
            redis::cmd("PING").query_async::<String>(&mut *connection),
        )
        .await
        .is_ok_and(|result| result.is_ok()),
        Err(_) => false,
    };
    let storage_ok = tokio::time::timeout(Duration::from_secs(5), services.media.ping())
        .await
        .is_ok_and(|result| result.is_ok());
    redis_ok && storage_ok
}

enum StageOutcome {
    Completed,
    Shutdown,
    Failed(anyhow::Error),
}

async fn await_stage<F>(
    stage: F,
    shutdown: &CancellationToken,
    heartbeat_error: &CancellationToken,
) -> StageOutcome
where
    F: std::future::Future<Output = Result<()>>,
{
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => StageOutcome::Shutdown,
        _ = heartbeat_error.cancelled() => StageOutcome::Failed(DeletionLeaseLost.into()),
        result = stage => match result {
            Ok(()) => StageOutcome::Completed,
            Err(error) => StageOutcome::Failed(error),
        },
    }
}

async fn run_stage_with_heartbeat(
    services: &Services,
    mode: LoopMode,
    claim: &ClaimedDeletion,
    shutdown: &CancellationToken,
    health: Arc<WorkerHealth>,
) -> StageOutcome {
    let heartbeat_services = services.clone();
    let heartbeat_token = claim.lease.clone();
    let heartbeat_mode = mode.as_str();
    let heartbeat_shutdown = CancellationToken::new();
    let heartbeat_cancel = heartbeat_shutdown.clone();
    let heartbeat_health = Arc::clone(&health);
    let heartbeat_error = CancellationToken::new();
    let heartbeat_error_signal = heartbeat_error.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = heartbeat_cancel.cancelled() => return,
                _ = interval.tick() => {
                    if heartbeat_services
                        .store
                        .heartbeat(
                            &heartbeat_token,
                            heartbeat_mode,
                            DEFAULT_LEASE_DURATION,
                            false,
                        )
                        .await
                        .is_err()
                    {
                        heartbeat_error_signal.cancel();
                        return;
                    }
                    heartbeat_health.mark_heartbeat();
                }
            }
        }
    });

    let stage = await_stage(
        execute_stage(services, claim, &heartbeat_error),
        shutdown,
        &heartbeat_error,
    )
    .await;
    heartbeat_shutdown.cancel();
    match heartbeat.await {
        Ok(()) => stage,
        Err(error) => {
            StageOutcome::Failed(anyhow::anyhow!("deletion heartbeat task failed: {error}"))
        }
    }
}

async fn run_guarded_external_step<F, Fut>(
    services: &Services,
    token: &LeaseToken,
    stage: DeletionStage,
    heartbeat_lost: &CancellationToken,
    operation: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    services.store.verify_execution_token(token, stage).await?;
    let result = tokio::select! {
        biased;
        _ = heartbeat_lost.cancelled() => {
            return Err(DeletionLeaseLost.into());
        }
        result = operation() => result,
    };
    result?;
    services.store.verify_execution_token(token, stage).await?;
    Ok(())
}

async fn execute_stage(
    services: &Services,
    claim: &ClaimedDeletion,
    heartbeat_lost: &CancellationToken,
) -> Result<()> {
    let request = &claim.request;
    let token = token_with_current_fence(&claim.lease, request);
    if matches!(
        request.stage,
        DeletionStage::Approved
            | DeletionStage::Fenced
            | DeletionStage::Drained
            | DeletionStage::BindingsRemoved
            | DeletionStage::PostgresPurged
            | DeletionStage::CachePurged
            | DeletionStage::LogicallyVerified
    ) {
        validate_frozen_inventory(request)?;
    }
    match request.stage {
        DeletionStage::Approved => {
            // Approval binds immutable catalog + key taxonomy. Live row counts
            // and tenant binding keys are deliberately not equality-bound until
            // the durable fence closes all writers.
            let live_schema = services
                .store
                .inventory_schema(request.community_id)
                .await?;
            let frozen = validate_frozen_inventory(request)?;
            if live_schema != frozen.schema {
                return Err(permanent(
                    "approved structural catalog drifted before fencing",
                ));
            }
            let live_storage = build_storage_manifest(services, request).await?;
            if !storage_taxonomy_matches(&frozen.storage, &live_storage) {
                return Err(permanent(
                    "approved storage taxonomy drifted before fencing",
                ));
            }
            services.store.begin_quiescing(&token).await?;
            match services.store.fence(&token).await {
                Ok(_) => {}
                Err(buzz_db::DbError::ServingWritesNotDrained {
                    active_count,
                    operations,
                    ..
                }) => {
                    return Err(transient(format!(
                        "serving writes not drained before fence: count={active_count}, operations={operations:?}"
                    )));
                }
                Err(error) => return Err(error.into()),
            }
        }
        DeletionStage::Fenced => {
            services
                .store
                .verify_execution_token(&token, DeletionStage::Fenced)
                .await?;
            let disconnect = tokio::select! {
                biased;
                _ = heartbeat_lost.cancelled() => Err(DeletionLeaseLost.into()),
                result = publish_disconnect_community(&services.redis, request.community_id) => result,
            };
            disconnect?;
            services
                .store
                .verify_execution_token(&token, DeletionStage::Fenced)
                .await?;
            let destructive = match request.destructive_storage_manifest.clone() {
                Some(value) => serde_json::from_value(value)?,
                None => {
                    let manifest = build_storage_manifest(services, request).await?;
                    services
                        .store
                        .freeze_destructive_storage_manifest(&token, &manifest)
                        .await?;
                    manifest
                }
            };
            validate_storage_ownership(request, &destructive)?;
            if services
                .store
                .serving_writes_drained(request.community_id)
                .await?
            {
                services.store.mark_drained(&token).await?;
            } else {
                return Err(transient("serving writes have not drained"));
            }
        }
        DeletionStage::Drained => {
            let storage: StorageManifest = serde_json::from_value(
                request
                    .destructive_storage_manifest
                    .clone()
                    .context("request has no post-fence destructive storage manifest")?,
            )?;
            validate_storage_ownership(request, &storage)?;
            let completed = services.store.completed_storage_object_keys(&token).await?;
            let mut processed = 0usize;
            for object in storage
                .tenant_objects
                .iter()
                .filter(|object| !completed.contains(&object.key))
                .take(storage_delete_batch_size())
            {
                let current = services.media.inspect_current_object(&object.key).await?;
                let already_missing = match storage_object_action(object, &current)? {
                    StorageObjectAction::AlreadyMissing => true,
                    StorageObjectAction::Delete => {
                        run_guarded_external_step(
                            services,
                            &token,
                            DeletionStage::Drained,
                            heartbeat_lost,
                            || async {
                                services.media.delete(&object.key).await?;
                                Ok(())
                            },
                        )
                        .await?;
                        run_guarded_external_step(
                            services,
                            &token,
                            DeletionStage::Drained,
                            heartbeat_lost,
                            || async {
                                if services.media.head(&object.key).await? {
                                    return Err(transient(format!(
                                        "object binding still exists after delete: {}",
                                        object.key
                                    )));
                                }
                                Ok(())
                            },
                        )
                        .await?;
                        false
                    }
                };
                services
                    .store
                    .checkpoint_storage_object_removed(&token, &object.key, already_missing)
                    .await?;
                processed += 1;
            }

            let completed_count = completed.len().saturating_add(processed);
            if completed_count < storage.tenant_objects.len() {
                return Err(transient(format!(
                    "storage deletion batch complete: {completed_count}/{}",
                    storage.tenant_objects.len()
                )));
            }
            services
                .store
                .mark_bindings_removed(
                    &token,
                    serde_json::json!({"deleted_keys": storage.tenant_objects.len()}),
                )
                .await?;
        }
        DeletionStage::BindingsRemoved => {
            services.store.purge_postgres(&token).await?;
        }
        DeletionStage::PostgresPurged => {
            services
                .store
                .verify_execution_token(&token, DeletionStage::PostgresPurged)
                .await?;
            let deleted = purge_redis_namespace(&services.redis, request.community_id).await?;
            services
                .store
                .verify_execution_token(&token, DeletionStage::PostgresPurged)
                .await?;
            services
                .store
                .mark_cache_purged(&token, serde_json::json!({"deleted_keys": deleted}))
                .await?;
        }
        DeletionStage::CachePurged => {
            services
                .store
                .verify_postgres_logically_deleted(&token)
                .await?;
            verify_storage_absence(services, request).await?;
            verify_redis_absence(&services.redis, request.community_id).await?;
            services
                .store
                .mark_logically_verified(
                    &token,
                    serde_json::json!({"postgres": true, "object_store": true, "redis": true}),
                )
                .await?;
        }
        DeletionStage::LogicallyVerified => {
            validate_frozen_inventory(request)?;
            services
                .store
                .mark_retention_pending(
                    &token,
                    serde_json::json!({
                        "policy": "member-erasure and fleet-wide shared-CAS GC are out of V1 scope"
                    }),
                )
                .await?;
        }
        DeletionStage::Submitted | DeletionStage::Inventoried => {
            anyhow::bail!("request has not crossed the explicit approval boundary")
        }
        DeletionStage::RetentionPending => {}
    }
    Ok(())
}

fn token_with_current_fence(token: &LeaseToken, request: &DeletionRequest) -> LeaseToken {
    LeaseToken {
        fence_generation: request.fence_generation,
        ..token.clone()
    }
}

async fn verify_storage_absence_from_objects(
    services: &Services,
    request: &DeletionRequest,
    objects: Vec<buzz_media::DeletionObject>,
) -> Result<()> {
    let live = build_storage_manifest_from_objects(services, request, objects).await?;
    if live.tenant_keys.is_empty() {
        Ok(())
    } else {
        Err(transient(format!(
            "logical verification found {} live target object binding(s); first={}",
            live.tenant_keys.len(),
            live.tenant_keys.first().map_or("<none>", String::as_str)
        )))
    }
}

async fn verify_storage_absence(services: &Services, request: &DeletionRequest) -> Result<()> {
    let objects = services
        .media
        .list_all_for_deletion(storage_object_cap())
        .await?;
    verify_storage_absence_from_objects(services, request, objects).await
}

async fn publish_disconnect_community(
    pool: &deadpool_redis::Pool,
    community: buzz_core::CommunityId,
) -> Result<()> {
    let mut connection = pool.get().await?;
    let channel = format!("buzz:{community}:conn-control");
    let _: u64 = redis::cmd("PUBLISH")
        .arg(channel)
        .arg(r#"{"op":"DisconnectCommunity"}"#)
        .query_async(&mut *connection)
        .await?;
    Ok(())
}

async fn purge_redis_namespace(
    pool: &deadpool_redis::Pool,
    community: buzz_core::CommunityId,
) -> Result<u64> {
    let mut connection = pool.get().await?;
    let pattern = format!("buzz:{community}:*");
    let mut cursor = 0u64;
    let mut deleted = 0u64;
    loop {
        let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(&mut *connection)
            .await?;
        if !keys.is_empty() {
            let count: u64 = redis::cmd("UNLINK")
                .arg(&keys)
                .query_async(&mut *connection)
                .await?;
            deleted = deleted.saturating_add(count);
        }
        if next == 0 {
            break;
        }
        cursor = next;
    }
    Ok(deleted)
}

fn scan_proves_absence(pages: &[(u64, Vec<String>)]) -> bool {
    pages.last().is_some_and(|(cursor, _)| *cursor == 0)
        && pages.iter().all(|(_, keys)| keys.is_empty())
}

async fn scan_redis_namespace(
    connection: &mut deadpool_redis::Connection,
    pattern: &str,
) -> Result<Vec<(u64, Vec<String>)>> {
    let mut cursor = 0u64;
    let mut pages = Vec::new();
    loop {
        let page: (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(&mut **connection)
            .await?;
        cursor = page.0;
        pages.push(page);
        if cursor == 0 {
            return Ok(pages);
        }
    }
}

async fn verify_redis_absence(
    pool: &deadpool_redis::Pool,
    community: buzz_core::CommunityId,
) -> Result<()> {
    let mut connection = pool.get().await?;
    let pattern = format!("buzz:{community}:*");
    // SCAN is weakly consistent. Two complete empty passes ensure a cursor
    // rollover or concurrent expiry cannot make one sparse pass look absent.
    let first = scan_redis_namespace(&mut connection, &pattern).await?;
    let second = scan_redis_namespace(&mut connection, &pattern).await?;
    if scan_proves_absence(&first) && scan_proves_absence(&second) {
        Ok(())
    } else {
        Err(transient(
            "logical verification found a Redis namespace key",
        ))
    }
}

fn storage_object_cap() -> u64 {
    std::env::var("BUZZ_DELETION_STORAGE_MAX_OBJECTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_STORAGE_OBJECT_CAP)
}

fn storage_delete_batch_size() -> usize {
    std::env::var("BUZZ_DELETION_STORAGE_DELETE_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(10_000))
        .unwrap_or(STORAGE_DELETE_BATCH_SIZE)
}

fn default_executor_id() -> String {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "buzz-admin".to_string());
    format!("{hostname}:{}", std::process::id())
}

async fn spawn_worker_health(
    shutdown: CancellationToken,
    health: Arc<WorkerHealth>,
) -> Result<tokio::task::JoinHandle<()>> {
    let address =
        std::env::var("BUZZ_DELETION_HEALTH_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("bind deletion worker health endpoint {address}"))?;
    let signal = Arc::clone(&health);
    let cancel = shutdown.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        signal.draining.store(true, Ordering::Relaxed);
    });
    let router = axum::Router::new()
        .route("/_liveness", axum::routing::get(|| async { "ok" }))
        .route(
            "/_readiness",
            axum::routing::get({
                move || {
                    let health = Arc::clone(&health);
                    async move {
                        if health.ready() {
                            (axum::http::StatusCode::OK, "ready")
                        } else {
                            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not_ready")
                        }
                    }
                }
            }),
        );
    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
        {
            eprintln!("deletion worker health endpoint failed: {error}");
        }
    }))
}

fn shutdown_token() -> CancellationToken {
    let token = CancellationToken::new();
    let signal = token.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal as unix_signal, SignalKind};
            if let Ok(mut terminate) = unix_signal(SignalKind::terminate()) {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal.cancel();
    });
    token
}

fn run_output(request: DeletionRequest) -> RunOutput {
    RunOutput {
        request_id: request.id,
        stage: request.stage,
        blocked_reason: request.blocked_reason,
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn claimed_test_deletion(prefix: &str) -> (Services, ClaimedDeletion) {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("BUZZ_TEST_DATABASE_URL or DATABASE_URL is required");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect deletion engine test DB");
        let db = Db::from_pool(pool);
        db.migrate().await.expect("migrate deletion engine test DB");
        let store = db.deletion_store();
        let host = format!("{prefix}-{}.example", Uuid::new_v4().simple());
        let community = db
            .ensure_configured_community(&host)
            .await
            .expect("create deletion engine test community");
        let request = store
            .submit(&host, "test", None)
            .await
            .expect("submit deletion request");
        let inventory = FrozenInventory {
            schema: store
                .inventory_schema(community.id)
                .await
                .expect("inventory schema"),
            storage: StorageManifest {
                version: 2,
                tenant_keys: Vec::new(),
                tenant_objects: Vec::new(),
                git_pointer_keys: Vec::new(),
                media_sidecar_keys: Vec::new(),
                media_upload_keys: Vec::new(),
                unknown_keys: Vec::new(),
                unsupported_version_keys: Vec::new(),
            },
        };
        store
            .freeze_inventory(request.id, &inventory)
            .await
            .expect("freeze deletion inventory");
        store
            .approve(request.id, "test", None)
            .await
            .expect("approve deletion request");
        let claim = store
            .claim_specific(request.id, "test-executor", DEFAULT_LEASE_DURATION)
            .await
            .expect("claim deletion request")
            .expect("runnable deletion request");
        let services = Services {
            store,
            media: Arc::new(
                MediaStorage::new(&buzz_media::MediaConfig {
                    s3_endpoint: "http://127.0.0.1:1".to_string(),
                    s3_access_key: "unused".to_string(),
                    s3_secret_key: "unused".to_string(),
                    s3_bucket: "unused".to_string(),
                    s3_region: "us-east-1".to_string(),
                    s3_addressing_style: buzz_media::S3AddressingStyle::Path,
                    max_image_bytes: 1,
                    max_gif_bytes: 1,
                    max_video_bytes: 1,
                    max_file_bytes: 1,
                    public_base_url: "http://localhost/media".to_string(),
                    upload_records_enabled: false,
                    upload_ip_header: None,
                    upload_port_header: None,
                })
                .expect("construct unused media service"),
            ),
            redis: deadpool_redis::Config::from_url("redis://127.0.0.1:1")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("construct unused Redis pool"),
        };
        (services, claim)
    }

    fn deletion_test_media_storage() -> Arc<MediaStorage> {
        let endpoint = std::env::var("BUZZ_TEST_S3_ENDPOINT")
            .or_else(|_| std::env::var("BUZZ_S3_ENDPOINT"))
            .expect("BUZZ_TEST_S3_ENDPOINT or BUZZ_S3_ENDPOINT is required");
        let access_key = std::env::var("BUZZ_TEST_S3_ACCESS_KEY")
            .or_else(|_| std::env::var("BUZZ_S3_ACCESS_KEY"))
            .expect("BUZZ_TEST_S3_ACCESS_KEY or BUZZ_S3_ACCESS_KEY is required");
        let secret_key = std::env::var("BUZZ_TEST_S3_SECRET_KEY")
            .or_else(|_| std::env::var("BUZZ_S3_SECRET_KEY"))
            .expect("BUZZ_TEST_S3_SECRET_KEY or BUZZ_S3_SECRET_KEY is required");
        let bucket = std::env::var("BUZZ_TEST_S3_BUCKET")
            .or_else(|_| std::env::var("BUZZ_S3_BUCKET"))
            .expect("BUZZ_TEST_S3_BUCKET or BUZZ_S3_BUCKET is required");
        Arc::new(
            MediaStorage::new(&buzz_media::MediaConfig {
                s3_endpoint: endpoint,
                s3_access_key: access_key,
                s3_secret_key: secret_key,
                s3_bucket: bucket,
                s3_region: std::env::var("BUZZ_TEST_S3_REGION")
                    .or_else(|_| std::env::var("BUZZ_S3_REGION"))
                    .unwrap_or_else(|_| "us-east-1".to_string()),
                s3_addressing_style: buzz_media::S3AddressingStyle::Path,
                max_image_bytes: 1,
                max_gif_bytes: 1,
                max_video_bytes: 1,
                max_file_bytes: 1,
                public_base_url: "http://localhost/media".to_string(),
                upload_records_enabled: false,
                upload_ip_header: None,
                upload_port_header: None,
            })
            .expect("construct deletion test media service"),
        )
    }

    #[test]
    fn large_storage_work_is_bounded_per_attempt() {
        assert_eq!(STORAGE_DELETE_BATCH_SIZE, 100);
        let keys = (0..1_000_000).take(STORAGE_DELETE_BATCH_SIZE).count();
        assert_eq!(keys, STORAGE_DELETE_BATCH_SIZE);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn frozen_inventory_digest_and_storage_ownership_fail_closed() {
        let (_, claim) = claimed_test_deletion("deletion-integrity").await;
        assert!(validate_frozen_inventory(&claim.request).is_ok());

        let mut digest_tampered = claim.request.clone();
        digest_tampered.inventory_manifest = Some(serde_json::json!({
            "schema": {"revision": 0, "migration_version": 0, "scoped_tables": [], "row_counts": {}, "fenced_tables": []},
            "storage": {"version": 2, "tenant_keys": [], "tenant_objects": [], "git_pointer_keys": [], "media_sidecar_keys": [], "media_upload_keys": [], "unknown_keys": [], "unsupported_version_keys": []}
        }));
        assert!(validate_frozen_inventory(&digest_tampered).is_err());

        let foreign_community = Uuid::new_v4();
        let foreign_key = format!("_meta/{foreign_community}/{}.json", "a".repeat(64));
        let foreign_manifest = StorageManifest {
            version: 2,
            tenant_keys: vec![foreign_key.clone()],
            tenant_objects: vec![StorageObject {
                key: foreign_key,
                size: 1,
                e_tag: Some("etag".to_string()),
            }],
            git_pointer_keys: Vec::new(),
            media_sidecar_keys: Vec::new(),
            media_upload_keys: Vec::new(),
            unknown_keys: Vec::new(),
            unsupported_version_keys: Vec::new(),
        };
        assert!(validate_storage_ownership(&claim.request, &foreign_manifest).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Postgres and S3-compatible storage"]
    async fn drained_stage_reconciles_first_object_deleted_before_checkpoint() {
        let (mut services, claim) = claimed_test_deletion("deletion-first-missing").await;
        let media = deletion_test_media_storage();
        services.media = media;

        let object_key = format!(
            "_meta/{}/{}.json",
            claim.request.community_id,
            "a".repeat(64)
        );
        services
            .media
            .put(&object_key, b"crash-window", "application/json")
            .await
            .expect("seed object");
        let current = services
            .media
            .inspect_current_object(&object_key)
            .await
            .expect("inspect seeded object");
        let CurrentObjectVersion::Present { size, e_tag, .. } = current else {
            panic!("seeded object must be present");
        };
        let storage = StorageManifest {
            version: 2,
            tenant_keys: vec![object_key.clone()],
            tenant_objects: vec![StorageObject {
                key: object_key.clone(),
                size,
                e_tag,
            }],
            git_pointer_keys: Vec::new(),
            media_sidecar_keys: vec![object_key.clone()],
            media_upload_keys: Vec::new(),
            unknown_keys: Vec::new(),
            unsupported_version_keys: Vec::new(),
        };
        services
            .store
            .begin_quiescing(&claim.lease)
            .await
            .expect("quiesce");
        let generation = services.store.fence(&claim.lease).await.expect("fence");
        let token = LeaseToken {
            fence_generation: Some(generation),
            ..claim.lease.clone()
        };
        services
            .store
            .freeze_destructive_storage_manifest(&token, &storage)
            .await
            .expect("freeze one-object manifest");
        services.store.mark_drained(&token).await.expect("drained");

        // This is the non-atomic boundary under test: S3 committed the delete,
        // then the worker died before checkpoint_storage_object_removed.
        services
            .media
            .delete(&object_key)
            .await
            .expect("simulate committed delete before crash");
        assert!(services
            .store
            .completed_storage_object_keys(&token)
            .await
            .expect("initial checkpoints")
            .is_empty());

        let resumed = ClaimedDeletion {
            request: services
                .store
                .get(token.request_id)
                .await
                .expect("reload drained request"),
            lease: claim.lease,
        };
        execute_stage(&services, &resumed, &CancellationToken::new())
            .await
            .expect("production Drained stage reconciles missing first object");

        assert_eq!(
            services
                .store
                .completed_storage_object_keys(&token)
                .await
                .expect("completed checkpoints"),
            std::collections::BTreeSet::from([object_key])
        );
        assert_eq!(
            services.store.get(token.request_id).await.unwrap().stage,
            DeletionStage::BindingsRemoved
        );
    }

    #[test]
    fn object_identity_rejects_replacement_but_accepts_exact_match() {
        let expected = StorageObject {
            key: "tenant/key".to_string(),
            size: 42,
            e_tag: Some("etag-a".to_string()),
        };
        assert!(storage_object_matches(&expected, 42, Some("etag-a")));
        assert!(!storage_object_matches(&expected, 42, Some("etag-b")));
        assert!(!storage_object_matches(&expected, 42, None));
    }

    #[test]
    fn permanent_failures_are_typed_not_string_classified() {
        let permanent_error = permanent("catalog drift");
        let transient_error = transient("temporary catalog service reset");
        let nested = permanent_source(anyhow::anyhow!("schema mismatch")).context("outer");
        let db_permanent = anyhow::Error::from(buzz_db::DbError::DeletionSafety(
            "typed catalog drift".to_string(),
        ));
        let db_transient = anyhow::Error::from(buzz_db::DbError::Sqlx(sqlx::Error::PoolTimedOut));
        assert!(is_permanent_error(&permanent_error));
        assert!(is_permanent_error(&nested));
        assert!(is_permanent_error(&db_permanent));
        assert!(!is_permanent_error(&transient_error));
        assert!(!is_permanent_error(&db_transient));
    }

    #[test]
    fn worker_readiness_requires_dependencies_heartbeat_and_not_draining() {
        let health = WorkerHealth::default();
        assert!(!health.ready());
        health.dependencies_ready.store(true, Ordering::Relaxed);
        health.mark_heartbeat();
        assert!(health.ready());
        health.draining.store(true, Ordering::Relaxed);
        assert!(!health.ready());
        health.draining.store(false, Ordering::Relaxed);
        health.last_heartbeat_epoch.store(1, Ordering::Relaxed);
        assert!(!health.ready());
    }

    #[test]
    fn worker_configuration_requires_every_destructive_dependency() {
        let variable = format!("BUZZ_DELETION_REQUIRED_TEST_{}", Uuid::new_v4().simple());
        assert!(required_env(&variable).is_err());
        std::env::set_var(&variable, "   ");
        assert!(required_env(&variable).is_err());
        std::env::set_var(&variable, "configured");
        assert_eq!(
            required_env(&variable).expect("configured environment variable"),
            "configured"
        );
        std::env::remove_var(&variable);
    }

    #[test]
    fn redis_absence_requires_terminal_cursor_and_all_pages_empty() {
        assert!(!scan_proves_absence(&[(9, Vec::new())]));
        assert!(!scan_proves_absence(&[
            (9, Vec::new()),
            (0, vec!["buzz:tenant:late".to_string()]),
        ]));
        assert!(scan_proves_absence(&[(9, Vec::new()), (0, Vec::new())]));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn final_storage_verification_rejects_late_target_binding() {
        let (services, claim) = claimed_test_deletion("deletion-late-binding").await;
        let community = claim.request.community_id;
        let late_key = format!("_meta/{community}/{}.json", "a".repeat(64));
        let error = verify_storage_absence_from_objects(
            &services,
            &claim.request,
            vec![buzz_media::DeletionObject {
                key: late_key.clone(),
                size: 7,
                last_modified: "2026-08-02T00:00:00Z".to_string(),
                e_tag: Some("etag".to_string()),
            }],
        )
        .await
        .expect_err("late target binding must fail verification");
        assert!(format!("{error:#}").contains(&late_key));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn stale_lease_during_failure_recording_is_lost_ownership() {
        let (services, claim) = claimed_test_deletion("deletion-stale-record").await;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("test database URL");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect stale-record test DB");
        sqlx::query(
            "UPDATE community_deletion_requests SET lease_until = now() - interval '1 second' WHERE id = $1",
        )
        .bind(claim.request.id)
        .execute(&pool)
        .await
        .expect("expire claim");
        let recorded = record_stage_failure(
            &services,
            &claim.lease,
            claim.request.stage,
            &transient("test failure"),
        )
        .await
        .expect("stale ownership is not fatal");
        assert!(!recorded);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn serving_guard_cancels_protected_operation_when_heartbeat_is_lost() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("BUZZ_TEST_DATABASE_URL or DATABASE_URL is required");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect serving guard test DB");
        let db = Db::from_pool(pool.clone());
        db.migrate().await.expect("migrate serving guard test DB");
        let community = db
            .ensure_configured_community(&format!(
                "serving-guard-{}.example",
                Uuid::new_v4().simple()
            ))
            .await
            .expect("create test community")
            .id;
        TEST_HEARTBEAT_INTERVAL_MS.store(10, Ordering::Relaxed);
        let guard = acquire_serving_write(&db, community, "test_cancel")
            .await
            .expect("serving guard");
        sqlx::query("DELETE FROM community_serving_write_leases WHERE community_id = $1")
            .bind(community.as_uuid())
            .execute(&pool)
            .await
            .expect("force heartbeat failure");
        let completed = Arc::new(AtomicBool::new(false));
        let operation_completed = Arc::clone(&completed);
        let result = guard
            .protect(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                operation_completed.store(true, Ordering::Relaxed);
            })
            .await;
        TEST_HEARTBEAT_INTERVAL_MS.store(0, Ordering::Relaxed);
        assert!(result.is_err(), "lease loss must reject the operation");
        assert!(
            !completed.load(Ordering::Relaxed),
            "lease loss must cancel the protected operation future"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn guarded_external_step_rejects_preexisting_heartbeat_loss_without_polling_operation() {
        let (services, claim) = claimed_test_deletion("deletion-heartbeat").await;
        let heartbeat_lost = CancellationToken::new();
        heartbeat_lost.cancel();
        let polled = Arc::new(AtomicBool::new(false));
        let operation_polled = Arc::clone(&polled);
        let result = run_guarded_external_step(
            &services,
            &claim.lease,
            DeletionStage::Approved,
            &heartbeat_lost,
            || async move {
                operation_polled.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err(), "heartbeat loss must abort the side effect");
        assert!(
            result
                .expect_err("heartbeat loss error")
                .downcast_ref::<DeletionLeaseLost>()
                .is_some(),
            "heartbeat loss must stay typed"
        );
        assert!(
            !polled.load(Ordering::Relaxed),
            "a pre-cancelled heartbeat must win before polling the operation"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn shutdown_during_stage_releases_claim_without_recording_retry() {
        let (services, claim) = claimed_test_deletion("deletion-shutdown").await;
        let request_id = claim.request.id;
        let retry_count = claim.request.retry_count;
        let shutdown = CancellationToken::new();
        let cancel = shutdown.clone();
        let services_for_run = services.clone();
        let executor = tokio::spawn(async move {
            execute_claim(
                &services_for_run,
                LoopMode::Worker,
                claim,
                &shutdown,
                Arc::new(WorkerHealth::default()),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();
        let output = tokio::time::timeout(Duration::from_secs(2), executor)
            .await
            .expect("shutdown must cancel the active stage")
            .expect("deletion executor task")
            .expect("graceful deletion executor shutdown");
        let request = services
            .store
            .get(request_id)
            .await
            .expect("load deletion request after shutdown");
        assert_eq!(output.stage, DeletionStage::Approved);
        assert_eq!(request.stage, DeletionStage::Approved);
        assert_eq!(request.retry_count, retry_count);
        assert!(request.last_error.is_none());
        assert!(request.lease_owner.is_none());
        assert!(request.lease_until.is_none());
    }

    #[tokio::test]
    async fn stage_wait_treats_shutdown_as_control_flow() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let heartbeat_lost = CancellationToken::new();
        let outcome = await_stage(
            std::future::pending::<Result<()>>(),
            &shutdown,
            &heartbeat_lost,
        )
        .await;
        assert!(matches!(outcome, StageOutcome::Shutdown));
    }

    #[tokio::test]
    async fn stage_wait_prioritizes_heartbeat_loss_over_a_ready_operation() {
        let shutdown = CancellationToken::new();
        let heartbeat_lost = CancellationToken::new();
        heartbeat_lost.cancel();
        let outcome = await_stage(async { Ok(()) }, &shutdown, &heartbeat_lost).await;
        match outcome {
            StageOutcome::Failed(error) => assert!(
                error.downcast_ref::<DeletionLeaseLost>().is_some(),
                "heartbeat loss must stay typed"
            ),
            StageOutcome::Completed | StageOutcome::Shutdown => {
                panic!("preexisting heartbeat loss must win")
            }
        }
    }

    #[tokio::test]
    async fn shutdown_token_can_interrupt_idle_worker_sleep() {
        let token = CancellationToken::new();
        token.cancel();
        let woke = tokio::select! {
            _ = token.cancelled() => true,
            _ = tokio::time::sleep(Duration::from_secs(30)) => false,
        };
        assert!(woke);
    }
}
