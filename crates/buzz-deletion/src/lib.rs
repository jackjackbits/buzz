#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Shared durable whole-community deletion engine and store adapters.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use buzz_db::deletion::{
    ClaimedDeletion, DeletionRequest, DeletionStage, DeletionStore, FrozenInventory, LeaseToken,
    StorageManifest, DEFAULT_LEASE_DURATION,
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

/// Return the shared durable deletion store for relay and operator paths.
pub fn store(db: &Db) -> DeletionStore {
    db.deletion_store()
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

struct Services {
    store: DeletionStore,
    media: Arc<MediaStorage>,
    redis: deadpool_redis::Pool,
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
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_string());
    let db = Db::new(&DbConfig {
        database_url,
        max_connections: env_parse("BUZZ_DB_POOL_SIZE", 20),
        ..DbConfig::default()
    })
    .await?;
    let store = store(&db);
    let media_config = buzz_media::MediaConfig {
        s3_endpoint: std::env::var("BUZZ_S3_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9000".to_string()),
        s3_access_key: std::env::var("BUZZ_S3_ACCESS_KEY")
            .unwrap_or_else(|_| "buzz_dev".to_string()),
        s3_secret_key: std::env::var("BUZZ_S3_SECRET_KEY")
            .unwrap_or_else(|_| "buzz_dev_secret".to_string()),
        s3_bucket: std::env::var("BUZZ_S3_BUCKET").unwrap_or_else(|_| "buzz-media".to_string()),
        s3_region: std::env::var("BUZZ_S3_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_string()),
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
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
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

fn env_parse<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
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

async fn build_storage_manifest(
    services: &Services,
    request: &DeletionRequest,
) -> Result<StorageManifest> {
    let max_objects = storage_object_cap();
    let objects = services.media.list_all_for_deletion(max_objects).await?;
    let bucket = deletion_inventory(
        *request.community_id.as_uuid(),
        objects
            .iter()
            .map(|object| (object.key.clone(), object.size)),
    );
    let mut unsupported_version_keys = Vec::new();
    for key in bucket.tenant_keys() {
        if matches!(
            services.media.inspect_current_version(&key).await?,
            CurrentObjectVersion::Present {
                version_id: Some(_)
            }
        ) {
            unsupported_version_keys.push(key);
        }
    }
    let storage = StorageManifest {
        version: 1,
        tenant_keys: bucket.tenant_keys(),
        git_pointer_keys: bucket.git_pointer_keys,
        media_sidecar_keys: bucket.media_sidecar_keys,
        media_upload_keys: bucket.media_upload_keys,
        retained_shared_cas_keys: bucket.retained_shared_cas_keys,
        unknown_keys: bucket.unknown_keys,
        unsupported_version_keys,
    };
    buzz_db::deletion::validate_storage_manifest(&storage)?;
    Ok(storage)
}

async fn run_loop(
    services: Services,
    mode: LoopMode,
    request_id: Option<Uuid>,
    executor_id: String,
) -> Result<i32> {
    let shutdown = shutdown_token();
    let _health = if mode == LoopMode::Worker {
        Some(spawn_worker_health(shutdown.clone()).await?)
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
                        _ = tokio::time::sleep(WORKER_IDLE_POLL) => continue,
                    }
                }
                LoopMode::Run if !ran => anyhow::bail!(
                    "deletion request is not runnable, is blocked, or is leased by another executor"
                ),
                LoopMode::Run | LoopMode::Drain => return Ok(0),
            }
        };
        ran = true;
        let output = execute_claim(&services, mode, claim, &shutdown).await?;
        print_json(&output)?;
        if mode == LoopMode::Run || shutdown.is_cancelled() {
            return Ok(i32::from(output.blocked_reason.is_some()));
        }
    }
}

async fn execute_claim(
    services: &Services,
    mode: LoopMode,
    mut claim: ClaimedDeletion,
    shutdown: &CancellationToken,
) -> Result<RunOutput> {
    let token = claim.lease.clone();
    loop {
        if shutdown.is_cancelled() {
            services
                .store
                .heartbeat(&token, mode.as_str(), DEFAULT_LEASE_DURATION, true)
                .await?;
            services
                .store
                .stop_executor(Some(&token), &token.owner)
                .await?;
            let request = services.store.get(token.request_id).await?;
            return Ok(run_output(request));
        }
        services
            .store
            .heartbeat(&token, mode.as_str(), DEFAULT_LEASE_DURATION, false)
            .await?;
        let stage_result = execute_stage(services, &claim).await;
        match stage_result {
            Ok(()) => {}
            Err(error) => {
                let message = format!("{error:#}");
                if is_permanent_failure(&message) {
                    services
                        .store
                        .block(&token, claim.request.stage, "stage", &message)
                        .await?;
                } else {
                    services
                        .store
                        .record_retry(&token, claim.request.stage, "stage", &message, RETRY_DELAY)
                        .await?;
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

async fn execute_stage(services: &Services, claim: &ClaimedDeletion) -> Result<()> {
    let request = &claim.request;
    let token = token_with_current_fence(&claim.lease, request);
    match request.stage {
        DeletionStage::Approved => {
            // Rebuild inventory immediately before the first destructive stage
            // and require byte-equivalence with the approved frozen inventory.
            let live = build_inventory(services, request).await?;
            let frozen: FrozenInventory = serde_json::from_value(
                request
                    .inventory_manifest
                    .clone()
                    .context("approved request has no frozen inventory")?,
            )?;
            if live != frozen {
                anyhow::bail!("approved inventory drifted before fencing");
            }
            services.store.fence(&token).await?;
        }
        DeletionStage::Fenced => {
            publish_disconnect_community(&services.redis, request.community_id).await?;
            services.store.mark_drained(&token).await?;
        }
        DeletionStage::Drained => {
            let storage: StorageManifest = serde_json::from_value(
                request
                    .storage_manifest
                    .clone()
                    .context("request has no frozen storage manifest")?,
            )?;
            buzz_db::deletion::validate_storage_manifest(&storage)?;
            // Re-run the exhaustive bucket taxonomy after fencing. Any key that
            // appeared after approval is drift and blocks before a delete.
            let live_storage = build_storage_manifest(services, request).await?;
            if live_storage != storage {
                anyhow::bail!("approved storage inventory drifted before binding removal");
            }
            for key in &storage.tenant_keys {
                match services.media.inspect_current_version(key).await? {
                    CurrentObjectVersion::Present { version_id: None } => {}
                    CurrentObjectVersion::Present {
                        version_id: Some(_),
                    } => anyhow::bail!("unsupported object version appeared after approval: {key}"),
                    CurrentObjectVersion::Missing => {
                        anyhow::bail!("approved object binding disappeared before deletion: {key}")
                    }
                }
            }
            services.media.delete_bindings(&storage.tenant_keys).await?;
            for key in &storage.tenant_keys {
                if services.media.head(key).await? {
                    anyhow::bail!("object binding still exists after delete: {key}");
                }
            }
            services
                .store
                .mark_bindings_removed(
                    &token,
                    serde_json::json!({"deleted_keys": storage.tenant_keys.len()}),
                )
                .await?;
        }
        DeletionStage::BindingsRemoved => {
            services.store.purge_postgres(&token).await?;
        }
        DeletionStage::PostgresPurged => {
            let deleted = purge_redis_namespace(&services.redis, request.community_id).await?;
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
            let frozen: FrozenInventory = serde_json::from_value(
                request
                    .inventory_manifest
                    .clone()
                    .context("request has no frozen inventory")?,
            )?;
            services
                .store
                .mark_retention_pending(
                    &token,
                    serde_json::json!({
                        "retained_shared_cas_keys": frozen.storage.retained_shared_cas_keys,
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

async fn verify_storage_absence(services: &Services, request: &DeletionRequest) -> Result<()> {
    let storage: StorageManifest = serde_json::from_value(
        request
            .storage_manifest
            .clone()
            .context("request has no frozen storage manifest")?,
    )?;
    for key in &storage.tenant_keys {
        if services.media.head(key).await? {
            anyhow::bail!("logical verification found object binding: {key}");
        }
    }
    Ok(())
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

async fn verify_redis_absence(
    pool: &deadpool_redis::Pool,
    community: buzz_core::CommunityId,
) -> Result<()> {
    let mut connection = pool.get().await?;
    let pattern = format!("buzz:{community}:*");
    let (_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
        .arg(0)
        .arg("MATCH")
        .arg(pattern)
        .arg("COUNT")
        .arg(1)
        .query_async(&mut *connection)
        .await?;
    if keys.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("logical verification found Redis key: {}", keys[0])
    }
}

fn storage_object_cap() -> u64 {
    std::env::var("BUZZ_DELETION_STORAGE_MAX_OBJECTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_STORAGE_OBJECT_CAP)
}

fn default_executor_id() -> String {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "buzz-admin".to_string());
    format!("{hostname}:{}", std::process::id())
}

async fn spawn_worker_health(shutdown: CancellationToken) -> Result<tokio::task::JoinHandle<()>> {
    let address =
        std::env::var("BUZZ_DELETION_HEALTH_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("bind deletion worker health endpoint {address}"))?;
    let draining = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&draining);
    let cancel = shutdown.clone();
    tokio::spawn(async move {
        cancel.cancelled().await;
        signal.store(true, Ordering::Relaxed);
    });
    let router = axum::Router::new()
        .route("/_liveness", axum::routing::get(|| async { "ok" }))
        .route(
            "/_readiness",
            axum::routing::get({
                let draining = Arc::clone(&draining);
                move || {
                    let draining = Arc::clone(&draining);
                    async move {
                        if draining.load(Ordering::Relaxed) {
                            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "draining")
                        } else {
                            (axum::http::StatusCode::OK, "ready")
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

fn is_permanent_failure(message: &str) -> bool {
    [
        "drift",
        "unknown object-store keys",
        "unsupported object",
        "catalog",
        "write-fence",
        "approved inventory",
        "tombstone/fence",
    ]
    .iter()
    .any(|needle| message.contains(needle))
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

    #[test]
    fn permanent_failures_are_narrow_and_fail_closed() {
        assert!(is_permanent_failure("community deletion catalog drift"));
        assert!(is_permanent_failure("unknown object-store keys"));
        assert!(!is_permanent_failure("temporary Redis connection reset"));
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
