use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};
use uuid::Uuid;

use quicfs_common::identity::Identity;
use quicfs_common::trust::{config_dir, parse_fingerprint, AuthorizedKeys};
use quicfs_server::verify::AuthorizedKeysVerifier;
use quicfs_server::{config, endpoint, handle_connection, ConnLimits};

#[derive(Parser)]
#[command(name = "quicfs-server", about = "QuicFS server daemon")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "server.toml", global = true)]
    config: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (this is the default if no subcommand is given).
    Run,
    /// Print this server's public-key fingerprint. Clients pin this on first connect.
    Fingerprint,
    /// Authorize a client key fingerprint (append it to authorized_keys).
    Authorize {
        /// The `SHA256:...` fingerprint to allow (run `quicfs key` on the client).
        fingerprint: String,
        /// Optional comment, e.g. the user/host the key belongs to.
        #[arg(long, default_value = "")]
        comment: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let cli = Cli::parse();

    match cli.cmd.unwrap_or(Cmd::Run) {
        Cmd::Run => run_server(&cli.config).await,
        Cmd::Fingerprint => cmd_fingerprint(&cli.config),
        Cmd::Authorize {
            fingerprint,
            comment,
        } => cmd_authorize(&cli.config, &fingerprint, &comment),
    }
}

/// Resolve the server's identity cert/key paths from config (or defaults).
fn identity_paths(cfg: Option<&config::Config>) -> (PathBuf, PathBuf) {
    if let Some(c) = cfg {
        if let (Some(cert), Some(key)) = (&c.tls.cert, &c.tls.key) {
            return (PathBuf::from(cert), PathBuf::from(key));
        }
    }
    let dir = config_dir().unwrap_or_else(|_| PathBuf::from("."));
    (dir.join("server.crt"), dir.join("server.key"))
}

/// Resolve the authorized_keys path from config (or default).
fn authorized_keys_path(cfg: Option<&config::Config>) -> PathBuf {
    if let Some(c) = cfg {
        if let Some(p) = &c.auth.authorized_keys {
            return PathBuf::from(p);
        }
    }
    config_dir()
        .map(|d| d.join("authorized_keys"))
        .unwrap_or_else(|_| PathBuf::from("authorized_keys"))
}

async fn run_server(config_path: &str) -> Result<()> {
    let cfg = config::load(config_path).with_context(|| format!("load config: {config_path}"))?;

    init_tracing(&cfg.server.log_level);

    let listen: std::net::SocketAddr = cfg.server.listen.parse().context("parse listen address")?;

    let export_root = PathBuf::from(&cfg.server.export_root);
    if !export_root.exists() {
        anyhow::bail!("export_root does not exist: {}", export_root.display());
    }
    let export_root: Arc<Path> = Arc::from(export_root.as_path());

    // Server identity: load configured cert/key, or self-generate (no CA).
    let (cert_path, key_path) = identity_paths(Some(&cfg));
    let identity = Identity::load_or_generate_at(&cert_path, &key_path, "quicfs-server")
        .context("load/generate server identity")?;

    // Client authorization: authorized_keys + allow_any policy.
    let ak_path = authorized_keys_path(Some(&cfg));
    let authorized = AuthorizedKeys::load(&ak_path)
        .with_context(|| format!("load authorized_keys: {}", ak_path.display()))?;
    let allow_any = cfg.auth.allow_any_client;
    if authorized.is_empty() && !allow_any {
        warn!(
            "no authorized client keys ({}) and allow_any_client=false - all clients will be \
             REJECTED. Authorize a client with `quicfs-server authorize <fingerprint>`.",
            ak_path.display()
        );
    }
    let verifier = AuthorizedKeysVerifier::new(authorized, allow_any);

    let transport = endpoint::build_transport(&cfg.quic);
    let ep = endpoint::make_server_endpoint(
        &identity.cert_pem,
        &identity.key_pem,
        verifier,
        listen,
        transport,
        cfg.quic.migration,
    )?;

    let server_id = Uuid::new_v4().to_string();
    let limits = ConnLimits::from_config(&cfg);
    // Bound concurrent connections (DoS): a permit is held for each connection's
    // lifetime and released when it ends. Without this the accept loop would
    // spawn an unbounded number of sessions.
    let max_clients = cfg.server.max_clients.max(1) as usize;
    let conn_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(max_clients));
    // Optional per-source-IP cap so one peer cannot occupy every max_clients slot.
    // 0 = disabled. Counts are keyed by the address seen at accept time and held
    // for the connection's whole life (migration may change the address later).
    let max_per_ip = cfg.server.max_conns_per_ip;
    let ip_counts: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    info!(
        listen = %listen,
        fingerprint = %identity.fingerprint,
        export_root = %export_root.display(),
        migration = cfg.quic.migration,
        max_clients,
        max_open_handles = limits.max_open_handles,
        rpc_timeout_ms = limits.rpc_timeout.as_millis(),
        "QuicFS server ready"
    );
    info!(
        "server key fingerprint (clients pin this): {}",
        identity.fingerprint
    );

    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => break,
        };
        // Refuse new connections once the concurrency limit is reached, rather
        // than queuing unboundedly. The permit is moved into the task and dropped
        // when the connection finishes, freeing the slot.
        let permit = match std::sync::Arc::clone(&conn_slots).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(remote = %incoming.remote_address(), max_clients,
                      "connection limit reached - refusing new connection");
                incoming.refuse();
                continue;
            }
        };
        // Enforce the per-IP cap (if enabled) and take a guard that decrements the
        // count when the connection ends. Reserve the slot before spawning so a
        // burst from one IP cannot race past the limit.
        let ip_guard =
            match IpSlot::try_acquire(&ip_counts, incoming.remote_address().ip(), max_per_ip) {
                Some(g) => g,
                None => {
                    warn!(remote = %incoming.remote_address(), max_per_ip,
                      "per-IP connection limit reached - refusing new connection");
                    incoming.refuse();
                    continue; // global `permit` drops here, freeing the slot
                }
            };
        let root = Arc::clone(&export_root);
        let sid = server_id.clone();
        let lim = limits.clone();
        tokio::spawn(async move {
            let _permit = permit; // global slot, held until the connection ends
            let _ip_guard = ip_guard; // per-IP count, decremented on drop
            if let Err(e) = handle_connection(incoming, root, sid, lim).await {
                warn!("connection error: {e:#}");
            }
        });
    }

    info!("endpoint closed");
    Ok(())
}

/// RAII guard for a per-source-IP connection slot. Acquired (incrementing the
/// IP's count) before a connection task is spawned, and decremented on drop, so
/// the count cannot leak on any exit path (handshake failure, error, clean close).
struct IpSlot {
    map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>,
    ip: std::net::IpAddr,
}

impl IpSlot {
    /// Reserve a slot for `ip`. `max == 0` disables the limit. Returns `None` if
    /// `ip` already holds `max` connections.
    fn try_acquire(
        map: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>,
        ip: std::net::IpAddr,
        max: u32,
    ) -> Option<Self> {
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        let count = m.entry(ip).or_insert(0);
        if max != 0 && *count >= max {
            if *count == 0 {
                m.remove(&ip);
            } // do not leave a stale 0 entry
            return None;
        }
        *count += 1;
        Some(IpSlot {
            map: std::sync::Arc::clone(map),
            ip,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = m.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

fn cmd_fingerprint(config_path: &str) -> Result<()> {
    let cfg = config::load(config_path).ok();
    let (cert_path, key_path) = identity_paths(cfg.as_ref());
    let identity = Identity::load_or_generate_at(&cert_path, &key_path, "quicfs-server")
        .context("load/generate server identity")?;
    println!("{}", identity.fingerprint);
    eprintln!("(stored at {})", cert_path.display());
    Ok(())
}

fn cmd_authorize(config_path: &str, fingerprint: &str, comment: &str) -> Result<()> {
    let cfg = config::load(config_path).ok();
    let fp = parse_fingerprint(fingerprint)?;
    let ak_path = authorized_keys_path(cfg.as_ref());
    let mut ak = AuthorizedKeys::load(&ak_path)?;
    ak.authorize(&fp, comment)?;
    eprintln!("authorized {fp} in {}", ak_path.display());
    Ok(())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = fmt().with_env_filter(filter).try_init();
}
