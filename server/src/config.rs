use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub quic: QuicSection,
    #[serde(default)]
    pub limits: LimitsSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub durability: DurabilitySection,
}

/// Server-side durability policy.
#[derive(Debug, Deserialize, Default)]
pub struct DurabilitySection {
    /// fsync each file to disk when its handle is released (close). Off by
    /// default: it trades write throughput for durability against a server-host
    /// crash (data already left the client and is in the server's page cache;
    /// this forces it to stable storage). Turn on for crash-sensitive exports.
    #[serde(default)]
    pub sync_on_close: bool,
    /// fsync the parent directory after a namespace mutation (create, rename,
    /// unlink, mkdir, rmdir, symlink, link) so the directory entry survives a
    /// server-host crash. Off by default: like `sync_on_close` it trades
    /// throughput for durability, but the cost lands on metadata-heavy
    /// workloads (an extra synchronous directory fsync per entry). This is the
    /// half of the crash-safe write-tmp-fsync-rename replace idiom the server
    /// owns: the application makes the file's data durable with an fsync RPC,
    /// and this makes the subsequent rename's directory entry durable. The two
    /// flags are independent so an operator can pay for one cost without the
    /// other; enable both for full crash durability.
    #[serde(default)]
    pub sync_metadata: bool,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    pub listen: String,
    pub export_root: String,
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    /// Maximum simultaneous connections from a single source IP. 0 disables the
    /// per-IP limit (the default), since clients behind one NAT share an address.
    /// Set it on a public-facing server so one peer cannot exhaust max_clients.
    #[serde(default)]
    pub max_conns_per_ip: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// TLS identity. Under QuicFS's TOFU model there is **no CA** - the server
/// presents a long-lived self-signed cert and clients pin its key.
///
/// All fields are optional: if `cert`/`key` are unset, the server generates a
/// persistent self-signed identity under its config directory on first run
/// (just like ssh-keygen produces a host key).
#[derive(Debug, Deserialize, Default)]
pub struct TlsSection {
    /// Path to the server certificate PEM (auto-generated if unset).
    #[serde(default)]
    pub cert: Option<String>,
    /// Path to the server private key PEM (auto-generated if unset).
    #[serde(default)]
    pub key: Option<String>,
}

/// Client authorization policy (the `authorized_keys` model).
#[derive(Debug, Deserialize, Default)]
pub struct AuthSection {
    /// Path to the authorized client keys file. Defaults to
    /// `<config_dir>/authorized_keys`.
    #[serde(default)]
    pub authorized_keys: Option<String>,
    /// Accept ANY client key when `authorized_keys` is empty. Single-user /
    /// trusted-network convenience; explicit opt-in, never the silent default.
    #[serde(default)]
    pub allow_any_client: bool,
}

#[derive(Debug, Deserialize)]
pub struct QuicSection {
    #[serde(default = "default_conn_recv_window")]
    pub connection_receive_window: u64,
    #[serde(default = "default_stream_recv_window")]
    pub stream_receive_window: u32,
    #[serde(default = "default_max_bidi_streams")]
    pub max_concurrent_bidi_streams: u32,
    #[serde(default = "default_keepalive_ms")]
    pub keep_alive_interval_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub migration: bool,
    #[serde(default)]
    pub zero_rtt: bool,
}

impl Default for QuicSection {
    fn default() -> Self {
        Self {
            connection_receive_window: default_conn_recv_window(),
            stream_receive_window: default_stream_recv_window(),
            max_concurrent_bidi_streams: default_max_bidi_streams(),
            keep_alive_interval_ms: default_keepalive_ms(),
            idle_timeout_ms: default_idle_timeout_ms(),
            migration: default_true(),
            zero_rtt: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LimitsSection {
    #[serde(default = "default_max_handles")]
    pub max_open_handles: u32,
    #[serde(default = "default_rpc_timeout_ms")]
    pub rpc_timeout_ms: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_open_handles: default_max_handles(),
            rpc_timeout_ms: default_rpc_timeout_ms(),
        }
    }
}

fn default_max_clients() -> u32 {
    128
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_conn_recv_window() -> u64 {
    67_108_864
}
fn default_stream_recv_window() -> u32 {
    16_777_216
}
fn default_max_bidi_streams() -> u32 {
    256
}
fn default_keepalive_ms() -> u64 {
    15_000
}
fn default_idle_timeout_ms() -> u64 {
    300_000
}
fn default_true() -> bool {
    true
}
fn default_max_handles() -> u32 {
    8192
}
fn default_rpc_timeout_ms() -> u64 {
    30_000
}

pub fn load(path: &str) -> Result<Config> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("read config file: {path}"))?;
    let cfg: Config = toml::from_str(&contents).context("parse config TOML")?;
    cfg.validate()?;
    Ok(cfg)
}

impl Config {
    /// Validate config values for sanity.  Called automatically by `load()`.
    pub fn validate(&self) -> Result<()> {
        if self.server.max_clients == 0 {
            anyhow::bail!("server.max_clients must be > 0");
        }
        if self.server.max_conns_per_ip > self.server.max_clients {
            anyhow::bail!(
                "server.max_conns_per_ip ({}) cannot exceed server.max_clients ({})",
                self.server.max_conns_per_ip,
                self.server.max_clients,
            );
        }
        if self.limits.max_open_handles == 0 {
            anyhow::bail!("limits.max_open_handles must be > 0");
        }
        if self.limits.max_open_handles > 1_000_000 {
            anyhow::bail!("limits.max_open_handles is unreasonably large (> 1 000 000)");
        }
        if self.limits.rpc_timeout_ms == 0 {
            anyhow::bail!("limits.rpc_timeout_ms must be > 0");
        }
        if self.quic.idle_timeout_ms < self.quic.keep_alive_interval_ms {
            anyhow::bail!(
                "quic.idle_timeout_ms ({}) must be ≥ keep_alive_interval_ms ({})",
                self.quic.idle_timeout_ms,
                self.quic.keep_alive_interval_ms,
            );
        }
        if self.server.export_root.is_empty() {
            anyhow::bail!("server.export_root must not be empty");
        }
        if self.server.listen.is_empty() {
            anyhow::bail!("server.listen must not be empty");
        }
        match self.server.log_level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            other => anyhow::bail!(
                "server.log_level '{other}' is not one of: error warn info debug trace"
            ),
        }
        Ok(())
    }
}
