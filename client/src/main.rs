mod cache;
mod conn;
mod verify;
mod writebuf;

#[cfg(target_os = "linux")]
mod fuse_ops;
#[cfg(target_os = "linux")]
mod mount;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use conn::{ConnManager, MountConfig, TofuPolicy};
use quicfs_common::identity::Identity;
use quicfs_common::trust::{config_dir, KnownHosts};

const DEFAULT_PORT: u16 = 9001;

// ── Argument structs (shared by `mount` and the bare default form) ───────────

#[derive(Parser, Clone)]
struct MountArgs {
    /// Remote in `[user@]host[:/remote/path]` form (sshfs-style).
    spec: String,
    /// Local mountpoint directory (Linux only).
    mountpoint: PathBuf,

    /// Server UDP port.
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Pin a new/unknown host key without prompting (ssh accept-new).
    #[arg(long)]
    accept_new: bool,
    /// Never accept an unknown host key (ssh StrictHostKeyChecking=yes).
    #[arg(long)]
    strict_host_key: bool,
    /// Directory holding this client's identity key (default: config dir).
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Path to the known_hosts file (default: <config dir>/known_hosts).
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    /// Override the TLS SNI sent to the server (cosmetic under key pinning).
    #[arg(long)]
    server_name: Option<String>,

    #[arg(long, default_value_t = 262_144)]
    chunk_size: u32,
    #[arg(long, default_value_t = 2_000)]
    cache_ttl: u64,
    #[arg(long)]
    allow_other: bool,
    #[arg(long = "ro")]
    readonly: bool,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long)]
    uid: Option<u32>,
    #[arg(long)]
    gid: Option<u32>,
    #[arg(long, default_value_t = 4_194_304)]
    write_buf: usize,
    #[arg(long, default_value_t = 10)]
    coalesce_ms: u64,
}

#[derive(Parser, Clone)]
struct PingArgs {
    /// Remote in `[user@]host` form.
    spec: String,
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,
    #[arg(long)]
    accept_new: bool,
    #[arg(long)]
    strict_host_key: bool,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    #[arg(long)]
    server_name: Option<String>,
}

// ── Entry point with manual subcommand dispatch ──────────────────────────────
//
// The headline UX is the bare form `quicfs user@host:/path /mnt`, so we cannot
// require a subcommand. We dispatch on argv[1]: a known verb routes to that
// subcommand; anything else is treated as the default `mount`.

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let argv: Vec<String> = std::env::args().collect();
    let verb = argv.get(1).map(|s| s.as_str()).unwrap_or("");

    match verb {
        "" | "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "--version" | "-V" => {
            println!("quicfs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "key" => cmd_key(&argv),
        "known-hosts" => cmd_known_hosts(&argv),
        "ping" => {
            let args = PingArgs::parse_from(sub_args(&argv));
            run_ping(args).await
        }
        "mount" => {
            let args = MountArgs::parse_from(sub_args(&argv));
            run_mount(args).await
        }
        _ => {
            // Default: treat the whole tail as `mount` arguments.
            let args = MountArgs::parse_from(
                std::iter::once("quicfs mount".to_string()).chain(argv[1..].iter().cloned()),
            );
            run_mount(args).await
        }
    }
}

/// argv with the subcommand verb stripped, but a synthetic bin name kept so clap
/// reports errors sensibly.
fn sub_args(argv: &[String]) -> Vec<String> {
    let prog = format!("quicfs {}", argv.get(1).cloned().unwrap_or_default());
    std::iter::once(prog)
        .chain(argv[2..].iter().cloned())
        .collect()
}

fn print_help() {
    eprintln!(
        "quicfs {} - a QUIC filesystem (SSHFS over QUIC)\n\n\
         USAGE:\n  \
           quicfs [user@]host[:/remote/path] <mountpoint> [options]   mount a remote tree\n  \
           quicfs ping [user@]host [options]                          test connectivity\n  \
           quicfs key                                                 print this client's key fingerprint\n  \
           quicfs known-hosts                                         list pinned server keys\n\n\
         COMMON OPTIONS:\n  \
           -p, --port <PORT>        server port (default {DEFAULT_PORT})\n  \
           --accept-new             pin an unknown host key without prompting\n  \
           --strict-host-key        refuse unknown host keys\n  \
           --ro                     read-only mount\n  \
           --allow-other            allow other users to access the mount\n\n\
         On first connect to a new host you'll be asked to confirm its key\n\
         fingerprint, exactly like ssh. The key is pinned in known_hosts.\n",
        env!("CARGO_PKG_VERSION"),
    );
}

// ── key / known-hosts subcommands ────────────────────────────────────────────

fn cmd_key(_argv: &[String]) -> Result<()> {
    let dir = config_dir()?;
    let id = Identity::load_or_generate(&dir, "client", &current_user())
        .context("load/generate client identity")?;
    println!("{}", id.fingerprint);
    eprintln!("(client identity stored in {})", dir.display());
    eprintln!(
        "Authorize it on the server with: quicfs-server authorize {}",
        id.fingerprint
    );
    Ok(())
}

fn cmd_known_hosts(_argv: &[String]) -> Result<()> {
    let path = KnownHosts::default_path()?;
    let kh = KnownHosts::load(&path)?;
    // KnownHosts has no iterator accessor; just point at the file.
    println!("known_hosts: {}", path.display());
    if !path.exists() {
        eprintln!("(no hosts pinned yet)");
    } else {
        print!("{}", std::fs::read_to_string(&path).unwrap_or_default());
    }
    let _ = kh;
    Ok(())
}

// ── ping ─────────────────────────────────────────────────────────────────────

async fn run_ping(args: PingArgs) -> Result<()> {
    init_tracing("info");
    let (_user, host, _path) = parse_spec(&args.spec)?;
    let cfg = build_config(
        &host,
        args.port,
        args.server_name.as_deref(),
        &args.spec,
        tofu(args.accept_new, args.strict_host_key),
        args.identity.as_deref(),
        args.known_hosts.as_deref(),
        262_144,
    )?;
    let conn = ConnManager::connect(cfg).await?;
    conn.ping().await?;
    println!("OK");
    if let Some(fp) = conn.server_fingerprint() {
        println!("server key: {fp}");
    }
    conn.close().await;
    Ok(())
}

// ── mount ──────────────────────────────────────────────────────────────────

async fn run_mount(args: MountArgs) -> Result<()> {
    init_tracing(&args.log_level);

    let (_user, host, remote_path) = parse_spec(&args.spec)?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (host, remote_path);
        anyhow::bail!("FUSE mount is only supported on Linux (try `quicfs ping` on this platform)");
    }

    #[cfg(target_os = "linux")]
    {
        let cfg = build_config(
            &host,
            args.port,
            args.server_name.as_deref(),
            &args.spec,
            tofu(args.accept_new, args.strict_host_key),
            args.identity.as_deref(),
            args.known_hosts.as_deref(),
            args.chunk_size,
        )?;
        let write_buf_total = (args.write_buf * 8).min(64 * 1024 * 1024);
        mount::run_mount(
            cfg,
            &args.mountpoint,
            mount::FuseOptions {
                allow_other: args.allow_other,
                readonly: args.readonly,
                cache_ttl_ms: args.cache_ttl,
                uid_override: args.uid,
                gid_override: args.gid,
                write_buf_per_handle: args.write_buf,
                write_buf_total,
                coalesce_ms: args.coalesce_ms,
                remote_root: remote_path,
            },
        )
        .await
    }
}

// ── Config assembly ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_config(
    host: &str,
    port: u16,
    server_name_override: Option<&str>,
    spec: &str,
    tofu: TofuPolicy,
    identity_dir: Option<&std::path::Path>,
    known_hosts_path: Option<&std::path::Path>,
    chunk_size: u32,
) -> Result<MountConfig> {
    if chunk_size == 0 {
        anyhow::bail!("--chunk-size must be greater than 0");
    }
    let (user, _host2, _path) = parse_spec(spec)?;
    let addr = resolve_addr(host, port)?;
    let server_name = server_name_override
        .map(|s| s.to_owned())
        .unwrap_or_else(|| host.to_owned());
    let host_key = format!("{host}:{port}");

    // Client identity: generated once, reused (the machine's key, like an ssh key).
    let id_dir = match identity_dir {
        Some(d) => d.to_path_buf(),
        None => config_dir()?,
    };
    let identity = Identity::load_or_generate(&id_dir, "client", &user)
        .context("load/generate client identity")?;

    let kh_path = match known_hosts_path {
        Some(p) => p.to_path_buf(),
        None => KnownHosts::default_path()?,
    };

    Ok(MountConfig {
        server_addr: addr,
        server_name,
        host_key,
        client_cert_pem: identity.cert_pem,
        client_key_pem: identity.key_pem,
        chunk_size,
        tofu,
        known_hosts_path: kh_path,
    })
}

fn tofu(accept_new: bool, strict: bool) -> TofuPolicy {
    if strict {
        TofuPolicy::Strict
    } else if accept_new {
        TofuPolicy::AcceptNew
    } else {
        TofuPolicy::Prompt
    }
}

/// Parse `[user@]host[:/remote/path]` (sshfs-style). IPv6 hosts use `[..]`.
fn parse_spec(spec: &str) -> Result<(String, String, String)> {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (u.to_owned(), r.to_owned()),
        None => (current_user(), spec.to_owned()),
    };

    let (host, path) = if let Some(stripped) = rest.strip_prefix('[') {
        // IPv6 literal: [addr]:/path
        let end = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unterminated '[' in host"))?;
        let host = stripped[..end].to_owned();
        let after = &stripped[end + 1..];
        let path = after.strip_prefix(':').unwrap_or(after);
        (host, path.to_owned())
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h.to_owned(), p.to_owned()),
            None => (rest, String::new()),
        }
    };

    if host.is_empty() {
        anyhow::bail!("no host in spec: {spec:?}");
    }
    let path = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    Ok((user, host, path))
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map(|it| it.collect())
        .unwrap_or_default();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .with_context(|| format!("resolve {host}:{port}"))
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_owned())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    use super::parse_spec;

    #[test]
    fn user_host_path() {
        let (u, h, p) = parse_spec("alice@server:/projects").unwrap();
        assert_eq!(
            (u.as_str(), h.as_str(), p.as_str()),
            ("alice", "server", "/projects")
        );
    }

    #[test]
    fn host_without_user_defaults_path_and_keeps_host() {
        // user defaults to the current OS user (env-dependent), so only assert host/path.
        let (_u, h, p) = parse_spec("server:/data").unwrap();
        assert_eq!((h.as_str(), p.as_str()), ("server", "/data"));
    }

    #[test]
    fn missing_path_defaults_to_root() {
        let (u, h, p) = parse_spec("alice@host").unwrap();
        assert_eq!((u.as_str(), h.as_str(), p.as_str()), ("alice", "host", "/"));
    }

    #[test]
    fn relative_remote_path_is_normalized_with_leading_slash() {
        let (_u, h, p) = parse_spec("host:rel/path").unwrap();
        assert_eq!((h.as_str(), p.as_str()), ("host", "/rel/path"));
    }

    #[test]
    fn ipv6_literal_host() {
        let (_u, h, p) = parse_spec("[::1]:/p").unwrap();
        assert_eq!((h.as_str(), p.as_str()), ("::1", "/p"));
    }

    #[test]
    fn empty_or_hostless_spec_is_error() {
        assert!(parse_spec("").is_err());
        assert!(
            parse_spec("alice@").is_err(),
            "user with no host must error"
        );
    }
}
