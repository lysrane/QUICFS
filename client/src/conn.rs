use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};
use uuid::Uuid;

use quicfs_common::{
    frames::*,
    io::{decode, encode, read_frame, write_frame},
    stat::{Stat, StatFs},
    status::Status,
    trust::KnownHosts,
};

use crate::verify::PinningServerVerifier;

/// Hard wall-clock deadline for any single client operation (including any
/// reconnect attempts it triggers). Without this, a crashed or wedged server
/// makes a FUSE callback block forever - an uninterruptible process and a
/// frozen mountpoint. With it, the op returns an error (→ EIO) and the next op
/// can retry. 30s mirrors the server's default `rpc_timeout_ms`.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `fut` under `RPC_TIMEOUT`, turning a stall into an error.
async fn deadline<F, T>(what: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(RPC_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => bail!("{what} timed out after {RPC_TIMEOUT:?}"),
    }
}

// ── Trust policy ─────────────────────────────────────────────────────────────

/// What to do when connecting to a host whose key is not yet in `known_hosts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TofuPolicy {
    /// Prompt the user on the terminal (ssh default). Refuse if not a TTY.
    Prompt,
    /// Accept and pin a new key automatically (ssh `accept-new`). For automation.
    AcceptNew,
    /// Never accept an unknown key (ssh `StrictHostKeyChecking=yes`).
    Strict,
}

// ── MountConfig ──────────────────────────────────────────────────────────────

/// All parameters needed to (re-)connect to a QuicFS server under TOFU trust.
#[derive(Clone)]
pub struct MountConfig {
    pub server_addr: SocketAddr,
    /// TLS server name (SNI). Ignored for trust (we pin the key) but required by QUIC.
    pub server_name: String,
    /// `host:port` key under which the server's fingerprint is pinned in known_hosts.
    pub host_key: String,
    /// Our own identity certificate (PEM) - always present; auto-generated on first run.
    pub client_cert_pem: String,
    /// Our own identity private key (PEM).
    pub client_key_pem: String,
    pub chunk_size: u32,
    /// First-contact policy.
    pub tofu: TofuPolicy,
    /// Path to the known_hosts file.
    pub known_hosts_path: std::path::PathBuf,
}

// ── ConnManager ───────────────────────────────────────────────────────────────

/// Thread-safe QUIC connection manager with TOFU server-key pinning and
/// transparent reconnection.
#[derive(Clone)]
pub struct ConnManager(Arc<Inner>);

struct Inner {
    conn: tokio::sync::Mutex<Option<Connection>>,
    endpoint: tokio::sync::Mutex<Option<Endpoint>>,
    cfg: MountConfig,
    seq: AtomicU64,
    reconnect_gen: AtomicU64,
    /// The fingerprint we enforce. `None` only during first-contact capture.
    expected_fp: Mutex<Option<String>>,
    /// Capture sink: the fingerprint the server presented during a capture handshake.
    capture_sink: Arc<Mutex<Option<String>>>,
}

impl ConnManager {
    /// Connect to the server, performing TOFU key verification and the QuicFS Handshake.
    pub async fn connect(cfg: MountConfig) -> Result<Self> {
        let mgr = Self(Arc::new(Inner {
            conn: tokio::sync::Mutex::new(None),
            endpoint: tokio::sync::Mutex::new(None),
            cfg,
            seq: AtomicU64::new(2), // 1 was used for the Handshake
            reconnect_gen: AtomicU64::new(0),
            expected_fp: Mutex::new(None),
            capture_sink: Arc::new(Mutex::new(None)),
        }));

        // 1. Look up the pinned fingerprint for this host.
        let mut known = KnownHosts::load(&mgr.0.cfg.known_hosts_path).with_context(|| {
            format!("load known_hosts: {}", mgr.0.cfg.known_hosts_path.display())
        })?;
        let pinned = known.get(&mgr.0.cfg.host_key).map(|s| s.to_owned());
        *mgr.0.expected_fp.lock().unwrap() = pinned.clone();

        // 2. Establish QUIC+TLS. If unknown, the verifier captures the key; if
        //    known, it enforces the pinned fingerprint (failing on mismatch).
        let conn = mgr.establish().await.map_err(|e| {
            if pinned.is_some() {
                // Enforce failed → almost certainly a key mismatch.
                anyhow::anyhow!(
                    "{e:#}\n\n\
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     @  WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     The server key for {} does not match the pinned key in\n\
                     {}.\n\
                     This may indicate a man-in-the-middle attack, or the server\n\
                     key was rotated. If you trust the change, remove the old line\n\
                     and reconnect.",
                    mgr.0.cfg.host_key,
                    mgr.0.cfg.known_hosts_path.display(),
                )
            } else {
                e
            }
        })?;

        // 3. First contact: decide whether to trust + pin the captured key.
        if pinned.is_none() {
            let captured = mgr
                .0
                .capture_sink
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| anyhow::anyhow!("server presented no certificate"))?;

            let accepted =
                decide_first_contact(&mgr.0.cfg.host_key, &captured, mgr.0.cfg.tofu).await?;
            if !accepted {
                conn.close(0u32.into(), b"host key rejected");
                bail!("host key for {} was not accepted", mgr.0.cfg.host_key);
            }

            known.insert(&mgr.0.cfg.host_key, &captured);
            known.save().context("persist known_hosts")?;
            info!("pinned host key {} = {}", mgr.0.cfg.host_key, captured);
            *mgr.0.expected_fp.lock().unwrap() = Some(captured);
        }

        // 4. Application-layer Handshake (auth/capability negotiation).
        mgr.app_handshake(&conn).await.context("QuicFS handshake")?;
        *mgr.0.conn.lock().await = Some(conn);
        Ok(mgr)
    }

    fn next_seq(&self) -> u64 {
        self.0.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Bumped on every successful reconnect; the FUSE layer watches this to
    /// clear its cache after a server restart.
    pub fn reconnect_gen(&self) -> u64 {
        self.0.reconnect_gen.load(Ordering::Relaxed)
    }

    /// The pinned server-key fingerprint currently being enforced.
    pub fn server_fingerprint(&self) -> Option<String> {
        self.0.expected_fp.lock().unwrap().clone()
    }

    // ── Connection management ─────────────────────────────────────────────

    async fn live_conn(&self) -> Option<Connection> {
        let guard = self.0.conn.lock().await;
        guard
            .as_ref()
            .filter(|c| c.close_reason().is_none())
            .cloned()
    }

    async fn ensure_conn(&self) -> Result<Connection> {
        if let Some(c) = self.live_conn().await {
            return Ok(c);
        }
        self.reconnect().await
    }

    async fn reconnect(&self) -> Result<Connection> {
        let mut delay = Duration::from_millis(100);
        let max_delay = Duration::from_secs(30);
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            match self.do_connect().await {
                Ok(c) => {
                    self.0.reconnect_gen.fetch_add(1, Ordering::Relaxed);
                    info!("reconnected (attempt {attempt})");
                    return Ok(c);
                }
                Err(e) => {
                    let jitter_ms =
                        (delay.as_millis() as u64 / 4).saturating_mul((attempt % 3) as u64);
                    let sleep = delay + Duration::from_millis(jitter_ms);
                    warn!("connect attempt {attempt} failed: {e:#}; retry in {sleep:?}");
                    tokio::time::sleep(sleep).await;
                    delay = (delay * 2).min(max_delay);
                }
            }
        }
    }

    /// Reconnect path: the key is already pinned, so enforce + handshake.
    async fn do_connect(&self) -> Result<Connection> {
        let conn = self.establish().await?;
        self.app_handshake(&conn).await?;
        *self.0.conn.lock().await = Some(conn.clone());
        Ok(conn)
    }

    /// Establish QUIC + TLS only. The server verifier is built from `expected_fp`:
    /// `Some` → enforce that fingerprint; `None` → capture mode (first contact).
    async fn establish(&self) -> Result<Connection> {
        let cfg = &self.0.cfg;

        let cert_der: CertificateDer<'static> =
            pem_to_der(&cfg.client_cert_pem).context("parse client cert PEM")?;
        let key_der: PrivateKeyDer<'static> =
            pem_key_to_der(&cfg.client_key_pem).context("parse client key PEM")?;

        let verifier: Arc<dyn ServerCertVerifier> = {
            let expected = self.0.expected_fp.lock().unwrap().clone();
            match expected {
                Some(fp) => Arc::new(PinningServerVerifier::enforce(fp)),
                None => Arc::new(PinningServerVerifier::capture(Arc::clone(
                    &self.0.capture_sink,
                ))),
            }
        };

        let mut rustls_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert_der], key_der)
            .context("build client TLS config")?;
        // Advertise the QuicFS ALPN so the server accepts us (and so we never
        // complete a handshake against some unrelated QUIC service on the port).
        rustls_cfg.alpn_protocols = vec![quicfs_common::frames::ALPN_PROTOCOL.to_vec()];

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| anyhow::anyhow!("QuicClientConfig: {e}"))?;

        let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
        // Keepalive + a short idle timeout so the client detects a dead/unreachable
        // server PROMPTLY (a hard server kill sends no QUIC close), errors the
        // connection, and reconnects - rather than stalling on each op until the
        // 30s RPC deadline. keep_alive (4s) < idle (12s) so an otherwise-idle mount
        // stays connected; a black-holed peer is declared dead in ~12s. The
        // keep-buffered-until-acked layer then replays positioned writes across the
        // reconnect, so a brief outage is transparent rather than data-losing.
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(4)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(12))
                .expect("12s is a valid idle timeout"),
        ));
        client_config.transport_config(Arc::new(transport));
        let mut ep =
            Endpoint::client("0.0.0.0:0".parse().unwrap()).context("create QUIC endpoint")?;
        ep.set_default_client_config(client_config);

        let conn = ep
            .connect(cfg.server_addr, &cfg.server_name)
            .context("initiate connection")?
            .await
            .context("QUIC handshake")?;

        *self.0.endpoint.lock().await = Some(ep);
        Ok(conn)
    }

    /// Perform the QuicFS application Handshake on an established connection.
    /// Bounded by `RPC_TIMEOUT` so a server that completes the QUIC/TLS handshake
    /// but never answers the Handshake RPC can't hang mount/reconnect forever.
    async fn app_handshake(&self, conn: &Connection) -> Result<()> {
        let cfg = &self.0.cfg;
        let req = HandshakeRequest {
            op: OP_HANDSHAKE,
            seq: 1,
            version: 1,
            client_id: Uuid::new_v4().to_string(),
            features: vec![],
            chunk_size: cfg.chunk_size,
            auth_type: "mtls".to_owned(),
        };

        deadline("handshake", async {
            let (mut send, mut recv) = conn.open_bi().await.context("open handshake stream")?;
            write_frame(&mut send, &encode(&req)?).await?;
            send.finish().context("finish handshake send")?;

            let raw = read_frame(&mut recv).await?;
            let resp: HandshakeResponse = decode(&raw)?;
            if resp.status != 0 {
                bail!("server rejected handshake: status={}", resp.status);
            }
            info!(server_id = %resp.server_id, features = ?resp.features, "handshake OK");
            Ok(())
        })
        .await
    }

    // ── Generic RPC helper ────────────────────────────────────────────────

    async fn rpc<Req, Resp>(&self, req: &Req) -> Result<Resp>
    where
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
    {
        deadline("RPC", async {
            let conn = self.ensure_conn().await?;
            let (mut send, mut recv) = conn.open_bi().await.context("open RPC stream")?;
            write_frame(&mut send, &encode(req)?).await?;
            send.finish().context("finish RPC send")?;
            let raw = read_frame(&mut recv).await?;
            decode(&raw)
        })
        .await
    }

    // ── Metadata RPCs ─────────────────────────────────────────────────────

    pub async fn getattr(&self, path: &str) -> Result<Stat> {
        let resp: GetAttrResponse = self
            .rpc(&GetAttrRequest {
                op: OP_GET_ATTR,
                seq: self.next_seq(),
                path: path.to_owned(),
            })
            .await?;
        check_status(resp.status)?;
        resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))
    }

    pub async fn setattr(
        &self,
        path: &str,
        valid: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime: i64,
        mtime: i64,
    ) -> Result<Stat> {
        let resp: SetAttrResponse = self
            .rpc(&SetAttrRequest {
                op: OP_SET_ATTR,
                seq: self.next_seq(),
                path: path.to_owned(),
                valid,
                mode,
                uid,
                gid,
                size,
                atime,
                mtime,
            })
            .await?;
        check_status(resp.status)?;
        resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))
    }

    pub async fn readdir(&self, path: &str) -> Result<Vec<quicfs_common::stat::DirEntry>> {
        let mut all = vec![];
        let mut cursor = 0u64;
        loop {
            let resp: ReadDirResponse = self
                .rpc(&ReadDirRequest {
                    op: OP_READ_DIR,
                    seq: self.next_seq(),
                    path: path.to_owned(),
                    cursor,
                })
                .await?;
            check_status(resp.status)?;
            cursor = resp.cursor;
            let eof = resp.eof;
            all.extend(resp.entries);
            if eof {
                break;
            }
        }
        Ok(all)
    }

    pub async fn mkdir(&self, path: &str, mode: u32) -> Result<Stat> {
        let resp: GetAttrResponse = self
            .rpc(&MkDirRequest {
                op: OP_MKDIR,
                seq: self.next_seq(),
                path: path.to_owned(),
                mode,
            })
            .await?;
        check_status(resp.status)?;
        resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))
    }

    pub async fn rmdir(&self, path: &str) -> Result<()> {
        let resp: StatusResponse = self
            .rpc(&PathRequest {
                op: OP_RMDIR,
                seq: self.next_seq(),
                path: path.to_owned(),
            })
            .await?;
        check_status(resp.status)
    }

    pub async fn unlink(&self, path: &str) -> Result<()> {
        let resp: StatusResponse = self
            .rpc(&PathRequest {
                op: OP_UNLINK,
                seq: self.next_seq(),
                path: path.to_owned(),
            })
            .await?;
        check_status(resp.status)
    }

    pub async fn rename(&self, old: &str, new: &str, flags: u32) -> Result<()> {
        let resp: RenameResponse = self
            .rpc(&RenameRequest {
                op: OP_RENAME,
                seq: self.next_seq(),
                old: old.to_owned(),
                new: new.to_owned(),
                flags,
            })
            .await?;
        check_status(resp.status)
    }

    pub async fn symlink(&self, target: &str, link: &str) -> Result<Stat> {
        let resp: GetAttrResponse = self
            .rpc(&SymlinkRequest {
                op: OP_SYMLINK,
                seq: self.next_seq(),
                target: target.to_owned(),
                link: link.to_owned(),
            })
            .await?;
        check_status(resp.status)?;
        resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))
    }

    pub async fn readlink(&self, path: &str) -> Result<String> {
        let resp: ReadLinkResponse = self
            .rpc(&PathRequest {
                op: OP_READLINK,
                seq: self.next_seq(),
                path: path.to_owned(),
            })
            .await?;
        check_status(resp.status)?;
        Ok(resp.target)
    }

    pub async fn link(&self, path: &str, link: &str) -> Result<Stat> {
        let resp: GetAttrResponse = self
            .rpc(&LinkRequest {
                op: OP_LINK,
                seq: self.next_seq(),
                path: path.to_owned(),
                link: link.to_owned(),
            })
            .await?;
        check_status(resp.status)?;
        resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))
    }

    pub async fn statfs(&self, path: &str) -> Result<StatFs> {
        let resp: StatFsResponse = self
            .rpc(&PathRequest {
                op: OP_STAT_FS,
                seq: self.next_seq(),
                path: path.to_owned(),
            })
            .await?;
        check_status(resp.status)?;
        resp.statfs.ok_or_else(|| anyhow::anyhow!("missing statfs"))
    }

    // ── File I/O RPCs ─────────────────────────────────────────────────────

    pub async fn open(&self, path: &str, flags: u32) -> Result<(u64, Stat)> {
        let resp: OpenResponse = self
            .rpc(&OpenRequest {
                op: OP_OPEN,
                seq: self.next_seq(),
                path: path.to_owned(),
                flags,
            })
            .await?;
        check_status(resp.status)?;
        let stat = resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))?;
        Ok((resp.handle, stat))
    }

    pub async fn create(&self, path: &str, flags: u32, mode: u32) -> Result<(u64, Stat)> {
        let resp: OpenResponse = self
            .rpc(&CreateRequest {
                op: OP_CREATE,
                seq: self.next_seq(),
                path: path.to_owned(),
                flags,
                mode,
            })
            .await?;
        check_status(resp.status)?;
        let stat = resp.stat.ok_or_else(|| anyhow::anyhow!("missing stat"))?;
        Ok((resp.handle, stat))
    }

    pub async fn release(&self, handle: u64) -> Result<()> {
        let resp: ReleaseResponse = self
            .rpc(&ReleaseRequest {
                op: OP_RELEASE,
                seq: self.next_seq(),
                handle,
            })
            .await?;
        check_status(resp.status)
    }

    /// Read `length` bytes starting at `offset`.  The server may return the
    /// data in multiple frames; this method collects them all.
    pub async fn read(&self, handle: u64, offset: u64, length: u32) -> Result<Vec<u8>> {
        deadline("read", async {
            let conn = self.ensure_conn().await?;
            let (mut send, mut recv) = conn.open_bi().await.context("open read stream")?;

            let req = ReadRequest {
                op: OP_READ,
                seq: self.next_seq(),
                handle,
                offset,
                length,
            };
            write_frame(&mut send, &encode(&req)?).await?;
            send.finish().context("finish read send")?;

            let mut data = Vec::with_capacity(length as usize);
            loop {
                let raw = read_frame(&mut recv).await?;
                let resp: ReadResponse = decode(&raw)?;
                check_status(resp.status)?;
                data.extend_from_slice(&resp.data);
                if resp.eof {
                    break;
                }
            }
            Ok(data)
        })
        .await
    }

    /// Write `data` starting at `offset`, chunked into `chunk_size` frames.
    /// Returns the total bytes committed on the server.
    pub async fn write(&self, handle: u64, offset: u64, data: &[u8]) -> Result<u64> {
        // Clamp to ≥1: slice::chunks(0) panics. The CLI rejects 0, but this is
        // the last line of defence for any other caller (tests, future code).
        let chunk_size = (self.0.cfg.chunk_size as usize).max(1);
        deadline("write", async {
            let conn = self.ensure_conn().await?;
            let (mut send, mut recv) = conn.open_bi().await.context("open write stream")?;

            let seq = self.next_seq();
            let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
            let n = chunks.len();

            for (i, chunk) in chunks.iter().enumerate() {
                let done = i + 1 == n;
                let req = WriteRequest {
                    op: OP_WRITE,
                    seq,
                    handle,
                    offset: offset + (i * chunk_size) as u64,
                    data: chunk.to_vec(),
                    done,
                };
                write_frame(&mut send, &encode(&req)?).await?;
            }

            let raw = read_frame(&mut recv).await?;
            let resp: WriteResponse = decode(&raw)?;
            check_status(resp.status)?;
            Ok(resp.written)
        })
        .await
    }

    pub async fn fsync(&self, handle: u64, datasync: bool) -> Result<()> {
        let resp: StatusResponse = self
            .rpc(&FsyncRequest {
                op: OP_FSYNC,
                seq: self.next_seq(),
                handle,
                datasync,
            })
            .await?;
        check_status(resp.status)
    }

    pub async fn ping(&self) -> Result<()> {
        let resp: PingResponse = self
            .rpc(&PingRequest {
                op: OP_PING,
                seq: self.next_seq(),
            })
            .await?;
        check_status(resp.status)
    }

    /// Gracefully close the connection.
    pub async fn close(self) {
        let guard = self.0.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            c.close(0u32.into(), b"bye");
        }
        drop(guard);
        if let Some(ep) = self.0.endpoint.lock().await.take() {
            ep.wait_idle().await;
        }
    }
}

// ── First-contact decision (the ssh known_hosts prompt) ──────────────────────

async fn decide_first_contact(
    hostport: &str,
    fingerprint: &str,
    policy: TofuPolicy,
) -> Result<bool> {
    match policy {
        TofuPolicy::Strict => {
            eprintln!(
                "Host key for {hostport} is not known and StrictHostKeyChecking is on.\n\
                 Key fingerprint is {fingerprint}."
            );
            Ok(false)
        }
        TofuPolicy::AcceptNew => {
            eprintln!("Warning: permanently pinning {hostport} ({fingerprint}).");
            Ok(true)
        }
        TofuPolicy::Prompt => {
            if !std::io::stdin().is_terminal() {
                eprintln!(
                    "Host key for {hostport} is unknown ({fingerprint}) and no terminal is \
                     available to confirm. Re-run with --accept-new to pin it, or pre-populate \
                     known_hosts."
                );
                return Ok(false);
            }
            let hostport = hostport.to_owned();
            let fingerprint = fingerprint.to_owned();
            // Blocking stdin prompt on a dedicated thread so we don't stall the runtime.
            tokio::task::spawn_blocking(move || prompt_yes_no(&hostport, &fingerprint))
                .await
                .context("prompt task")?
        }
    }
}

fn prompt_yes_no(hostport: &str, fingerprint: &str) -> Result<bool> {
    use std::io::Write;
    eprintln!("The authenticity of host '{hostport}' can't be established.");
    eprintln!("Key fingerprint is {fingerprint}.");
    loop {
        eprint!("Are you sure you want to continue connecting (yes/no)? ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok(false); // EOF
        }
        match line.trim() {
            "yes" => return Ok(true),
            "no" => return Ok(false),
            _ => eprintln!("Please type 'yes' or 'no'."),
        }
    }
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>> {
    let pem_bytes = pem.as_bytes();
    rustls_pemfile::certs(&mut pem_bytes.as_ref())
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate found in PEM"))
        .and_then(|r| r.context("parse cert PEM"))
}

fn pem_key_to_der(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let pem_bytes = pem.as_bytes();
    rustls_pemfile::private_key(&mut pem_bytes.as_ref())
        .context("read private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))
}

// ── Error mapping ─────────────────────────────────────────────────────────────

fn check_status(status: u8) -> Result<()> {
    match Status::from(status) {
        Status::Ok => Ok(()),
        s => bail!("server error: {:?}", s),
    }
}
