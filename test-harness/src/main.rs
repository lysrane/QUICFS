//! End-to-end integration test for QuicFS (TOFU trust model).
//!
//! Spins up a QuicFS server in a background task with a self-signed identity and
//! an `authorized_keys` allowlist, connects a client that pins the server key on
//! first contact, and exercises every implemented operation over real QUIC.
//! No FUSE required.
//!
//! Run with: `cargo run --bin test-harness`

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::TempDir;
use tracing::{error, info};

use quicfs_client::conn::{ConnManager, MountConfig, TofuPolicy};
use quicfs_common::identity::Identity;
use quicfs_common::trust::AuthorizedKeys;
use quicfs_server::verify::AuthorizedKeysVerifier;

// ── Server bootstrap ──────────────────────────────────────────────────────────

async fn start_server(
    server_identity: Identity,
    authorized_keys_path: std::path::PathBuf,
    export_root: &Path,
    limits: quicfs_server::ConnLimits,
) -> Result<SocketAddr> {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let quic_cfg = quicfs_server::config::QuicSection::default();
    let transport = quicfs_server::endpoint::build_transport(&quic_cfg);

    let authorized = AuthorizedKeys::load(&authorized_keys_path)?;
    let verifier = AuthorizedKeysVerifier::new(authorized, false);

    let ep = quicfs_server::endpoint::make_server_endpoint(
        &server_identity.cert_pem,
        &server_identity.key_pem,
        verifier,
        listen,
        transport,
        false, // migration off for the loopback test
    )
    .context("start server")?;

    let bound = ep.local_addr().context("server local addr")?;
    info!(bound = %bound, fingerprint = %server_identity.fingerprint, "test server listening");

    let export_root: Arc<Path> = Arc::from(export_root);
    let server_id = uuid::Uuid::new_v4().to_string();

    tokio::spawn(async move {
        loop {
            let incoming = match ep.accept().await {
                Some(i) => i,
                None => break,
            };
            let root = Arc::clone(&export_root);
            let sid = server_id.clone();
            let lim = limits.clone();
            tokio::spawn(async move {
                if let Err(e) = quicfs_server::handle_connection(incoming, root, sid, lim).await {
                    tracing::warn!("test connection: {e:#}");
                }
            });
        }
    });

    Ok(bound)
}

fn client_config(
    server_addr: SocketAddr,
    client: &Identity,
    known_hosts_path: std::path::PathBuf,
    tofu: TofuPolicy,
) -> MountConfig {
    MountConfig {
        server_addr,
        server_name: "localhost".to_owned(),
        host_key: server_addr.to_string(),
        client_cert_pem: client.cert_pem.clone(),
        client_key_pem: client.key_pem.clone(),
        chunk_size: 262_144,
        tofu,
        known_hosts_path,
    }
}

// ── Functional test cases ─────────────────────────────────────────────────────

async fn run_tests(conn: &ConnManager, root: &Path) -> Result<()> {
    info!("── ping ──────────────────────────────────────");
    conn.ping().await.context("ping")?;
    info!("  PASS");

    info!("── getattr on root ───────────────────────────");
    let root_stat = conn.getattr("/").await.context("getattr /")?;
    assert!(
        root_stat.size == 0 || root_stat.mode != 0,
        "root stat is non-zero"
    );
    info!("  PASS  mode=0o{:o}", root_stat.mode);

    info!("── mkdir ─────────────────────────────────────");
    conn.mkdir("/testdir", 0o755)
        .await
        .context("mkdir /testdir")?;
    assert!(root.join("testdir").is_dir(), "testdir not created");
    info!("  PASS");

    info!("── getattr on new dir ────────────────────────");
    let dir_stat = conn.getattr("/testdir").await.context("getattr /testdir")?;
    assert!((dir_stat.mode >> 12) & 0xF == 0x4, "not a directory");
    info!("  PASS");

    info!("── create + write + read ─────────────────────");
    let (handle, _) = conn
        .create("/testdir/hello.txt", 0, 0o644)
        .await
        .context("create")?;
    let payload = b"Hello, QuicFS!";
    let written = conn.write(handle, 0, payload).await.context("write")?;
    assert_eq!(written as usize, payload.len());
    conn.release(handle).await.context("release after write")?;

    let (rhandle, _) = conn.open("/testdir/hello.txt", 0).await.context("open")?;
    let data = conn.read(rhandle, 0, 1024).await.context("read")?;
    conn.release(rhandle).await.context("release after read")?;
    assert_eq!(data, payload, "read data mismatch");
    info!("  PASS  {} bytes round-tripped", payload.len());

    info!("── readdir ───────────────────────────────────");
    let entries = conn.readdir("/testdir").await.context("readdir")?;
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.contains(&"hello.txt"),
        "hello.txt missing from readdir"
    );
    info!("  PASS  entries={names:?}");

    info!("── rename ────────────────────────────────────");
    conn.rename("/testdir/hello.txt", "/testdir/world.txt", 0)
        .await
        .context("rename")?;
    assert!(
        !root.join("testdir/hello.txt").exists(),
        "old name still exists"
    );
    assert!(
        root.join("testdir/world.txt").exists(),
        "new name not created"
    );
    info!("  PASS");

    // setattr is the path the REAL client uses for truncate/chmod/utimes, and all
    // three sinks now go through open_confined (openat2 RESOLVE_BENEATH). Exercise
    // them functionally to confirm the confined rewrite works, not just compiles.
    info!("── setattr (size/mode/times via confined fd) ──");
    {
        // size -> 3 (valid 0x8)
        conn.setattr("/testdir/world.txt", 0x8, 0, 0, 0, 3, 0, 0)
            .await
            .context("setattr size")?;
        assert_eq!(
            std::fs::metadata(root.join("testdir/world.txt"))
                .unwrap()
                .len(),
            3,
            "setattr size truncation failed"
        );
        // mode -> 0o640 (valid 0x1)
        conn.setattr("/testdir/world.txt", 0x1, 0o640, 0, 0, 0, 0, 0)
            .await
            .context("setattr mode")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(root.join("testdir/world.txt")).unwrap();
            assert_eq!(
                m.permissions().mode() & 0o777,
                0o640,
                "setattr chmod failed"
            );
        }
        // mtime -> a fixed instant (valid 0x20)
        let mtime_ns: i64 = 1_600_000_000_000_000_000;
        conn.setattr("/testdir/world.txt", 0x20, 0, 0, 0, 0, 0, mtime_ns)
            .await
            .context("setattr mtime")?;
        info!("  PASS  (size=3, mode=0o640, mtime set via confined fd)");
    }

    info!("── statfs ────────────────────────────────────");
    let fs = conn.statfs("/").await.context("statfs")?;
    assert!(fs.bsize > 0);
    info!("  PASS  bsize={}", fs.bsize);

    info!("── unlink ────────────────────────────────────");
    conn.unlink("/testdir/world.txt").await.context("unlink")?;
    assert!(
        !root.join("testdir/world.txt").exists(),
        "file still exists after unlink"
    );
    info!("  PASS");

    info!("── rmdir ─────────────────────────────────────");
    conn.rmdir("/testdir").await.context("rmdir")?;
    assert!(
        !root.join("testdir").is_dir(),
        "dir still exists after rmdir"
    );
    info!("  PASS");

    #[cfg(unix)]
    {
        info!("── symlink + readlink ────────────────────────");
        conn.mkdir("/linktest", 0o755)
            .await
            .context("mkdir /linktest")?;
        conn.create("/linktest/target.txt", 0, 0o644)
            .await
            .context("create target")?;
        conn.symlink("/linktest/target.txt", "/linktest/link.txt")
            .await
            .context("symlink")?;
        let target = conn
            .readlink("/linktest/link.txt")
            .await
            .context("readlink")?;
        assert_eq!(target, "/linktest/target.txt");
        info!("  PASS  target={target}");
        conn.unlink("/linktest/link.txt").await.ok();
        conn.unlink("/linktest/target.txt").await.ok();
        conn.rmdir("/linktest").await.ok();
    }

    // O_APPEND (0x400): the server must open the retained fd in append mode so
    // every write lands at EOF and the client-supplied offset is ignored. Without
    // the fix, an existing file opened for append seeks to the bogus offset and
    // overwrites. Discriminates the handle_open O_APPEND change specifically (the
    // open path, not create).
    info!("── O_APPEND ignores client offset ────────────");
    {
        let (ch, _) = conn
            .create("/append.txt", 0, 0o644)
            .await
            .context("create append base")?;
        conn.write(ch, 0, b"AAA")
            .await
            .context("seed append base")?;
        conn.release(ch).await.ok();
        // Re-open O_WRONLY|O_APPEND and write at the bogus offset 0.
        let (ah, _) = conn
            .open("/append.txt", 0x1 | 0x400)
            .await
            .context("open append")?;
        conn.write(ah, 0, b"BBB").await.context("append write")?;
        conn.release(ah).await.ok();
        let (arh, ast) = conn
            .open("/append.txt", 0)
            .await
            .context("open append read")?;
        assert_eq!(
            ast.size, 6,
            "O_APPEND must accumulate (AAA+BBB), not overwrite at offset 0"
        );
        let adata = conn.read(arh, 0, 16).await.context("read append")?;
        assert_eq!(adata, b"AAABBB", "append must land at EOF, not offset 0");
        conn.release(arh).await.ok();
        conn.unlink("/append.txt").await.ok();
        info!("  PASS  offset ignored, appended at EOF (AAABBB)");
    }

    // Positioned-write replay idempotency: the foundation of keep-buffered-across-
    // reconnect. After a reconnect the client re-sends still-unacked positioned
    // chunks against a freshly reopened handle; re-applying the SAME (offset,data)
    // must overwrite identically, even when it overlaps a partially-committed
    // prefix. This proves the server side of that guarantee (the client fh-remap
    // itself needs a live FUSE mount to exercise).
    info!("── positioned write replay is idempotent ─────");
    {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (h, _) = conn
            .create("/replay.bin", 0, 0o644)
            .await
            .context("create replay")?;
        // Original write, then a partial "prefix re-send" (first half) and a full
        // re-send - exactly what a reconnect replay does after a partial commit.
        conn.write(h, 0, &payload).await.context("replay w1")?;
        conn.write(h, 0, &payload[..100_000])
            .await
            .context("replay prefix")?;
        conn.write(h, 0, &payload).await.context("replay full")?;
        conn.release(h).await.ok();
        let (rh, st) = conn.open("/replay.bin", 0).await.context("open replay")?;
        assert_eq!(st.size, payload.len() as u64, "replay changed the size");
        let got = conn
            .read(rh, 0, payload.len() as u32)
            .await
            .context("read replay")?;
        assert!(
            got == payload,
            "re-applied positioned writes must be identical"
        );
        conn.release(rh).await.ok();
        conn.unlink("/replay.bin").await.ok();
        info!("  PASS  (re-applying positioned writes is byte-identical)");
    }

    // Multi-frame streaming: payload > chunk_size (262144) forces the client's
    // write-chunking loop and the server's multi-frame read response. 14-byte
    // payloads never exercise these paths.
    info!("── large multi-frame write + read ────────────");
    let big: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    let frames = (big.len() + 262_143) / 262_144;
    let (h, _) = conn
        .create("/big.bin", 0, 0o644)
        .await
        .context("create big")?;
    let written = conn.write(h, 0, &big).await.context("write big")?;
    assert_eq!(written as usize, big.len(), "short write");
    conn.release(h).await.ok();

    let (rh, st) = conn.open("/big.bin", 0).await.context("open big")?;
    assert_eq!(st.size, big.len() as u64, "size mismatch after write");
    let got = conn
        .read(rh, 0, big.len() as u32 + 10)
        .await
        .context("read big")?;
    assert_eq!(got.len(), big.len(), "read length mismatch");
    assert!(got == big, "round-trip data mismatch");
    // Offset read of the second half must match the corresponding slice.
    let half = (big.len() / 2) as u64;
    let tail = conn
        .read(rh, half, big.len() as u32)
        .await
        .context("read tail")?;
    assert!(tail == big[half as usize..], "offset-read tail mismatch");
    conn.release(rh).await.ok();
    conn.unlink("/big.bin").await.ok();
    info!(
        "  PASS  {} bytes across {frames} write-frames, offset read verified",
        big.len()
    );

    Ok(())
}

// ── Trust-model test cases ────────────────────────────────────────────────────

/// A client whose key is NOT authorized must be rejected by the server.
async fn test_unauthorized_client_rejected(server_addr: SocketAddr, tmp: &TempDir) -> Result<()> {
    info!("── unauthorized client is rejected ───────────");
    let stranger = Identity::generate("stranger")?;
    let kh = tmp.path().join("kh_stranger");
    let cfg = client_config(server_addr, &stranger, kh, TofuPolicy::AcceptNew);
    match ConnManager::connect(cfg).await {
        Ok(c) => {
            c.close().await;
            anyhow::bail!("SECURITY FAILURE: unauthorized client was allowed to connect");
        }
        Err(_) => {
            info!("  PASS  (server refused the unlisted client key)");
            Ok(())
        }
    }
}

/// An authenticated client must NOT be able to create a file outside the export
/// root by planting a symlink and creating through it. Regression test for the
/// dangling-final-component-symlink escape (closed by O_NOFOLLOW in
/// ops::data::handle_create). Without the fix this creates `<outside>/pwned.txt`.
#[cfg(unix)]
async fn test_symlink_escape_blocked(
    conn: &ConnManager,
    root: &Path,
    outside_dir: &Path,
) -> Result<()> {
    info!("── symlink escape is blocked ─────────────────");
    // Attacker plants <root>/escape -> <outside>/pwned.txt (dangling target).
    let outside_target = outside_dir.join("pwned.txt");
    assert!(
        !outside_target.exists(),
        "setup: outside target must not pre-exist"
    );
    let target_str = outside_target.to_str().context("outside path utf8")?;
    conn.symlink(target_str, "/escape")
        .await
        .context("plant symlink")?;
    assert!(
        root.join("escape")
            .symlink_metadata()?
            .file_type()
            .is_symlink(),
        "symlink was not planted"
    );

    // Attacker tries to materialise a file THROUGH the escaping symlink.
    let res = conn.create("/escape", 0x200 /* O_TRUNC */, 0o644).await;

    assert!(
        res.is_err(),
        "SECURITY FAILURE: create through an escaping symlink succeeded: {res:?}"
    );
    assert!(
        !outside_target.exists(),
        "SECURITY FAILURE: a file was created OUTSIDE the export root at {}",
        outside_target.display()
    );

    conn.unlink("/escape").await.ok();
    info!("  PASS  (refused to create a file outside the export root via a symlink)");
    Ok(())
}

/// A pinned host whose key changes must be refused (no MITM).
async fn test_host_key_mismatch_rejected(
    server_addr: SocketAddr,
    client: &Identity,
    tmp: &TempDir,
) -> Result<()> {
    info!("── changed host key is rejected ──────────────");
    // Pre-populate known_hosts with a bogus fingerprint for this host.
    let kh_path = tmp.path().join("kh_bogus");
    let mut kh = quicfs_common::trust::KnownHosts::load(&kh_path)?;
    kh.insert(
        &server_addr.to_string(),
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    kh.save()?;

    let cfg = client_config(server_addr, client, kh_path, TofuPolicy::Prompt);
    match ConnManager::connect(cfg).await {
        Ok(c) => {
            c.close().await;
            anyhow::bail!("SECURITY FAILURE: connected despite host-key mismatch");
        }
        Err(_) => {
            info!("  PASS  (client refused the changed server key)");
            Ok(())
        }
    }
}

/// With server metadata durability ON (`sync_metadata`), every namespace op
/// fsyncs the affected parent directory. This exercises that path end to end -
/// including a create directly under the export root (parent == root, the
/// empty-relative-path "." case in openat2) and a cross-directory rename (two
/// distinct parents) - and asserts every op still returns success. It is the
/// regression guard for the fix that a directory-fsync must NOT be reported as an
/// op failure (the mutation already took effect).
async fn test_sync_metadata(tmp: &TempDir) -> Result<()> {
    info!("── metadata durability (sync_metadata) ───────");
    let server = Identity::generate("localhost-dur").context("dur server id")?;
    let client = Identity::generate("dur-client").context("dur client id")?;
    let export_root = tempfile::tempdir().context("dur export root")?;

    let ak_path = tmp.path().join("authorized_keys_dur");
    {
        let mut ak = AuthorizedKeys::load(&ak_path)?;
        ak.authorize(&client.fingerprint, "dur-client")?;
    }

    let limits = quicfs_server::ConnLimits {
        sync_metadata: true,
        ..Default::default()
    };
    let addr = start_server(server.clone(), ak_path, export_root.path(), limits).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let kh = tmp.path().join("kh_dur");
    let cfg = client_config(addr, &client, kh, TofuPolicy::AcceptNew);
    let conn = ConnManager::connect(cfg)
        .await
        .context("dur client connect")?;

    // create directly under root: parent == export root (the "." openat2 case).
    let (h, _) = conn
        .create("/durable.txt", 0, 0o644)
        .await
        .context("durable create at root")?;
    conn.write(h, 0, b"durable")
        .await
        .context("durable write")?;
    conn.release(h).await.ok();

    // rename within the same directory (both parents == root, dedup to one fsync).
    conn.rename("/durable.txt", "/durable2.txt", 0)
        .await
        .context("durable rename same-dir")?;

    // mkdir + nested create (parent below root).
    conn.mkdir("/sub", 0o755).await.context("durable mkdir")?;
    let (h2, _) = conn
        .create("/sub/x.txt", 0, 0o644)
        .await
        .context("durable nested create")?;
    conn.release(h2).await.ok();

    // rename across directories (old.parent != new.parent -> fsync BOTH).
    conn.rename("/durable2.txt", "/sub/durable2.txt", 0)
        .await
        .context("durable rename cross-dir")?;

    // removals + rmdir.
    conn.unlink("/sub/x.txt")
        .await
        .context("durable unlink x")?;
    conn.unlink("/sub/durable2.txt")
        .await
        .context("durable unlink durable2")?;
    conn.rmdir("/sub").await.context("durable rmdir")?;

    // The export must be consistent after the rename/remove chain: everything is
    // gone (the last file was unlinked, its directory removed).
    assert!(
        !export_root.path().join("sub").exists(),
        "sub dir should be removed"
    );
    assert!(
        !export_root.path().join("durable2.txt").exists()
            && !export_root.path().join("durable.txt").exists(),
        "renamed-away files should not remain at the root"
    );
    conn.close().await;
    info!("  PASS  (all metadata-durable ops succeeded; root-parent fsync path exercised)");
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("QuicFS integration test (TOFU trust model)");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let export_root = tempfile::tempdir().context("export root")?;
    info!(root = %export_root.path().display(), "export root");

    // Identities (no CA).
    let server = Identity::generate("localhost").context("server identity")?;
    let client = Identity::generate("test-client").context("client identity")?;

    // Authorize the client's key on the server.
    let ak_path = tmp.path().join("authorized_keys");
    {
        let mut ak = AuthorizedKeys::load(&ak_path)?;
        ak.authorize(&client.fingerprint, "test-client")?;
    }

    let server_addr = start_server(
        server.clone(),
        ak_path.clone(),
        export_root.path(),
        quicfs_server::ConnLimits::default(),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // First contact pins the server key (AcceptNew so the test is non-interactive).
    let kh_path = tmp.path().join("known_hosts");
    let cfg = client_config(server_addr, &client, kh_path.clone(), TofuPolicy::AcceptNew);
    let conn = ConnManager::connect(cfg).await.context("client connect")?;
    info!(pinned = ?conn.server_fingerprint(), "connected; host key pinned");
    assert_eq!(
        conn.server_fingerprint().as_deref(),
        Some(server.fingerprint.as_str())
    );

    let result = run_tests(&conn, export_root.path()).await;
    conn.close().await;
    result?;

    // Re-connect with the host already pinned (enforce path must succeed).
    info!("── reconnect with pinned key ─────────────────");
    let cfg2 = client_config(server_addr, &client, kh_path.clone(), TofuPolicy::Strict);
    let conn2 = ConnManager::connect(cfg2)
        .await
        .context("reconnect with pinned key")?;
    conn2.ping().await.context("ping after re-pin")?;
    info!("  PASS");

    // Security properties.
    #[cfg(unix)]
    test_symlink_escape_blocked(&conn2, export_root.path(), tmp.path()).await?;
    conn2.close().await;
    test_unauthorized_client_rejected(server_addr, &tmp).await?;
    test_host_key_mismatch_rejected(server_addr, &client, &tmp).await?;
    test_sync_metadata(&tmp).await?;

    match Ok::<(), anyhow::Error>(()) {
        Ok(()) => {
            info!("ALL TESTS PASSED");
            Ok(())
        }
        Err(e) => {
            error!("TESTS FAILED: {e:#}");
            std::process::exit(1);
        }
    }
}
