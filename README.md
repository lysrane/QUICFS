# QuicFS

A QUIC-based remote filesystem, written in Rust. You run a small server that
exports one directory tree, and a Linux FUSE client mounts it over a single
encrypted [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) connection:

```sh
quicfs alice@fileserver:/projects /mnt/projects
```

Trust works like SSH: on first connect you confirm the server's key fingerprint,
it is pinned, and you are not asked again. There is no certificate authority and
no certificate wrangling.

This README is the complete guide: overview, the QUIC and security design, and
everything needed to build, test, install, and run it. For the protocol and
design rationale see [WHITEPAPER.md](WHITEPAPER.md).

---

## Why this exists

Most remote filesystems run over TCP: SSHFS tunnels one SSH connection,
NFS-over-TCP and SMB use one or a few TCP connections per mount. Two TCP
properties hurt a filesystem on an imperfect network:

- **Head-of-line blocking within a connection.** Logical operations multiplexed
  over a single TCP connection are delivered in order, so one lost segment stalls
  every request sharing that connection until the gap is retransmitted.
  (NFS `nconnect` and SMB3 multichannel spread load across several connections,
  which reduces this but does not remove it per connection.)
- **A connection is bound to its 4-tuple.** Because a TCP connection is
  identified by (source IP, source port, destination IP, destination port),
  changing the client's network address forces the connection to be
  re-established.

QUIC, designed for HTTP/3, addresses both directly: it multiplexes independent
streams that are not head-of-line-blocked by each other, and it identifies a
connection by a Connection ID instead of an IP/port pair, so a connection can
survive an address change. QUIC also carries TLS 1.3 as a mandatory part of the
protocol, so the transport is always encrypted. QuicFS points those properties
at a filesystem: a server that exports a directory and a Linux FUSE client that
mounts it.

It is an early-stage project. The core read/write/metadata path works and is
tested (including a live two-machine test that kills the server mid-write and
confirms the write resumes byte-identical after reconnect). Remaining hardening
items are listed under [Reliability and limitations](#reliability-and-limitations).

---

## What QuicFS is

- A **server** (`quicfs-server`) that exports one directory tree over QUIC.
- A **Linux FUSE client** (`quicfs`) that mounts that tree locally.
- A wire protocol where **each filesystem operation gets its own QUIC stream**,
  so a slow or lost operation does not block the others.
- Transport security is **TLS 1.3, always on**. There is no unencrypted mode.
- Authentication is **Trust On First Use (TOFU) public-key pinning**, modelled on
  SSH `known_hosts` (the client trusts the server) and `authorized_keys` (the
  server trusts the client). After this first mention the document uses the
  acronym TOFU.

## Who it is for

- People who mount a remote directory over a **lossy, high-latency, or roaming
  link** (mobile tethering, long-distance, jittery VPN, Wi-Fi that hands off to
  another access point) and are tired of the mount stalling or dying.
- People who want SSH-style ergonomics (`user@host:/path /mnt`, a host-key prompt
  on first connect) without running a full SSH server, and who are comfortable
  with an early-stage tool.
- People who want to see QUIC used for something other than HTTP.

On a fast, reliable LAN the difference between QuicFS and a TCP-based mount is
small. The point is the bad-network case.

---

## What QUIC changes for a remote filesystem

The table compares QuicFS to a TCP-based remote filesystem (SSHFS is the familiar
example). It states only what is implemented and verified in this repository.

| Property | SSHFS (SSH over TCP) | QuicFS (QUIC) |
|---|---|---|
| Head-of-line blocking | A lost segment stalls every request multiplexed on the SSH connection | None across streams: each operation is its own QUIC stream, a lost packet only affects that stream |
| Client address change | The TCP connection is bound to the 4-tuple, so the mount is re-established | The connection is identified by a Connection ID and migrates (validated by a source-address-change test, see below) |
| Encryption | SSH transport | TLS 1.3, mandatory, verified on the wire (see [Encryption](#encryption-in-transit-verified)) |
| Trust model | TOFU host keys + `authorized_keys` | The same model: TOFU key pinning + `authorized_keys` |
| Server requirement | A full SSH daemon | A single small daemon exporting one directory |
| Maturity | Mature, widely deployed | Early-stage (this project) |

SSHFS is mature and widely used, it handles symlink and edge cases that QuicFS
may not, and it does not carry the open reliability items listed later here.

---

## How the handshake works

There are two handshakes when a client mounts: the **QUIC/TLS 1.3 transport
handshake** that builds an encrypted, mutually authenticated channel, and then a
small **QuicFS application handshake** for capability negotiation.

### The QUIC + TLS 1.3 transport handshake

QUIC carries the TLS 1.3 handshake inside its own CRYPTO frames during connection
setup, in a single round trip for a full handshake:

```
client                                                        server
  | --- Initial: ClientHello (TLS 1.3, key share, ALPN) ------> |
  |                                                             |  picks params,
  |                                                             |  signs the handshake
  | <-- Initial/Handshake: ServerHello, server Certificate, --- |
  |        CertificateVerify, Finished                          |
  | --- Handshake: client Certificate, CertificateVerify, ----> |
  |        Finished  (mutual TLS: the client authenticates too) |
  | ====== connection established, all later packets 1-RTT =====|
  |                  encrypted with TLS 1.3 keys                 |
```

Two things are specific to QuicFS:

- **The certificates are self-signed identities, not CA-issued.** There is no
  certificate authority. Each side presents its own self-signed certificate and
  proves possession of its private key, because TLS 1.3 requires a
  `CertificateVerify` signature over the handshake transcript and QuicFS verifies
  that signature (it is delegated to rustls, not skipped). Trust is by the pinned
  key, so the certificate's validity dates are not checked; the certificate
  exists only to carry the public key, which TLS 1.3 requires.
- **Authorization is by key fingerprint, checked by custom verifiers.** Instead
  of validating a certificate chain, each side computes the SHA-256 fingerprint
  of the peer's public key (the certificate's SubjectPublicKeyInfo, formatted
  `SHA256:<base64>` like OpenSSH) and checks it:
  - the client's verifier compares the server fingerprint against `known_hosts`
    (TOFU: capture-and-pin on first contact, enforce afterwards);
  - the server's verifier compares the client fingerprint against
    `authorized_keys`.

A non-QuicFS QUIC peer is rejected at the TLS layer because both endpoints
require the ALPN identifier `quicfs/1`. Because the channel is encrypted and both
peers are authenticated before any filesystem bytes flow, file contents and file
names never appear in cleartext on the network.

### TOFU pinning, step by step

First connect to an unknown host:

```
The authenticity of host 'fileserver:9001' can't be established.
Key fingerprint is SHA256:9z8y7x...
Are you sure you want to continue connecting (yes/no)? yes
```

On `yes`, the fingerprint is written to `~/.config/quicfs/known_hosts`, and every
later connect enforces it. If the server's key ever changes, QuicFS refuses to
connect with a loud `REMOTE HOST IDENTIFICATION HAS CHANGED` warning, like SSH.
`--accept-new` pins without prompting (for automation) and `--strict-host-key`
refuses unknown hosts outright.

### The QuicFS application handshake

Once the encrypted channel is up, the client opens the first QUIC stream and
sends a small `Handshake` message for version and capability negotiation. This is
not where authentication happens (that already occurred at the TLS layer); it
only agrees on protocol features. Every subsequent operation runs on its own
fresh bidirectional stream.

---

## Encryption in transit, verified

TLS 1.3 is mandatory, but it is worth checking on the wire. Reproduce it with
`tcpdump`:

```sh
# 1. capture the QuicFS UDP traffic (adjust the interface and port)
sudo tcpdump -i lo -nn "udp port 9001" -w /tmp/quicfs.pcap &

# 2. write a known marker string through the mount
echo "MY_UNIQUE_CANARY_STRING" > /mnt/projects/canary.txt

# 3. stop tcpdump, then search the capture for the marker
sudo grep -a "MY_UNIQUE_CANARY_STRING" /tmp/quicfs.pcap   # expect: no matches
```

In this project's runs of that procedure (loopback and a real two-machine LAN),
the captured traffic was UDP/QUIC and the canary string, both the file content
and the file name, did not appear anywhere in the capture, while the same bytes
were of course present in cleartext in the file on disk. The one piece of
metadata that can be visible in the QUIC Initial packets is the TLS SNI (the
server name), which is cosmetic here because trust is by pinned key, not by name.

---

## Connection migration, verified

QUIC connections are identified by a Connection ID, not by the client's IP and
port, so a client that changes address keeps the same connection. This is the
main reason to build a filesystem on QUIC: a mount can survive Wi-Fi to LTE or a
NAT rebind without remounting.

This was validated by interposing a small UDP relay between client and server and
changing the relay's source port mid-transfer (a stand-in for the client's
address changing). The server performed QUIC path validation, migrated the live
connection to the new address, and a continuous read/write loop saw zero failures
across the change. This is a single-host simulation of an address change, not yet
a field test across real cellular and Wi-Fi networks.

Separately, if the connection is fully lost (not migrated) and re-established,
buffered writes are kept until the server acknowledges them and replayed against
a re-opened handle, so an ordinary (positioned) write survives a reconnect. This
was confirmed live by killing the server mid-write and restarting it: the write
resumed and the file was byte-identical. See
[Reliability and limitations](#reliability-and-limitations) for the edges.

---

## Performance

Measured on a gigabit LAN between two machines (your numbers will vary with
hardware and network):

- Raw link capacity (iperf3): about 940 Mbps, roughly 112 MiB/s.
- QuicFS sequential **read**: about 90 MB/s.
- QuicFS sequential **write**: about 90 MB/s.

Writes were originally limited to about 10 MB/s by a write path that sent one
network round trip per small FUSE write. That is fixed: contiguous buffered writes
are coalesced into a single streaming operation per flush, which raised sequential
write throughput to roughly the read rate. Two parallel transfers reach about
107 MiB/s aggregate, which indicates the remaining single-transfer gap to line
rate is the client's one-operation-at-a-time path; pipelining is a possible
improvement. Metadata-heavy small-file workloads are limited by per-operation
latency because the FUSE session is single-threaded.

---

## Requirements

**Server** (Linux, macOS, or Windows):

- **Rust 1.80 or newer** (the code uses `std::sync::LazyLock`, stabilized in 1.80).
- **CMake 3.x and a C compiler** (`gcc` / `cl`). These are needed to build
  `aws-lc-sys`, pulled in as the default `aws-lc-rs` crypto backend of `rustls`,
  and to build `ring` (the cryptographic provider QuicFS actually installs at
  runtime). Both are compiled during the build.

**Client** (Linux only, because it uses FUSE):

- `fuse3`, `libfuse3-dev`, and `pkg-config`, plus the same Rust and build tooling.

```sh
# Debian / Ubuntu
sudo apt install cmake gcc pkg-config fuse3 libfuse3-dev
# Fedora / RHEL
sudo dnf install cmake gcc pkgconf-pkg-config fuse3 fuse3-devel
```

The FUSE client modules are gated with `#[cfg(target_os = "linux")]`, so on
non-Linux hosts only the server and the test harness build.

---

## Build

```sh
cargo build --release
#   target/release/quicfs-server   the server daemon
#   target/release/quicfs          the client (FUSE mount), Linux only
```

---

## Tests

```sh
# unit tests across all crates
cargo test --workspace

# protocol-level end-to-end integration test (no FUSE, any OS). It generates
# fresh TOFU identities in memory, authorizes the client key, starts a server on
# a random loopback port, and exercises every implemented operation plus the
# security properties (unauthorized client refused, changed host key refused,
# symlink escape blocked). Expected final line: ALL TESTS PASSED.
cargo run --bin test-harness
```

**Fuzzing** (optional, needs the nightly toolchain and `cargo-fuzz`): the
export-root jail and the wire-frame decoders have coverage-guided fuzz targets,
and the jail invariant also runs as a property test under `cargo test`. See
[fuzz/README.md](fuzz/README.md):

```sh
cargo +nightly fuzz run resolve          # the export-root jail invariant
cargo +nightly fuzz run decode_requests  # wire-frame deserialization
cargo +nightly fuzz run open_confined    # the kernel-enforced jail
```

---

## Install

For a real deployment, install the server on the machine that holds the files and
the client on the machine that mounts them.

**Debian / Ubuntu packages** (build them locally with `cargo-deb`):

```sh
cargo install cargo-deb
cargo deb -p quicfs-server     # produces target/debian/quicfs-server_*.deb
cargo deb -p quicfs-client     # produces target/debian/quicfs_*.deb (depends on fuse3)
sudo apt install ./target/debian/quicfs-server_*.deb   # on the server
sudo apt install ./target/debian/quicfs_*.deb          # on the client
```

**Install script** (any Linux):

```sh
sudo ./packaging/install.sh server     # on the server machine
sudo ./packaging/install.sh client     # on the client machine
```

---

## Run: two machines

### 1. Start the server (the machine with the files)

Edit `/etc/quicfs/server.toml` (the package ships an annotated example at
`packaging/server.toml.example`); at minimum set the export directory and port:

```toml
[server]
listen      = "0.0.0.0:9001"
export_root = "/srv/quicfs"
```

```sh
sudo systemctl enable --now quicfs-server   # or: quicfs-server --config /etc/quicfs/server.toml
sudo ufw allow 9001/udp                      # open the UDP port (QUIC is UDP)
```

On first start the server generates its own key (no CA) and prints its
fingerprint; `quicfs-server fingerprint` shows it again.

### 2. Pair the client key, once (the mounting machine)

```sh
quicfs key
# SHA256:AbCdEf...   <- copy this
```

On the server, authorize that client:

```sh
sudo quicfs-server authorize SHA256:AbCdEf... --comment alice@laptop \
     --config /etc/quicfs/server.toml
```

On a trusted single-user network you can instead set `allow_any_client = true`
under `[auth]` in `server.toml`. It is convenient but not recommended in
production.

### 3. Mount (Linux client)

```sh
mkdir -p /mnt/projects
quicfs alice@fileserver:/projects /mnt/projects
# answer "yes" to the host-key prompt on first connect

echo "hello" > /mnt/projects/test.txt && cat /mnt/projects/test.txt
fusermount3 -u /mnt/projects     # unmount (or Ctrl-C / SIGTERM the process)
```

Test connectivity without mounting:

```sh
quicfs ping alice@fileserver -p 9001
```

---

## Command reference

```
quicfs [user@]host[:/remote/path] <mountpoint> [options]   mount (default form)
quicfs ping [user@]host [options]                          test connectivity
quicfs key                                                 print this client's key fingerprint
quicfs known-hosts                                         list pinned server keys

quicfs-server --config <path>                              run the server
quicfs-server fingerprint                                  print the server's key fingerprint
quicfs-server authorize SHA256:... [--comment C]           allow a client key
```

Common mount options: `-p/--port`, `--accept-new`, `--strict-host-key`, `--ro`,
`--allow-other`, `--cache-ttl`, `--write-buf`, `--coalesce-ms`, `--uid`/`--gid`,
`--log-level`. The full server config reference is `packaging/server.toml.example`.

---

## Files at a glance

| Path | What |
|---|---|
| `~/.config/quicfs/client.{crt,key}` | client identity (auto-generated, key is `0600`) |
| `~/.config/quicfs/known_hosts` | pinned server fingerprints |
| `/var/lib/quicfs/server.{crt,key}` | server identity (auto-generated) |
| `/etc/quicfs/server.toml` | server config |
| `/etc/quicfs/authorized_keys` | permitted client fingerprints |

---

## UDP socket tuning (Linux server, optional)

QUIC is UDP; larger socket buffers help on high-bandwidth links. Add to
`/etc/sysctl.d/quicfs.conf` on the server host, then `sudo sysctl --system`:

```
net.core.rmem_max     = 26214400
net.core.wmem_max     = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

---

## Security notes

- All traffic is TLS 1.3; there is no plaintext mode. File content and names are
  encrypted in transit (verified above). No application-layer crypto is
  hand-rolled; everything is rustls / ring / rcgen / sha2.
- Trust is TOFU key pinning plus `authorized_keys`. Both sides verify the TLS
  handshake signature, so key possession is always proven and the pinning is not
  cosmetic. The server requires client authentication (a no-certificate peer is
  rejected at the TLS layer).
- The server confines clients to its single `export_root`. Path handling rejects
  `..`, null bytes, and intermediate-symlink escapes, and on Linux the kernel
  itself enforces the jail for every path-based operation: the open sinks (open,
  create, truncate, and the chmod/utimes/truncate behind `setattr`) use
  `openat2(RESOLVE_BENEATH)`, and the namespace operations (mkdir, rmdir, unlink,
  rename, symlink, link, readlink) run their `*at` syscall against a parent
  directory opened the same confined way, on a single trailing component the call
  does not follow. The kernel refuses any resolution that would leave the export
  root, including a symlink swapped in after the initial path check, which closes
  the resolve-then-use race for both the open sinks and the namespace ops. The
  jail is fuzz-tested (a libFuzzer target over `openat2` with planted escaping
  symlinks), has symlink-escape regression tests on both the open and namespace
  paths, and a property test that runs in `cargo test`.
- Per-connection bounds limit open handles, a server-wide limit (plus an optional
  per-source-IP cap) bounds concurrent connections, the handshake has a timeout,
  and every frame is size-capped.

---

## Reliability and limitations

The data path for the common single-writer case is tested: large-file integrity,
write coalescing, truncate ordering, a fault-injection suite that confirms a
failed flush surfaces an error rather than silently losing data, and a live
two-machine test that kills the server mid-write and confirms the write resumes
byte-identical after reconnect. Known remaining items:

- **Reconnect survival, and its edges.** A connection drop or migration is handled
  gracefully: buffered writes are kept until the server acknowledges them and
  replayed against a re-opened handle, so an ordinary (positioned) write survives
  a server restart transparently. Two caveats: an `O_APPEND` write in flight at
  the moment of a drop is reported as an error rather than replayed (replaying it
  could double-append), and if the server stays unreachable past the bounded
  buffer/retention window the write fails loudly. Across a reconnect, acknowledged
  data is not silently lost: it either persists or `close()`/`fsync()` returns an
  error. The inherent exception is the client process itself being killed (a crash
  or SIGKILL) with writes still buffered locally; as with any write-back cache
  those bytes are lost, and because the process is gone there is no error left to
  report.
- **Durability on server power loss.** A successful `close()` flushes data to the
  server's page cache; it does not force the server to fsync to disk unless the
  application calls `fsync` or the operator enables the opt-in `[durability]`
  options (`sync_on_close`, `sync_metadata`). A server power loss in that window
  can lose recently written data, as with many network filesystems.
- **Concurrent and multi-client writes.** There is no byte-range locking, so two
  writers to the same region are last-writer-wins or can interleave. QuicFS is
  single-writer oriented today.
- **No change notification.** Without a watch mechanism, a client can serve
  slightly stale metadata for the cache TTL after another client changes a file.
- **Throughput.** The FUSE session is single-threaded, which caps small-file and
  single-stream throughput; this is deliberate for now to keep the write-ordering
  and reconnect machinery simple.

---

## Repository layout

```
QuicFS/
  common/          shared wire types and trust primitives
  server/          quicfs-server binary and library
  client/          quicfs binary and library (FUSE client, Linux)
  test-harness/    end-to-end integration test (functional + security)
  fuzz/            cargo-fuzz targets (export-root jail, frame decoders, fingerprint parser)
  packaging/       systemd unit, example config, install.sh, deb metadata
  WHITEPAPER.md    protocol and design document
  AUTHORS.md       maintainer and contact
```

---

## Contributing

Contributions and security reports are welcome, but responses will be slow by
design: there is no committed response time, and a reply may realistically take
weeks or months, security reports included. The maintainer keeps time online and
hands-on technical involvement to a minimum. Please plan any security disclosure
timeline around a slow, best-effort response. See [AUTHORS.md](AUTHORS.md) for
contact.

---

## License

MIT. See [LICENSE](LICENSE).
