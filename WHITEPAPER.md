# QuicFS - QUIC-Based Remote Filesystem

**Status:** design + as-built
**Scope:** read/write POSIX-approximate remote filesystem over QUIC (RFC 9000)
**Client:** Linux FUSE daemon (the `quicfs` binary)
**Server:** portable Rust daemon (the `quicfs-server` binary)
**Transport:** QUIC over UDP, TLS 1.3 (mandatory inside QUIC)

This document describes what QuicFS does today. Features that are scoped but not
yet built are labeled inline as "reserved / not yet implemented (future)" so the
wire constants and roadmap stay visible without overstating the running system.

---

## 1. Goals and Non-Goals

### Goals

- Mount a remote directory tree as a local FUSE filesystem.
- Use QUIC properties that matter for a filesystem: per-stream independent
  delivery (no head-of-line blocking across concurrent operations), and
  connection migration so a client that changes IP keeps its session.
- Encrypt all traffic in transit. TLS 1.3 is mandatory in QUIC; there is no
  plaintext mode.
- Authenticate both ends by public key using Trust On First Use (TOFU) pinning,
  the SSH `known_hosts` / `authorized_keys` model. There is no certificate
  authority.
- SSHFS-style usability: `quicfs [user@]host[:/remote/path] <mountpoint>`.
- One static server binary; one static client binary that embeds the FUSE
  driver.

### Non-Goals

- Full POSIX compliance. Byte-range locks are reserved in the protocol but have
  no server handler (see section 5.3 and 10).
- HTTP/3 compatibility. QuicFS speaks a custom application protocol over QUIC,
  not HTTP/3.
- Multi-server federation.
- A kernel module. The client is FUSE userspace only.

---

## 2. Why QUIC Over TCP for a Filesystem

The specific QUIC properties QuicFS relies on:

**No head-of-line blocking across operations.** When logical operations are
multiplexed over a single TCP connection (as in any HTTP/2-style transport), a
lost segment stalls every one of them until the gap is retransmitted. In
QUIC each stream is independently flow-controlled, so a lost packet carrying one
stream's bytes does not delay another stream. QuicFS puts each filesystem
operation on its own QUIC stream (section 5.1), so concurrent reads do not block
one another on a lossy path.

**Connection migration.** A QUIC connection is identified by Connection IDs, not
by the 4-tuple (src IP, src port, dst IP, dst port). When the client's source
address changes (Wi-Fi to LTE), QUIC validates the new path with
PATH_CHALLENGE/PATH_RESPONSE and the connection survives without a remount. The
server enables this with `migration` in its config (section 8.1); the client
endpoint accepts the migrated path automatically. Surviving a client address
change is the primary motivation for building the filesystem on QUIC.

**Multiplexing over one UDP socket.** Many concurrent operations share one
socket. The QUIC stack owns congestion control, loss recovery, and per-stream
flow control. The OS sees one socket; the application sees N independent ordered
byte streams.

---

## 3. Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│  Client (Linux)                                               │
│                                                               │
│  VFS syscall                                                  │
│      ↓                                                        │
│  FUSE kernel module                                           │
│      ↓                                                        │
│  quicfs FUSE daemon (userspace, fuser)                        │
│      ├─ FUSE op handlers (one QUIC stream per operation)      │
│      ├─ metadata cache (LRU, TTL-based)                       │
│      ├─ keep-until-acked write buffer (coalesce + replay)     │
│      └─ QUIC connection manager (quinn) + TOFU pinning        │
│              ↓ QUIC/UDP + TLS 1.3 (ALPN quicfs/1)            │
└──────────────────────────┬────────────────────────────────────┘
                           │ UDP
┌──────────────────────────┴────────────────────────────────────┐
│  quicfs-server daemon                                         │
│      ├─ QUIC endpoint (quinn)                                 │
│      ├─ per-connection handler + handshake                    │
│      ├─ stream dispatcher (one Tokio task per stream)         │
│      ├─ client key authorization (authorized_keys, at TLS)    │
│      ├─ path sanitizer + openat2(RESOLVE_BENEATH) confinement │
│      ├─ handle table (retained file descriptors)             │
│      └─ OS filesystem backend                                 │
│              ↓                                                │
│  Host filesystem (exported root)                              │
└───────────────────────────────────────────────────────────────┘
```

The QUIC and TLS stack is `quinn` over `rustls`. The FUSE driver is `fuser`.
Frames are MessagePack via `rmp-serde`. The runtime is `tokio`.

---

## 4. QUIC Transport Layer

### 4.1 Library

The implementation uses `quinn` (async Rust QUIC) over `rustls` (TLS 1.3),
running on `tokio`. The FUSE driver is `fuser`. Self-signed identity certificates
are generated with `rcgen`. The QUIC stack is pure Rust; there is no dependency
on a C QUIC library.

### 4.2 ALPN

Both endpoints set the ALPN protocol identifier `quicfs/1` (constant
`ALPN_PROTOCOL`). A QUIC peer that does not offer it fails the TLS handshake
(`no_application_protocol`) before reaching the application handshake, so a stray
non-QuicFS QUIC client never reaches the app layer. The suffix is bumped on any
wire-incompatible change.

### 4.3 Connection Setup

```
Client                              Server
  │                                    │
  │─── QUIC Initial (CRYPTO) ─────────►│  TLS ClientHello, ALPN quicfs/1,
  │                                    │  client cert (mutual auth)
  │◄── QUIC Handshake (CRYPTO) ────────│  TLS ServerHello + server cert
  │─── QUIC Handshake complete ───────►│
  │◄── QUIC 1-RTT ready ───────────────│
  │                                    │
  │─── Stream: Handshake RPC ─────────►│  capability negotiation (op 0xF0)
  │◄── Stream: HandshakeResponse ──────│
  │                                    │
  │─── Stream: GetAttr("/") ──────────►│  first filesystem op
  │◄── Stream: GetAttrResponse ────────│
```

Mutual TLS authentication happens during the QUIC handshake: the client always
presents a client certificate, and the server requires one (section 6). Key
identity is checked at the TLS layer by fingerprint, not by a CA.

### 4.4 0-RTT Resumption (reserved / not yet implemented, future)

0-RTT / early-data resumption is not implemented. A reconnect after connection
loss uses a normal 1-RTT handshake. There is a `zero_rtt` field in the server
`[quic]` config, but it is currently inert (never read). What gives QuicFS its
reconnect resilience today is the application layer, not 0-RTT: the client keeps
positioned writes buffered until the server acknowledges them and replays them
after a fresh handshake (section 7.5 and 9).

### 4.5 Connection Migration

The server sets `migration` (default true) on its QUIC config so a peer can keep
its connection across a source-address change. `quinn` performs path validation.
Open handles and in-flight RPCs are unaffected because the connection (and its
Connection IDs) is unchanged; this is distinct from connection loss, which forces
a reconnect (section 9).

### 4.6 Flow Control and Timeouts

The server applies these from its `[quic]` config (defaults shown):

```toml
[quic]
connection_receive_window    = 67108864    # 64 MiB
stream_receive_window        = 16777216    # 16 MiB
max_concurrent_bidi_streams  = 256
keep_alive_interval_ms       = 15000       # 15 s
idle_timeout_ms              = 300000      # 5 min
```

Timeouts differ by endpoint on purpose:

- The **server** uses its configured keep-alive (15 s default) and idle timeout
  (300 s default).
- The **client** hard-codes a 4 s keep-alive and a 12 s idle timeout. The short
  values let the client detect a dead or unreachable server promptly (a hard
  server kill sends no QUIC CLOSE), error the connection, and reconnect rather
  than stalling each operation until the per-RPC deadline. keep-alive (4 s) is
  kept below idle (12 s) so an otherwise-idle mount stays connected while a
  black-holed peer is declared dead in roughly 12 s.

The client also bounds each operation by a 30 s wall-clock RPC deadline so a
wedged server cannot block a FUSE callback forever.

---

## 5. Application Protocol

### 5.1 Stream Model

Each filesystem operation uses one bidirectional QUIC stream. Streams are cheap
(no TLS handshake per stream), so one-stream-per-operation is the model.

```
Client opens a bidirectional stream
Client sends: [4-byte length][request frame]
Server sends: [4-byte length][response frame]
  (streaming ops send multiple frames; the last is marked eof or done)
Both sides finish the stream (FIN)
```

The length prefix is a 4-byte big-endian `uint32` giving the byte length of the
following frame. The maximum single frame size is 16 MiB (`MAX_FRAME_SIZE`),
enforced on both read and write. This is a hard wire constant that bounds
per-stream read allocation (DoS protection); it is intentionally not operator
tunable. A larger frame is always a protocol violation.

### 5.2 Frame Format

Frames are encoded as MessagePack with **named string keys** (`rmp-serde`'s
`to_vec_named`). Each frame is a single flat map. There is no integer field-ID
scheme and no nested `payload` submap. Every frame carries at least:

- `op` (`u8`): the operation code (section 5.3).
- `seq` (`u64`): a client-assigned sequence number used for logging and tracing.

Operation-specific fields sit alongside `op` and `seq` in the same flat map. For
routing, the receiver first decodes a minimal `Envelope { op, seq }` and then
decodes the full frame for the matched operation.

Examples of the on-the-wire shape (field names are exact):

```
GetAttr request:  { op: 0x01, seq: N, path: "/dir/file" }
GetAttr response: { op: 0x01, seq: N, status: 0, stat: { ... } | null }
```

Binary payloads (`data` in Read and Write) are encoded as MessagePack `bin`
(`serde_bytes`), not arrays of integers.

### 5.3 Operation Codes

```
Metadata operations:
  0x01  GetAttr
  0x02  SetAttr
  0x03  ReadDir
  0x04  MkDir
  0x05  RmDir
  0x06  Unlink
  0x07  Rename
  0x08  Symlink
  0x09  ReadLink
  0x0A  Link
  0x0B  StatFS

File operations:
  0x10  Open
  0x11  Release
  0x12  Create
  // 0x13 is unused: truncation is SetAttr with the size bit set (0x30), not a
  // separate opcode.

Data operations:
  0x20  Read          // one request; server streams response frames until eof
  0x21  Write         // client streams request frames; server replies once
  0x22  Fsync

Extended attributes (reserved opcodes, no handler yet, future):
  0x30  GetXAttr
  0x31  SetXAttr
  0x32  ListXAttr
  0x33  RemoveXAttr

Byte-range / advisory locking (reserved opcodes, no handler yet, future):
  0x40  Lock
  0x41  Unlock

Control:
  0xF0  Handshake
  0xF1  Ping
  0xF2  Watch         // reserved opcode, no handler yet (future)
```

Every opcode value above is defined as a constant in the wire protocol. The
opcodes in the "reserved" groups (xattr 0x30-0x33, lock 0x40-0x41, and Watch
0xF2) have no server dispatch handler. The server's dispatcher answers any
unrecognized or unhandled opcode with a `StatusResponse` carrying
`InvalidArg` (status 8). The opcode constants are kept stable so these features
can be added without a wire renumber.

### 5.4 Handshake (op 0xF0)

The first stream a client opens must be the Handshake exchange. Both request and
response are flat maps. There is no nested `payload` and no `token` field.

Request (client to server):

```
{
  op:         0xF0,
  seq:        1,
  version:    1,
  client_id:  "<uuid>",      // logging only; never used for auth
  features:   [],            // client sends an empty feature list
  chunk_size: 262144,        // requested max data chunk (server may clamp)
  auth_type:  "mtls"         // the only accepted value
}
```

Response (server to client):

```
{
  op:          0xF0,
  seq:         1,
  status:      0,            // 0 = OK
  version:     1,
  features:    [],           // negotiated subset; server supports none today
  chunk_size:  262144,       // clamped to a 4 MiB server maximum
  server_id:   "<uuid>",
  export_root: "<display name>"  // informational only (the export dir basename)
}
```

Authentication is established at the TLS layer before any frame is exchanged
(section 6). The Handshake op only negotiates capabilities and reports identity:

- `auth_type` must be exactly `"mtls"`. Any other value is rejected with a
  `Permission` status and the connection is closed. ("mtls" here means
  certificate-based mutual TLS auth, with the client's key authorized by
  fingerprint; it does not imply a CA.)
- `features` is an empty list from the client, and the server supports an empty
  feature set: the intersection is empty. No feature flags are implemented.
- `chunk_size` is clamped to a 4 MiB server-side maximum; an over-large request
  is rejected with `InvalidArg`.

The session's authenticated identity is the client's TLS key fingerprint, taken
from the verified peer certificate (not from any field in the handshake frame).
The certificate Common Name is attacker-chosen and is used only for diagnostic
logging.

### 5.5 Metadata Operations

All metadata operations are a single request/response on one stream. Field names
below are exact.

**GetAttr**
```
Request:  { op: 0x01, seq, path }
Response: { op: 0x01, seq, status, stat: Stat | null }
```

**Stat object** (all times are nanoseconds since the Unix epoch):
```
{
  ino:    u64,
  mode:   u32,
  nlink:  u32,
  uid:    u32,
  gid:    u32,
  size:   u64,
  atime:  i64,
  mtime:  i64,
  ctime:  i64,
  blksz:  u32,
  blocks: u64
}
```

**ReadDir** (cursor-paginated; `cursor` = 0 starts at the beginning):
```
Request:  { op: 0x03, seq, path, cursor: u64 }
Response: { op: 0x03, seq, status, entries: [ { name, ino, mode }, ... ],
            cursor: u64, eof: bool }
```
The client issues ReadDir repeatedly, advancing `cursor` from each response,
until `eof` is true.

**Open**
```
Request:  { op: 0x10, seq, path, flags: u32 }
Response: { op: 0x10, seq, status, handle: u64, stat: Stat | null }
```

**Release**
```
Request:  { op: 0x11, seq, handle: u64 }
Response: { op: 0x11, seq, status }
```

**SetAttr** (`valid` is a bitmask: 0x1 mode, 0x2 uid, 0x4 gid, 0x8 size,
0x10 atime, 0x20 mtime):
```
Request:  { op: 0x02, seq, path, valid: u32, mode, uid, gid, size, atime, mtime }
Response: { op: 0x02, seq, status, stat: Stat | null }
```

**Rename**
```
Request:  { op: 0x07, seq, old, new, flags: u32 }
Response: { op: 0x07, seq, status }
```

**MkDir**
```
Request:  { op: 0x04, seq, path, mode: u32 }
Response: { op: 0x04, seq, status, stat: Stat | null }  // GetAttr-shaped
```

**Unlink, RmDir, ReadLink** share a path-only request:
```
Request:  { op, seq, path }
Unlink/RmDir response:  { op, seq, status }
ReadLink response:      { op: 0x09, seq, status, target: "<link target>" }
```

**Symlink** (`target` is what the link points to; `link` is where it is created):
```
Request:  { op: 0x08, seq, target, link }
Response: { op: 0x08, seq, status, stat: Stat | null }  // GetAttr-shaped
```

**Link** (hard link; `path` is the existing file, `link` is the new name):
```
Request:  { op: 0x0A, seq, path, link }
Response: { op: 0x0A, seq, status, stat: Stat | null }  // GetAttr-shaped
```

**StatFS**
```
Request:  { op: 0x0B, seq, path }
Response: { op: 0x0B, seq, status, statfs: StatFs | null }
StatFs = { blocks, bfree, bavail, files, ffree, bsize, namelen, frsize }
```

### 5.6 Read (op 0x20)

The client opens one stream, sends a single Read request, and the server streams
response frames until the requested range is satisfied or end of file. Each
response frame carries the `offset` of its `data`, and the last frame sets `eof`.

```
Client to server (one frame):
{ op: 0x20, seq, handle: u64, offset: u64, length: u32 }

Server to client (one or more frames):
{ op: 0x20, seq, status, offset: u64, data: bytes, eof: bool }
```

The server reads from disk in 256 KiB chunks per frame and rejects a single Read
request larger than 16 MiB with `InvalidArg`. A read on a handle the server no
longer knows (for example after a reconnect issued a fresh handle table) returns
`Stale`. Reads use the retained file descriptor (section 7.7); they never reopen
by path.

Multiple concurrent Read streams are independent QUIC streams with no
head-of-line blocking between them. There is no speculative prefetch engine
(section 7.6).

### 5.7 Write (op 0x21)

The client streams one or more request frames with sequential data chunks on a
single stream and marks the final chunk `done`. The server replies once, after
it has received the frame with `done = true`.

```
Client to server (one or more frames, same seq):
{ op: 0x21, seq, handle: u64, offset: u64, data: bytes, done: bool }

Server to client (one frame, after done = true):
{ op: 0x21, seq, status, written: u64 }
```

The server writes each chunk with a positioned write at the frame's `offset`. If
the handle was opened `O_APPEND`, the kernel appends at end of file atomically
and the supplied offset is ignored, which is what lets concurrent appenders avoid
clobbering each other. `written` is the total bytes committed in the RPC, a `u64`
to avoid overflow past 4 GiB in one multi-frame write. A write on an unknown
handle returns `Stale`. All writes to one physical file are serialized for the
whole RPC (section 7.7), so a coalesced multi-frame write lands as a contiguous
unit and cannot be torn by a concurrent writer.

### 5.8 Fsync (op 0x22)

```
Request:  { op: 0x22, seq, handle: u64, datasync: bool }
Response: { op: 0x22, seq, status }
```
`datasync` selects `fdatasync` (data only) versus `fsync` (data and metadata) on
the retained descriptor.

### 5.9 Ping (op 0xF1)

```
Request:  { op: 0xF1, seq }
Response: { op: 0xF1, seq, status }
```
Used by `quicfs ping` for a connectivity check after the handshake.

---

## 6. Authentication and Security

### 6.1 TLS 1.3 (mandatory)

QUIC mandates TLS 1.3; there is no plaintext mode. The TLS session is part of the
QUIC handshake. QuicFS uses mutual TLS: the client always presents a client
certificate and the server requires one.

### 6.2 Trust On First Use (TOFU) Key Pinning

QuicFS has no certificate authority and no CRL. Each peer holds a long-lived
self-signed certificate wrapping a stable public key. Identity is the SHA-256
fingerprint of that certificate's SubjectPublicKeyInfo (SPKI), formatted exactly
like an OpenSSH key fingerprint: `SHA256:<base64-no-pad>`. Pinning the public key
(not the whole certificate) lets a peer renew certificate metadata or expiry
without breaking trust, as long as the key is unchanged, matching SSH host-key
semantics.

Both verifiers always perform the cryptographic TLS handshake signature check
(delegated to the active `rustls` CryptoProvider), proving the peer holds the
private key. This is never skipped. On top of that:

**Client side (`known_hosts`).** On first contact with an unknown host, the
client captures the server's fingerprint and decides whether to pin it based on
the TOFU policy:

- `Prompt` (default): ask on the terminal, exactly like ssh. If there is no TTY,
  refuse and tell the user to re-run with `--accept-new`.
- `--accept-new`: pin a new key automatically (ssh `accept-new`), for automation.
- `--strict-host-key`: never accept an unknown key (ssh
  `StrictHostKeyChecking=yes`).

Once pinned in `known_hosts` (`host:port SHA256:...`), a later fingerprint
mismatch is a hard failure with the familiar "REMOTE HOST IDENTIFICATION HAS
CHANGED" warning.

**Server side (`authorized_keys`).** The server authorizes client keys by
fingerprint, like `~/.ssh/authorized_keys`:

- If the authorized set is non-empty, the client's fingerprint must be in it, or
  the TLS handshake is rejected.
- If the set is empty and `allow_any_client` is true, any key is accepted
  (single-user or trusted-network mode). This is an explicit opt-in, never the
  silent default; an empty set with `allow_any_client = false` rejects everyone
  and logs the fingerprint an admin needs to authorize.

A client certificate is mandatory; a connection with no client certificate is
rejected outright. Every rejected or observed client fingerprint is logged so an
admin can authorize it.

### 6.3 Key Management CLI

There is no `init`, `add-client`, or `revoke`. Trust is managed with these
commands.

Client:
```
quicfs key                # print this client's key fingerprint
quicfs known-hosts        # list pinned server keys (and the known_hosts path)
```

Server:
```
quicfs-server fingerprint            # print this server's key fingerprint
quicfs-server authorize <fingerprint> [--comment "..."]   # append to authorized_keys
```

Identity keys are generated once and reused (like an ssh key), stored under the
config directory (`~/.config/quicfs` on Linux, overridable with `$QUICFS_HOME`).
`known_hosts` and private keys are written 0600; `authorized_keys` is written
0644 because it holds only public-key fingerprints and must be readable by the
server's service account.

### 6.4 Path Sanitization and Confinement

Every client-supplied path is resolved against the export root by `sanitize`:

- Total path length is capped at 4096 bytes (PATH_MAX); each component at 255
  bytes; depth at 128 components.
- Null bytes are rejected.
- `..` components are rejected.
- Each intermediate component is checked with a no-follow stat; an intermediate
  symlink is rejected. If the fully joined path exists, both it and the root are
  canonicalized and the result must stay under the root.

Path resolution alone is a check-then-use pattern and is not race-free on its
own, so on Linux the kernel enforces the jail at the point of use for every
path-based operation:

- **Open sinks** (Create, Open, and all three SetAttr sinks: size, mode, times)
  route through `open_confined`, which uses `openat2(2)` with
  `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` against a directory descriptor on the
  export root. The kernel re-checks confinement atomically at open time, so a
  symlink swapped in after `resolve()` ran still cannot escape. Create and the
  SetAttr size sink (truncation) additionally pass `O_NOFOLLOW` so a final-
  component symlink (including a dangling one, which the canonicalize check cannot
  see) is refused with `ELOOP` rather than followed out of the export. SetAttr
  mode/times operate through a confined `O_PATH` descriptor (`/proc/self/fd`) so
  they never re-resolve the path.
- **Namespace operations** (MkDir, RmDir, Unlink, Rename, Symlink, Link, ReadLink)
  open the target's PARENT as a confined `O_PATH` directory descriptor the same
  way, then run the operation with the `*at` family (`mkdirat`, `unlinkat`,
  `renameat`, `symlinkat`, `linkat`, `readlinkat`) against the single trailing
  component, which those calls do not follow. The descriptor pins the parent
  inode and the kernel refuses any parent path that leaves the root, so the
  resolve-then-use race is closed for these too. Rename and Link confine both
  endpoints.

On a kernel without `openat2` (pre-5.6, `ENOSYS`) or a non-Linux unix target the
helpers fall back to the portable `std::fs` path with the same flags, never
anything less safe. On a sanitization failure the server returns a generic
`Permission` status rather than echoing the client's path.

### 6.5 Resource Limits and DoS Mitigation

- A global semaphore bounds concurrent connections at `max_clients`; an optional
  `max_conns_per_ip` caps connections from one source address (0 disables it).
- The handshake phase is bounded by a 10 s timeout, so a peer that completes
  the TLS handshake but then stalls cannot pin a connection slot until the QUIC
  idle timeout (slow-loris protection on the accept path).
- Each RPC stream is bounded by `rpc_timeout_ms` on the server; a handler that
  exceeds it has its future dropped and the stream is reset.
- Per-session open handles are capped at `max_open_handles`; exceeding it returns
  `NoSpace`.
- QUIC's built-in anti-amplification (a server responds with at most 3x the
  received bytes until the client address is validated) is handled by `quinn`; no
  application action is required.

---

## 7. Client (FUSE Daemon)

### 7.1 FUSE Library

The client uses `fuser` on Linux. FUSE mounting is Linux-only; on other platforms
the binary still supports `quicfs ping`, `quicfs key`, and `quicfs known-hosts`
but refuses to mount.

### 7.2 Invocation and Options

The bare, SSHFS-style form is the default; the `mount` verb is optional:

```
quicfs [user@]host[:/remote/path] <mountpoint> [options]
quicfs mount [user@]host[:/remote/path] <mountpoint> [options]
quicfs ping  [user@]host [options]
quicfs key
quicfs known-hosts
```

The spec is `[user@]host[:/remote/path]`; IPv6 literals use `[..]`. A missing
remote path defaults to `/` (the export root). `user@` is informational (it seeds
the client identity's default comment) and does not select a server account.

Options (with defaults):

```
-p, --port <PORT>          server UDP port (default 9001)
    --accept-new           pin an unknown host key without prompting
    --strict-host-key      refuse unknown host keys
    --identity <DIR>       directory holding this client's identity key
    --known-hosts <PATH>   known_hosts file (default <config dir>/known_hosts)
    --server-name <NAME>   override the TLS SNI (cosmetic under key pinning)
    --chunk-size <BYTES>   max data chunk per frame (default 262144)
    --cache-ttl <MS>       metadata cache TTL (default 2000)
    --allow-other          pass allow_other to FUSE
    --ro                   read-only mount
    --log-level <LEVEL>    error|warn|info|debug|trace (default info)
    --uid <UID>            override displayed owner uid
    --gid <GID>            override displayed owner gid
    --write-buf <BYTES>    per-handle write buffer soft cap (default 4194304)
    --coalesce-ms <MS>     write coalescing window (default 10)
```

There are no `--tls-*`, `--token`, `--prefetch`, `--migrate`, `--0rtt`,
`--bind`, `--daemonize`, `--no-cache`, `--config`, or `--log-file` flags.

### 7.3 Connection Manager

The `ConnManager` owns the QUIC endpoint and connection, performs TOFU
verification and the application handshake, and transparently reconnects. It
exposes the filesystem RPCs (getattr, readdir, open, read, write, and so on) used
by the FUSE op handlers. A `reconnect_gen` counter is bumped on every successful
reconnect; the FUSE layer watches it to clear its cache after a server restart
(section 9).

### 7.4 Metadata Cache

The client keeps a TTL-based LRU metadata cache (`lru` crate). The TTL is set by
`--cache-ttl` (default 2000 ms). Mutating operations invalidate the affected
entries, and the cache is cleared when `reconnect_gen` advances (a fresh server
session).

### 7.5 Write Buffer (coalescing + keep-until-acked)

Small FUSE writes (often 4 KiB) are accumulated per handle and flushed as one
streaming Write RPC. The buffer is keep-until-acked: a chunk is removed only when
the server acknowledges it (`Status::Ok`), not when it is sent. A failed send
leaves the chunk buffered so a reconnect can re-send it. Because writes are
positioned, a re-send after a partial commit overwrites the same bytes
idempotently, with no server-side dedup needed.

On flush, buffered chunks are offset-sorted and contiguous runs are coalesced
into larger writes. Memory is hard-bounded: a soft per-handle cap
(`--write-buf`), a soft global cap, and a hard global cap at twice the soft
global cap. Past the hard cap a push is refused and the FUSE write fails loudly
(sticky EIO) rather than acknowledging data the client cannot hold. A background
task force-flushes any handle whose oldest chunk has waited longer than the
coalesce window (`--coalesce-ms`).

### 7.6 Stream Pool and Prefetch (reserved / not yet implemented, future)

There is no idle-stream pool and no read-ahead / prefetch engine. Each operation
opens its own QUIC stream on demand, and reads are issued as the application
requests them. These were scoped in early design but are not built.

### 7.7 Server-Side Handle and Write Semantics

The properties below are guarantees the server provides for handles the client
holds.

- **Retained file descriptors.** An open handle retains the open `File` itself,
  not just a path. Read, Write, and Fsync operate on that retained descriptor
  with positioned I/O; they never reopen by path. This closes a rename-based
  TOCTOU where a client could replace an intermediate directory with a symlink
  between RPCs to make a later reopen-by-name escape the export root. A retained
  descriptor refers to the inode opened at Open/Create time and is immune to
  later namespace changes.

- **Session-namespaced handle IDs.** Handle IDs carry a random per-session epoch
  in their high 32 bits and a monotonic counter in the low 32 bits. The handle
  table is per QUIC connection, so a reconnect produces a fresh table with a new
  epoch. A handle issued before a reconnect cannot collide with one the new
  session hands out: a stale ID simply misses the table and the op fails `Stale`,
  surfaced as an error, never a silent wrong-file access.

- **Per-inode write serialization.** Writes to one physical file are serialized
  by a process-global stripe lock keyed on the file's identity (`dev << 64 | ino`
  on unix), held for the whole Write RPC. Two Write RPCs to the same inode, even
  across different handles or sessions, serialize against each other, so a
  multi-frame coalesced write lands contiguously and cannot be torn by another
  writer. The lock is a fixed 1024-entry stripe array; unrelated files that hash
  to the same stripe occasionally serialize, which costs a little parallelism but
  is never a correctness problem. Reads take only the per-handle descriptor lock
  and are unaffected.

---

## 8. Server

### 8.1 Configuration

The server reads a TOML config (default `server.toml`). Sections and keys:

```toml
[server]
listen           = "0.0.0.0:9001"   # required
export_root      = "/srv/quicfs"    # required, must exist
max_clients      = 128
max_conns_per_ip = 0                # 0 disables the per-IP cap
log_level        = "info"           # error|warn|info|debug|trace

[tls]
# Optional. With no CA, the server presents a self-signed identity. If cert/key
# are unset it generates a persistent self-signed identity under its config
# directory on first run (like ssh-keygen producing a host key).
cert = "/etc/quicfs/server.crt"
key  = "/etc/quicfs/server.key"

[auth]
authorized_keys  = "/etc/quicfs/authorized_keys"  # default <config dir>/authorized_keys
allow_any_client = false           # accept any key only when authorized_keys is empty

[quic]
connection_receive_window   = 67108864
stream_receive_window       = 16777216
max_concurrent_bidi_streams = 256
keep_alive_interval_ms      = 15000
idle_timeout_ms             = 300000
migration                   = true
zero_rtt                    = false   # inert: never read (0-RTT is not implemented)

[limits]
max_open_handles = 8192
rpc_timeout_ms   = 30000

[durability]
sync_on_close = false
sync_metadata = false
```

There is no `[tls] ca_cert`, no congestion-control selector, and no
`max_frame_size` or `max_file_size` config. The 16 MiB frame ceiling is the
hard-coded wire constant `MAX_FRAME_SIZE`, not a tunable. Config validation
rejects a zero `max_clients`, a `max_conns_per_ip` greater than `max_clients`, a
zero or unreasonably large `max_open_handles`, a zero `rpc_timeout_ms`, an idle
timeout below the keep-alive interval, an empty `listen` or `export_root`, and an
unknown `log_level`.

### 8.2 Durability Policy

Durability is two independent booleans under `[durability]`, both default false.
There are not three named modes.

- `sync_on_close`: fsync each file to disk when its handle is released. It trades
  write throughput for durability against a server-host crash (the data has
  already left the client and is in the server's page cache; this forces it to
  stable storage).
- `sync_metadata`: fsync the parent directory after a namespace mutation (create,
  rename, unlink, mkdir, rmdir, symlink, link) so the directory entry survives a
  server-host crash. The cost lands on metadata-heavy workloads (an extra
  synchronous directory fsync per entry).

The two are independent so an operator can pay one cost without the other. The
directory fsync is best effort and runs after the handle is retained: a fsync
failure is logged, never reported as an operation failure. Together with the
client's explicit Fsync RPC, `sync_metadata` is the server half of the durable
write-tmp / fsync / rename idiom: the application makes the file's data durable
with Fsync, and `sync_metadata` makes the subsequent rename's directory entry
durable.

### 8.3 Per-Connection State

Each accepted QUIC connection gets a `ClientSession`:

```rust
struct ClientSession {
    id:           Uuid,
    identity:     ClientIdentity,   // the client's key fingerprint (SHA256:...)
    conn:         quinn::Connection,
    handles:      HandleTable,      // retained file descriptors, capped
    rx_bytes:     AtomicU64,
    tx_bytes:     AtomicU64,
    connected_at: Instant,
    features:     Vec<String>,      // negotiated subset (empty today)
    sync_on_close: bool,
    sync_metadata: bool,
}
```

There is no advisory-lock table (locking is reserved, no handler). On connection
close, the handle table is dropped, closing all retained descriptors.

### 8.4 Stream Dispatch

Each incoming bidirectional stream is handed to a Tokio task. The task reads the
first frame, decodes the `Envelope` to route on `op`, dispatches to the handler,
writes the response frame(s), and finishes the stream. Each dispatch runs under
the per-RPC timeout. An unhandled opcode returns `InvalidArg`.

---

## 9. Error Handling and Reconnection

### 9.1 Migration vs Loss

- **IP migration** (Wi-Fi to LTE): the QUIC connection survives. In-flight
  streams continue on the new path. The mount is uninterrupted, and the metadata
  cache is not invalidated.
- **Connection loss** (network outage, server restart, server kill): the
  client's short idle timeout (12 s) declares the peer dead, the connection
  errors, and the next operation triggers a reconnect.

### 9.2 Reconnect Flow

`ensure_conn` checks for a live connection and otherwise reconnects with
exponential backoff (100 ms base, doubling, 30 s cap, with jitter). A reconnect
opens a fresh QUIC connection (the host key is already pinned, so the TOFU
verifier enforces it) and replays the application Handshake. Because reconnect
opens a new connection, the server issues a new handle table (new epoch), so
handles from before the loss are stale; operations on them fail `Stale`. On
success `reconnect_gen` advances and the client clears its metadata cache.

The keep-until-acked write buffer (section 7.5) is what makes a brief outage
non-data-losing: positioned writes that were not yet acknowledged are replayed
idempotently after the reconnect. An `O_APPEND` handle's buffered writes are not
replayed (append offsets are server-assigned and replay could duplicate); they
are dropped deliberately with a sticky error so the failure is surfaced rather
than silently producing duplicate bytes.

### 9.3 0-RTT Reconnect (reserved / not yet implemented, future)

There is no 0-RTT reconnect. Each reconnect is a normal 1-RTT handshake.

---

## 10. Watch / Server-Push Notifications (reserved / not yet implemented, future)

The Watch opcode (0xF2) and its event bitmask constants (CREATE=1, DELETE=2,
MODIFY=4, RENAME=8, ATTR=16) and frame types (`WatchRequest`, `WatchEvent`) are
defined in the wire protocol, but there is no server handler. A Watch request
currently falls through to the unknown-op path and is answered with `InvalidArg`.
Server-push cache invalidation and any FUSE kernel cache-invalidation hookup
(`FUSE_NOTIFY_INVAL_*`) are future work. There is no `inotify`/`fanotify`
integration and no `inotify` crate dependency.

---

## 11. Status Codes

The protocol uses a single-byte status enum, returned in the `status` field of
responses:

```
0    Ok
1    NotFound
2    Permission
3    Io
4    Exists
5    NotEmpty
6    NotDir
7    IsDir
8    InvalidArg
9    NoSpace
10   TooLarge
11   Stale
255  Unknown
```

`std::io::Error` kinds map onto these (NotFound, PermissionDenied to Permission,
AlreadyExists to Exists, invalid input to InvalidArg, everything else to Io). The
client maps a non-Ok status to an operation error (surfaced to FUSE, typically as
EIO or the closest errno).

---

## 12. Performance Notes

- **One stream per operation** means concurrent operations do not block one
  another on packet loss. With `max_concurrent_bidi_streams = 256` a client can
  have up to 256 operations in flight per connection.
- **Metadata caching** (TTL LRU) serves repeated `stat`/`lookup` from memory and
  avoids a round trip on cache hits.
- **Write coalescing** turns many small FUSE writes into fewer, larger,
  contiguous Write RPCs.
- **Congestion control** is `quinn`'s default controller. It is not runtime
  selectable and there are no congestion-control config keys.

UDP receive-buffer tuning (`net.core.rmem_max` and friends) can help on
high bandwidth-delay-product paths but is an operator/OS concern, not something
QuicFS configures.

---

## 13. Key Dependencies

| Component        | Crate                  | Notes                                   |
|------------------|------------------------|-----------------------------------------|
| QUIC             | `quinn` 0.11           | async, over rustls                      |
| TLS              | `rustls` 0.23 (ring)   | no OpenSSL                              |
| FUSE             | `fuser` 0.14           | Linux client                            |
| Serialization    | `rmp-serde`            | MessagePack (named keys) via serde      |
| Async runtime    | `tokio`                | multi-thread scheduler                  |
| Logging          | `tracing` (+ subscriber)| env-filter                             |
| Config           | `toml`                 | server config parsing                   |
| Identity gen     | `rcgen`                | self-signed cert/key without OpenSSL    |
| Fingerprint hash | `sha2`, `base64`       | SHA-256 SPKI, base64-no-pad             |
| Cert parsing     | `x509-parser`          | extract SPKI for fingerprinting         |
| UUID             | `uuid`                 | session and handle-epoch identifiers    |
| CLI              | `clap`                 | argument parsing                        |
| Metadata cache   | `lru`                  | client-side TTL LRU                      |
| Paths/config dir | `dirs`                 | locate the user config directory        |
| Unix syscalls    | `libc`                 | openat2, O_NOFOLLOW, dev/ino, fsync     |

The QUIC implementation is `quinn` (pure Rust); there is no separate `config`
crate and no `inotify` crate.