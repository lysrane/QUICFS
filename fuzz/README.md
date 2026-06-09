# QuicFS fuzzing

Coverage-guided fuzz targets (libFuzzer via `cargo-fuzz`) for the parts that take
untrusted bytes from a (possibly malicious or compromised) client. Requires the
nightly toolchain and `cargo-fuzz`:

```
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run a target (Ctrl-C to stop, or `-- -max_total_time=SECONDS`):

```
cargo +nightly fuzz run resolve
cargo +nightly fuzz run decode_requests
cargo +nightly fuzz run open_confined
cargo +nightly fuzz run parse_fingerprint
```

## Targets, by priority

- **resolve** (security-critical) - the export-root jail's first line. Invariant:
  for any client path string, `sanitize::resolve` either errors or returns a path
  under the export root. A regression is a jail break (arbitrary server-side file
  access). This area has shipped a CRITICAL escape and a HIGH TOCTOU before.
- **open_confined** (security-critical) - the kernel-enforced half of the jail
  (`openat2 RESOLVE_BENEATH`) against a tempdir with planted escaping symlinks.
  Invariant: whatever opens has a real path under the root.
- **decode_requests** (high) - the wire entry point. Decodes arbitrary bytes into
  every server-handled request type (rmp-serde / MessagePack); finds panics, huge
  allocations, hangs on hostile frames.
- **parse_fingerprint** (low) - the `SHA256:<base64>` key-fingerprint parser used by
  known_hosts / authorized_keys / the `authorize` CLI.

The `resolve` invariant is ALSO a CI-runnable proptest
(`server/src/sanitize.rs::resolve_never_escapes_root`) so the jail guarantee is
checked on every `cargo test`, not only under nightly fuzzing.

## Status (2026-06-07)

First run: all four targets clean - no crashes, panics, OOM, hangs, or jail
escapes. ~25M execs on resolve, ~1.9M on decode_requests (11.9k coverage edges),
~6.7M on open_confined, ~20M on parse_fingerprint.

## Not yet fuzzed (deeper follow-ups)

- The multi-frame Write-RPC reassembly state machine (`handle_write`): stateful and
  async, needs a mock `RecvStream` or the frame-sequence logic factored out.
- `read_frame` length handling / the eager per-frame allocation (async reader).
- Client-side response parsing (only matters when hardening against a hostile
  server, which the pin-the-server trust model makes low priority).
