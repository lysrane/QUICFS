#![no_main]
//! Fuzz `trust::parse_fingerprint` - the parser for `SHA256:<base64>` key
//! fingerprints that come from known_hosts / authorized_keys files and the
//! `authorize` CLI. Lower-severity than the wire decoders (config-layer), but a
//! panic on a malformed fingerprint would crash `authorize` or a load, so we
//! confirm it only ever returns Ok/Err on arbitrary input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = quicfs_common::trust::parse_fingerprint(s);
    }
});
