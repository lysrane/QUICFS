#!/usr/bin/env bash
# QuicFS installer for systems without a .deb package.
#
# Builds release binaries and installs them, plus (optionally) the systemd unit.
# Run as root (or via sudo). Idempotent; safe to re-run to upgrade.
#
#   sudo ./packaging/install.sh            # install client + server + service
#   sudo ./packaging/install.sh client     # client binary only
#   sudo ./packaging/install.sh server     # server binary + service only
set -euo pipefail

ROLE="${1:-all}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: must run as root (try: sudo $0 $*)" >&2
        exit 1
    fi
}

build() {
    echo "==> building release binaries"
    ( cd "$REPO_DIR" && cargo build --release --workspace )
}

install_client() {
    echo "==> installing client -> $BINDIR/quicfs"
    install -Dm755 "$REPO_DIR/target/release/quicfs" "$BINDIR/quicfs"
    if ! command -v fusermount3 >/dev/null 2>&1; then
        echo "    note: install fuse3 (apt install fuse3) for mounting to work"
    fi
}

install_server() {
    echo "==> installing server -> $BINDIR/quicfs-server"
    install -Dm755 "$REPO_DIR/target/release/quicfs-server" "$BINDIR/quicfs-server"

    # Service account.
    if ! id quicfs >/dev/null 2>&1; then
        echo "==> creating system user 'quicfs'"
        useradd --system --no-create-home --shell /usr/sbin/nologin quicfs || true
    fi

    install -d -o quicfs -g quicfs -m 0750 /var/lib/quicfs
    install -d -m 0755 /etc/quicfs
    install -d -o quicfs -g quicfs -m 0755 /srv/quicfs

    if [ ! -f /etc/quicfs/server.toml ]; then
        echo "==> installing example config -> /etc/quicfs/server.toml"
        install -m 0644 "$SCRIPT_DIR/server.toml.example" /etc/quicfs/server.toml
    else
        echo "    /etc/quicfs/server.toml exists; leaving it untouched"
        install -m 0644 "$SCRIPT_DIR/server.toml.example" /etc/quicfs/server.toml.example
    fi
    touch /etc/quicfs/authorized_keys
    chown quicfs:quicfs /etc/quicfs/authorized_keys
    chmod 0644 /etc/quicfs/authorized_keys

    if [ -d /run/systemd/system ]; then
        echo "==> installing systemd unit (ExecStart → $BINDIR/quicfs-server)"
        # The shipped unit hardcodes /usr/bin; rewrite it to wherever we installed.
        sed "s|^ExecStart=.*|ExecStart=$BINDIR/quicfs-server --config /etc/quicfs/server.toml|" \
            "$SCRIPT_DIR/quicfs-server.service" > /lib/systemd/system/quicfs-server.service
        chmod 0644 /lib/systemd/system/quicfs-server.service
        systemctl daemon-reload
        echo "    enable with: systemctl enable --now quicfs-server"
    fi

    echo
    echo "Server installed. Next:"
    echo "  1. edit /etc/quicfs/server.toml (set export_root, listen)"
    echo "  2. systemctl enable --now quicfs-server"
    echo "  3. quicfs-server fingerprint     # share this with clients (optional)"
    echo "  4. authorize a client: quicfs-server authorize SHA256:... --config /etc/quicfs/server.toml"
}

need_root "$@"
build
case "$ROLE" in
    client) install_client ;;
    server) install_server ;;
    all)    install_client; install_server ;;
    *) echo "usage: $0 [all|client|server]" >&2; exit 2 ;;
esac
echo "==> done"
