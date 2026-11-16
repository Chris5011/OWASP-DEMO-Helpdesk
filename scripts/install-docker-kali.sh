#!/usr/bin/env bash
# Install Docker Engine + Compose plugin on Kali Linux from Docker's official apt repo.
#
# Docker's own instructions build the repo line from $VERSION_CODENAME, which on Kali
# is "kali-rolling" - a suite Docker doesn't publish. Kali is Debian-based, so we use
# Docker's Debian repo with a pinned Debian codename instead (default: trixie).
#
# Usage:   sudo ./scripts/install-docker-kali.sh
# Options: DOCKER_CODENAME=<debian codename>  override the pinned codename (default trixie)
#          SKIP_HELLO=1                        skip the hello-world smoke test
#
# Safe to re-run.
set -euo pipefail

CODENAME="${DOCKER_CODENAME:-trixie}"
KEYRING=/etc/apt/keyrings/docker.asc
SOURCES=/etc/apt/sources.list.d/docker.sources

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0"
command -v apt-get >/dev/null || die "apt-get not found - this script is for Kali/Debian."

. /etc/os-release
if [ "${ID:-}" != "kali" ]; then
    warn "This is '${PRETTY_NAME:-unknown}', not Kali. Continuing with Debian '$CODENAME' packages."
fi

ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
    amd64|arm64|armhf|ppc64el|s390x) ;;
    *) die "Architecture '$ARCH' isn't published by Docker for Debian." ;;
esac
log "Kali/Debian on $ARCH -> Docker Debian repo, codename '$CODENAME'"

# 1) Remove distro packages that conflict with Docker CE (Kali often ships docker.io).
CONFLICTS=(docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc)
INSTALLED=()
for p in "${CONFLICTS[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 && INSTALLED+=("$p")
done
if [ "${#INSTALLED[@]}" -gt 0 ]; then
    log "Removing conflicting packages: ${INSTALLED[*]}"
    apt-get remove -y "${INSTALLED[@]}"
fi
# Older installs of this script / Docker's docs may have left a one-line repo file.
rm -f /etc/apt/sources.list.d/docker.list

# 2) Prerequisites + Docker's GPG key.
log "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o "$KEYRING"
chmod a+r "$KEYRING"

# 3) Docker apt repo with the pinned codename (deb822 format).
log "Adding Docker apt repo ($SOURCES)"
cat > "$SOURCES" <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $CODENAME
Components: stable
Architectures: $ARCH
Signed-By: $KEYRING
EOF

# 4) Docker Engine, CLI, containerd, Buildx and the Compose v2 plugin.
log "Installing Docker Engine + Compose plugin"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 5) Start on boot (only if systemd is running - not inside containers/WSL without it).
if [ -d /run/systemd/system ]; then
    log "Enabling and starting docker.service"
    systemctl enable --now docker.service containerd.service
else
    warn "systemd isn't running; start the daemon yourself (e.g. 'dockerd &')."
fi

# 6) Let the invoking user run docker without sudo.
TARGET_USER="${SUDO_USER:-}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
    getent group docker >/dev/null || groupadd docker
    if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
        log "User '$TARGET_USER' is already in the docker group"
    else
        usermod -aG docker "$TARGET_USER"
        log "Added '$TARGET_USER' to the docker group - log out and back in (or run 'newgrp docker')"
    fi
fi

# 7) Report + smoke test.
docker --version
docker compose version
if [ "${SKIP_HELLO:-0}" != "1" ] && docker info >/dev/null 2>&1; then
    log "Smoke test: docker run --rm hello-world"
    docker run --rm hello-world | grep -m1 'Hello from Docker!' || die "hello-world failed"
fi

log "Done. Next: cd into the repo and run 'docker compose up --build' (localhost only - see README)."
