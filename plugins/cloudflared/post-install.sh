#!/bin/sh
# Install a pinned cloudflared binary (not available via apt).
set -e

: "${CLOUDFLARED_VERSION:=2026.9.3}"
: "${CLOUDFLARED_INSTALL_PATH:=/usr/local/bin/cloudflared}"

# Architecture is detected here rather than taken from a build arg, so this hook
# works unchanged from both Dockerfile and Dockerfile.ci.
arch="${CLOUDFLARED_ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"
case "$arch" in
  amd64|x86_64)
    asset=cloudflared-linux-amd64
    # SHA256 published by Cloudflare in the release notes for the pinned version.
    default_sha=77e26d8d900e0b8469f416239d14b5f296525fdf79fee6f511ef55609e3fbac2
    ;;
  arm64|aarch64)
    asset=cloudflared-linux-arm64
    default_sha=aaeb2d7d0da3614634c7e03ab13487a1522c2e79165ed2929cfe23d5e95b326d
    ;;
  *)
    echo "[cloudflared] unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

: "${CLOUDFLARED_ASSET:=$asset}"
: "${CLOUDFLARED_SHA256:=$default_sha}"

curl -fL "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/${CLOUDFLARED_ASSET}" -o "$CLOUDFLARED_INSTALL_PATH"
printf '%s  %s\n' "$CLOUDFLARED_SHA256" "$CLOUDFLARED_INSTALL_PATH" | sha256sum -c -
chmod 755 "$CLOUDFLARED_INSTALL_PATH"
