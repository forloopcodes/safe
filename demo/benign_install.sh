#!/usr/bin/env bash
# Example clean installer: downloads a release, verifies it, installs to a prefix.
set -euo pipefail

REPO="example/tool"
VERSION="${1:-1.4.0}"
PREFIX="${PREFIX:-$HOME/.local}"

usage() {
  echo "usage: install.sh [version]"
  echo "  installs the tool binary into \$PREFIX/bin"
}

main() {
  tmp="$(mktemp -d)"
  url="https://github.com/${REPO}/releases/download/v${VERSION}/tool-linux.tar.gz"
  echo "Downloading ${url}"
  curl -fsSL "$url" -o "$tmp/tool.tar.gz"
  curl -fsSL "$url.sha256" -o "$tmp/tool.sha256"
  ( cd "$tmp" && sha256sum -c tool.sha256 )
  tar -xzf "$tmp/tool.tar.gz" -C "$tmp"
  install -Dm755 "$tmp/tool" "$PREFIX/bin/tool"
  echo "Installed tool ${VERSION} to $PREFIX/bin"
}

main "$@"
