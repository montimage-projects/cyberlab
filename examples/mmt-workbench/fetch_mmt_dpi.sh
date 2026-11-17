#!/usr/bin/env bash
# Download the mmt-dpi .deb of a GitHub Release and verify it, inside the image build.
#
# Usage: fetch_mmt_dpi.sh <output dir>      prints the verified .deb path on stdout
# Env:   MMT_DPI_TAG          release tag (default v1.10.2)
#        MMT_DPI_SUMS_SHA256  expected sha256 of the release's SHA256SUMS (pinned for v1.10.2;
#                             required for any other tag)
#        MMT_DPI_DISTRO       distro in the asset name (default ubuntu-24.04)
#
# Chain of trust: SHA256SUMS is checked against the pinned hash, the package against SHA256SUMS.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail "usage: $0 <output dir>"
TAG="${MMT_DPI_TAG:-v1.10.2}"
DISTRO="${MMT_DPI_DISTRO:-ubuntu-24.04}"
ARCH="$(dpkg --print-architecture)"
PINNED_TAG=v1.10.2
PINNED_SUMS=07b796d1d7fea1586e06f5b2872fc6c69b65543ae7c091eb2a70fe73d096306c
SUMS_SHA="${MMT_DPI_SUMS_SHA256:-}"
if [ -z "$SUMS_SHA" ]; then
  [ "$TAG" = "$PINNED_TAG" ] || fail "MMT_DPI_SUMS_SHA256 is required for $TAG (only $PINNED_TAG is pinned)"
  SUMS_SHA="$PINNED_SUMS"
fi
OUT="$1"; mkdir -p "$OUT"; cd "$OUT"
BASE="https://github.com/Montimage/mmt-dpi/releases/download/$TAG"
DEB="mmt-dpi_${DISTRO}_${ARCH}.deb"
curl -fsSL --proto '=https' --tlsv1.2 -o SHA256SUMS "$BASE/SHA256SUMS"
echo "$SUMS_SHA  SHA256SUMS" | sha256sum -c - >&2 || fail "SHA256SUMS of $TAG does not match the pinned hash"
grep -E "  ${DEB}\$" SHA256SUMS > deb.sum || fail "$DEB is not listed in SHA256SUMS of $TAG"
curl -fsSL --proto '=https' --tlsv1.2 -o "$DEB" "$BASE/$DEB"
sha256sum -c deb.sum >&2 || fail "$DEB does not match SHA256SUMS"
echo "$OUT/$DEB"
