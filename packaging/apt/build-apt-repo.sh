#!/usr/bin/env bash
# Build (and optionally sign) a flat APT repository for taudit from one or more
# .deb files, laid out for static hosting on GitHub Pages.
#
# Ported from the tsafe reference implementation (packaging/RELEASE-CHANNELS.md).
# taudit differs in one structural way: its source repo is PUBLIC, so there is no
# separate `-releases` assets repo. Release archives live on the taudit repo's own
# GitHub Releases, and this apt tree is published to the `gh-pages` branch of the
# same repo, served at https://0ryant.github.io/taudit/apt.
#
# Signing: the ONLY signature taudit carries is this repository's, because a modern
# apt client refuses an unsigned repo. It is a FREE, self-generated OpenPGP key
# (no CA, no cost) held in the tsafe vault under apt/taudit/. It is NOT code
# signing: the binary inside the .deb is unsigned, like every other taudit channel.
#
# Usage:
#   build-apt-repo.sh --debs <dir-of-debs> --out <repo-out-dir> [--suite stable]
#                     [--component main] [--arch amd64] [--sign] [--key <id>]
#   build-apt-repo.sh --sign-only --out <repo-out-dir> --key <id>
#
# The index phase needs `dpkg-dev` (dpkg-scanpackages) and `apt-utils`
# (apt-ftparchive) — i.e. a Debian/Ubuntu userspace. On a Windows host run it in
# Docker or WSL2 (see README.md). The --sign phase needs only gpg with the secret
# key imported; on a Windows+WSL2 host that must be the shell where the real tsafe
# vault lives (Git Bash on Windows), because WSL2's tsafe is a different, empty vault.
set -euo pipefail

SUITE=stable COMPONENT=main ARCH=amd64 DEBS="" OUT="" SIGN=0 SIGN_ONLY=0
GPG_KEY_ID="${TAUDIT_APT_GPG_KEY_ID:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --debs) DEBS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --suite) SUITE="$2"; shift 2;;
    --component) COMPONENT="$2"; shift 2;;
    --arch) ARCH="$2"; shift 2;;
    --sign) SIGN=1; shift;;
    --sign-only) SIGN_ONLY=1; SIGN=1; shift;;
    --key) GPG_KEY_ID="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
POOL="pool/$COMPONENT/t/taudit"
BINDIR="dists/$SUITE/$COMPONENT/binary-$ARCH"

if [ "$SIGN_ONLY" -eq 1 ]; then
  [ -n "$OUT" ] || { echo "required: --out <existing repo dir>" >&2; exit 2; }
  [ -f "$OUT/dists/$SUITE/Release" ] || { echo "no dists/$SUITE/Release under $OUT — run the index phase first" >&2; exit 4; }
else
  [ -n "$DEBS" ] && [ -n "$OUT" ] || { echo "required: --debs <dir> --out <dir>" >&2; exit 2; }
  command -v dpkg-scanpackages >/dev/null || { echo "need dpkg-scanpackages (apt-get install dpkg-dev)" >&2; exit 3; }
  command -v apt-ftparchive   >/dev/null || { echo "need apt-ftparchive (apt-get install apt-utils)" >&2; exit 3; }
  rm -rf "$OUT"; mkdir -p "$OUT/$POOL" "$OUT/$BINDIR"
fi

if [ "$SIGN_ONLY" -eq 0 ]; then
  # 1. Pool: copy every .deb in.
  count=0
  for deb in "$DEBS"/*.deb; do [ -e "$deb" ] || continue; cp -f "$deb" "$OUT/$POOL/"; count=$((count+1)); done
  [ "$count" -gt 0 ] || { echo "no .deb files in $DEBS" >&2; exit 4; }
  echo "pooled $count .deb(s)"

  # 2. Packages index. Paths in it are relative to the repo root, so run from $OUT.
  ( cd "$OUT" && dpkg-scanpackages --arch "$ARCH" "$POOL" /dev/null > "$BINDIR/Packages" )
  gzip -9kf "$OUT/$BINDIR/Packages"
  echo "wrote $BINDIR/Packages(.gz)"

  # 3. Release — apt-ftparchive computes the per-file hashes apt verifies.
  cat > "$OUT/apt-ftparchive.conf" <<CONF
APT::FTPArchive::Release::Origin "taudit";
APT::FTPArchive::Release::Label "taudit";
APT::FTPArchive::Release::Suite "$SUITE";
APT::FTPArchive::Release::Codename "$SUITE";
APT::FTPArchive::Release::Architectures "$ARCH";
APT::FTPArchive::Release::Components "$COMPONENT";
CONF
  ( cd "$OUT" && apt-ftparchive -c apt-ftparchive.conf release "dists/$SUITE" > "dists/$SUITE/Release" )
  rm -f "$OUT/apt-ftparchive.conf"
  echo "wrote dists/$SUITE/Release"
fi

# 4. Sign. Free self-generated OpenPGP key from the vault; see README.md.
if [ "$SIGN" -eq 1 ]; then
  [ -n "$GPG_KEY_ID" ] || { echo "--sign needs --key <id> or TAUDIT_APT_GPG_KEY_ID, and the secret key in the gpg keyring" >&2; exit 5; }
  ( cd "$OUT/dists/$SUITE"
    gpg --default-key "$GPG_KEY_ID" --batch --yes --armor --detach-sign -o Release.gpg Release
    gpg --default-key "$GPG_KEY_ID" --batch --yes --clearsign          -o InRelease  Release
  )
  gpg --armor --export "$GPG_KEY_ID" > "$OUT/taudit-archive-keyring.asc"
  gpg --export         "$GPG_KEY_ID" > "$OUT/taudit-archive-keyring.gpg"
  echo "signed Release -> InRelease + Release.gpg; exported public key"
else
  echo "NOT signed (--sign omitted). apt will REJECT this repo until signed; see README.md."
fi
echo "apt repo built at $OUT (host its contents at <pages-base>/apt/)"
