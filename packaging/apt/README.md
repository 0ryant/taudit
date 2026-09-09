# taudit APT repository

Tracked source for the taudit apt channel. The built, signed repo is published to
the `gh-pages` branch of this repository and served at
`https://0ryant.github.io/taudit/apt`.

Ported from the tsafe reference implementation (see
[`../RELEASE-CHANNELS.md`](../RELEASE-CHANNELS.md)). One structural difference:
**taudit's source repo is public**, so there is no separate `taudit-releases`
assets repo. Release archives are the taudit repo's own GitHub Release assets,
and the apt tree lives on a `gh-pages` branch of the same repo — keeping the
binary pool out of `main` while giving taudit its own trust anchor.

## Signing, stated plainly

The repository's `Release` file is signed with a **free, self-generated OpenPGP
key** — the only signature taudit carries, because apt refuses an unsigned repo.
It is **not** code signing: the `taudit` binary inside the `.deb` is unsigned,
exactly like the binary in every other taudit channel. The key is the
maintainer's, held in the tsafe vault under `apt/taudit/`, and reaches gpg only
through `tsafe exec`.

Key: `taudit apt signing <rytilcock@gmail.com>`, ed25519, 2-year expiry.
Vault keys: `apt/taudit/GPG_SIGNING_KEY`, `apt/taudit/GPG_PUBLIC_KEY` (both
base64 of the armored export, because `tsafe set` takes a single stdin line).

The key is **per tool**, not shared with tsafe: each tool is its own trust
anchor, so compromising one channel's key does not implicate another's.

## One-time — generate and store the key

Run on the host where the real vault lives (Git Bash on Windows here; a vault
inside WSL2 is a different, empty vault).

```bash
export GNUPGHOME="$(mktemp -d)"; chmod 700 "$GNUPGHOME"
gpg --batch --passphrase '' --quick-gen-key 'taudit apt signing <you@example.com>' ed25519 sign 2y
KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}')
gpg --armor --export-secret-keys "$KEYID" | base64 -w0 | tsafe set apt/taudit/GPG_SIGNING_KEY --overwrite
gpg --armor --export             "$KEYID" | base64 -w0 | tsafe set apt/taudit/GPG_PUBLIC_KEY  --overwrite
tsafe list | grep '^apt/taudit/'
rm -rf "$GNUPGHOME"; unset GNUPGHOME    # the vault is now the only copy
```

Delete that keyring afterwards. Leaving it behind keeps an unprotected secret
key on disk, which is the thing the vault exists to prevent.

## Per release

### 1. Build the `.deb` (needs the release binary, not a compiler)

```bash
just release-asset x86_64-unknown-linux-gnu   # or download the published archive
just deb                                      # nFPM via Docker -> dist/packages/
```

`release_assets.py deb` unpacks `taudit-x86_64-linux.tar.gz` and packages exactly
those bytes, so the `.deb` and the tarball ship an identical binary.

### 2. Build the index (needs a Debian userspace)

`dpkg-scanpackages` and `apt-ftparchive` are Debian tools. On a Windows host,
Docker is the shortest path (WSL2 works too):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/work" -w /work debian:bookworm-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq dpkg-dev apt-utils && \
   bash packaging/apt/build-apt-repo.sh --debs dist/packages --out dist/apt-repo'
```

### 3. Sign it (needs the vault)

The vault lives on Windows, so this phase runs in Git Bash, not the container.
Two Windows-specific details, both learned the hard way:

- Use a **POSIX** `GNUPGHOME` (`/tmp/...`) and set it **inside** the child, with
  `MSYS_NO_PATHCONV=1`. `tsafe.exe` is a native Windows binary, so MSYS rewrites
  a `/tmp/...` env value into `C:/...` on the way in, and the Git Bash gpg then
  reads that as a path relative to the cwd and finds no writable keyring.
- Import the **public key first**, then the secret. gpg 2.4 refuses a secret-key
  import into a keyring with no matching public key (`import failed: No public key`).

```bash
KR=/tmp/taudit-apt-keyring; rm -rf "$KR"; mkdir -p "$KR"; chmod 700 "$KR"
MSYS_NO_PATHCONV=1 tsafe exec --mode standard --preset full \
  --keys apt/taudit/GPG_PUBLIC_KEY --keys apt/taudit/GPG_SIGNING_KEY \
  --env PUB=apt/taudit/GPG_PUBLIC_KEY --env SEC=apt/taudit/GPG_SIGNING_KEY --redact-output -- \
  bash -c 'export GNUPGHOME=/tmp/taudit-apt-keyring
           printf "%s" "$PUB" | base64 -d | gpg --batch --import
           printf "%s" "$SEC" | base64 -d | gpg --batch --import'
# gpg-agent keeps that child alive; Ctrl-C once the imports print. The keys are in.
export GNUPGHOME="$KR"
KEYID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}')
bash packaging/apt/build-apt-repo.sh --sign-only --out dist/apt-repo --key "$KEYID"
gpgconf --kill gpg-agent; rm -rf "$KR"; unset GNUPGHOME
```

Use `tsafe exec --keys`, never `--only`: `--only` strips the child's environment
(PATH, SystemRoot, PATHEXT), which breaks gpg and every other tool.

### 4. Install-test before publishing

A repo whose signature does not verify fails at `apt update` on every user's
machine, so test it locally first. `file:` URIs exercise the same verification
path as `https:`:

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/dist/apt-repo:/repo:ro" debian:bookworm-slim bash -c '
  apt-get update -qq
  install -m0755 -d /etc/apt/keyrings
  cp /repo/taudit-archive-keyring.gpg /etc/apt/keyrings/taudit.gpg
  echo "deb [signed-by=/etc/apt/keyrings/taudit.gpg] file:/repo stable main" \
    > /etc/apt/sources.list.d/taudit.list
  apt-get update && apt-get install -y taudit && taudit --version'
```

Note: `debian:*-slim` images ship a dpkg config that excludes `/usr/share/man/*`,
so the man page will look missing there. That is the image, not the package —
delete `/etc/dpkg/dpkg.cfg.d/docker` to see it install.

### 5. Publish

Commit the built tree to the `gh-pages` branch under `/apt` and push. GitHub
Pages serves it; an empty `.nojekyll` at the branch root is required so paths
like `dists/` are served verbatim rather than being run through Jekyll.

## User install

```bash
sudo install -m0755 -d /etc/apt/keyrings
curl -fsSL https://0ryant.github.io/taudit/apt/taudit-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/taudit.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/taudit.gpg] https://0ryant.github.io/taudit/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/taudit.list >/dev/null
sudo apt update && sudo apt install taudit
```

amd64 only today. An arm64 `.deb` needs `release_assets.py deb --cpu aarch64`
against the aarch64 archive, then a second `--arch arm64` index pass.
