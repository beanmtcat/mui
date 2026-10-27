#!/usr/bin/env bash
# Run on the build machine. Docker compiles and exports standalone Linux
# binaries; target servers run systemd or OpenRC services directly.
set -euo pipefail
cd "$(dirname "$0")/.."
arch="${1:-amd64}"
core_version="${2:-v1.14.2}"
agent_version="${3:-0.6.22}"
release_key=${MUI_RELEASE_KEY:-"$(pwd)/deploy/.secrets/release.key"}
case "$arch" in amd64|arm64) ;; *) echo "usage: $0 [amd64|arm64] [sing-box version, for example v1.14.2] [agent version, for example 0.6.7]" >&2; exit 2;; esac
if [[ ! "$core_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "sing-box version must be a vX.Y.Z release tag" >&2
  exit 2
fi
if [[ ! "$agent_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "agent version must be a stable X.Y.Z release, for example 0.6.7" >&2
  exit 2
fi
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { echo 'release build requires a clean Git worktree' >&2; exit 1; }
source_commit=$(git rev-parse HEAD)
source_version=$(git show "$source_commit:internal/agent/version.go" | sed -n 's/^var Version = "\([^"]*\)"$/\1/p')
[[ "$source_version" == "$agent_version" ]] || {
  echo "Agent version in commit $source_commit is $source_version, expected $agent_version" >&2
  exit 1
}
if [[ -n "${MUI_RELEASE_KEY:-}" && ! -f "$release_key" ]]; then
  echo "release signing key not found: $release_key" >&2
  exit 1
fi
mkdir -p "bin/$arch"
# Optional upstream commit pin for the sing-box tag above. Look the commit up
# with: git ls-remote https://github.com/SagerNet/sing-box.git "refs/tags/${core_version}^{}"
# Without it the build trusts the tag; a moved tag would change the output.
docker buildx build --platform "linux/$arch" --build-arg "AGENT_VERSION=$agent_version" --build-arg "SING_BOX_VERSION=$core_version" --build-arg "SING_BOX_COMMIT=${SING_BOX_COMMIT:-}" --file deploy/Agent.Dockerfile --output "type=local,dest=bin/$arch" .
(
  cd "bin/$arch"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 mui-agent sing-box > SHA256SUMS
  else
    sha256sum mui-agent sing-box > SHA256SUMS
  fi
)
# Sign the manifest when a release key is available, so agents that pinned its
# public half only accept upgrades built here. Create one with:
#   go run ./cmd/release-sign keygen release.key
rm -f "bin/$arch/SHA256SUMS.sig"
if [[ -f "$release_key" ]]; then
  go run ./cmd/release-sign sign "$release_key" "bin/$arch"
  # A signing key was provided, so a missing .sig is a build failure, not a
  # silent unsigned build. Without MUI_RELEASE_KEY the build is unsigned and
  # only a warning is printed (see below).
  if [[ ! -s "bin/$arch/SHA256SUMS.sig" ]]; then
    echo "release signing produced no bin/$arch/SHA256SUMS.sig" >&2
    exit 1
  fi
  printf 'Signed bin/%s/SHA256SUMS\n' "$arch"
else
  echo "warning: no release key at $release_key; bin/$arch is UNSIGNED (agents that pinned a release key will refuse it)" >&2
fi
mkdir -p dist/release
archive="dist/release/mui-agent-$agent_version-linux-$arch.tar.gz"
manifest_asset="dist/release/mui-agent-$agent_version-linux-$arch.SHA256SUMS"
signature_asset="$manifest_asset.sig"
# macOS bsdtar otherwise adds LIBARCHIVE.xattr.com.apple.provenance headers
# that GNU tar on Linux warns about during manual extraction.
tar_flags=()
if tar --version 2>/dev/null | grep -q bsdtar; then tar_flags=(--no-xattrs --no-acls --no-mac-metadata); fi
COPYFILE_DISABLE=1 tar ${tar_flags[@]+"${tar_flags[@]}"} -czf "$archive" -C bin "$arch"
cp "bin/$arch/SHA256SUMS" "$manifest_asset"
if [[ -s "bin/$arch/SHA256SUMS.sig" ]]; then
  cp "bin/$arch/SHA256SUMS.sig" "$signature_asset"
else
  rm -f "$signature_asset"
fi
printf '%s\n' "$source_commit" > "$archive.commit"
printf 'Built Agent %s: bin/%s/mui-agent; sing-box %s: bin/%s/sing-box\n' "$agent_version" "$arch" "$core_version" "$arch"
printf 'GitHub Release archive: %s\n' "$archive"
