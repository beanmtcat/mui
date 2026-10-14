#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
arch="${1:-amd64}"
core_version="${2:-v1.14.2}"
case "$arch" in amd64|arm64) ;; *) echo "usage: $0 [amd64|arm64] [sing-box version, for example v1.14.2]" >&2; exit 2;; esac
if [[ ! "$core_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "sing-box version must be a vX.Y.Z release tag" >&2
  exit 2
fi
mkdir -p "bin/$arch"
# Optional upstream commit pin for the sing-box tag above. Look the commit up
# with: git ls-remote https://github.com/SagerNet/sing-box.git "refs/tags/${core_version}^{}"
# Without it the build trusts the tag; a moved tag would change the output.
docker buildx build --platform "linux/$arch" --build-arg "SING_BOX_VERSION=$core_version" --build-arg "SING_BOX_COMMIT=${SING_BOX_COMMIT:-}" --file deploy/Agent.Dockerfile --output "type=local,dest=bin/$arch" .
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
if [[ -n "${MUI_RELEASE_KEY:-}" ]]; then
  go run ./cmd/release-sign sign "$MUI_RELEASE_KEY" "bin/$arch"
  # A signing key was provided, so a missing .sig is a build failure, not a
  # silent unsigned build. Without MUI_RELEASE_KEY the build is unsigned and
  # only a warning is printed (see below).
  if [[ ! -s "bin/$arch/SHA256SUMS.sig" ]]; then
    echo "release signing produced no bin/$arch/SHA256SUMS.sig" >&2
    exit 1
  fi
  printf 'Signed bin/%s/SHA256SUMS\n' "$arch"
else
  echo "warning: no MUI_RELEASE_KEY, bin/$arch is UNSIGNED (agents that pinned a release key will refuse it)" >&2
fi
printf 'Built bin/%s/mui-agent and bin/%s/sing-box\n' "$arch" "$arch"
