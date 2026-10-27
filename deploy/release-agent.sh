#!/usr/bin/env bash
# Publish a signed Agent release from exactly the commit that was built.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:-}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo 'usage: deploy/release-agent.sh X.Y.Z' >&2
  exit 2
}
tag="v$version"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || {
  echo 'refusing to tag: Git worktree has staged, unstaged or untracked changes' >&2
  exit 1
}
head=$(git rev-parse HEAD)
source_version=$(git show "$head:internal/agent/version.go" | sed -n 's/^var Version = "\([^"]*\)"$/\1/p')
[[ "$source_version" == "$version" ]] || {
  echo "refusing to tag: commit has Agent version $source_version, not $version" >&2
  exit 1
}
[[ "$(git show "$head:deploy/Agent.Dockerfile" | sed -n 's/^ARG AGENT_VERSION=//p')" == "$version" ]] || {
  echo 'refusing to tag: Agent.Dockerfile default version differs' >&2
  exit 1
}
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && {
  echo "refusing to replace existing local tag $tag" >&2
  exit 1
}

for arch in amd64 arm64; do
  archive="dist/release/mui-agent-$version-linux-$arch.tar.gz"
  [[ -s "$archive" && -s "$archive.commit" ]] || {
    echo "missing built archive or source commit: $archive" >&2
    exit 1
  }
  [[ "$(cat "$archive.commit")" == "$head" ]] || {
    echo "$archive was built from a different commit" >&2
    exit 1
  }
  temp=$(mktemp -d)
  trap 'rm -rf -- "$temp"' EXIT
  tar -xzf "$archive" -C "$temp"
  for name in mui-agent sing-box SHA256SUMS SHA256SUMS.sig; do
    [[ -s "$temp/$arch/$name" && ! -L "$temp/$arch/$name" ]] || {
      echo "$archive is missing $name" >&2
      exit 1
    }
  done
  [[ "$(find "$temp/$arch" -type f | wc -l | tr -d ' ')" == 4 ]] || {
    echo "$archive contains unexpected files" >&2
    exit 1
  }
  (cd "$temp/$arch" && sha256sum -c --status SHA256SUMS)
  for name in mui-agent sing-box SHA256SUMS SHA256SUMS.sig; do
    cmp -s "$temp/$arch/$name" "bin/$arch/$name" || {
      echo "$archive differs from built bin/$arch/$name" >&2
      exit 1
    }
  done
  rm -rf -- "$temp"
  trap - EXIT
done

for command in gh git; do command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }; done
gh auth status >/dev/null
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
  echo "refusing to replace existing remote tag $tag" >&2
  exit 1
else
  result=$?
  [[ "$result" == 2 ]] || { echo 'cannot check remote tags; release stopped' >&2; exit 1; }
fi
notes="docs/releases/$tag.md"
[[ -s "$notes" ]] || { echo "missing release notes: $notes" >&2; exit 1; }

git tag -a "$tag" "$head" -m "MUI Agent $tag"
git push origin "refs/tags/$tag"
gh release create "$tag" \
  "dist/release/mui-agent-$version-linux-amd64.tar.gz" \
  "dist/release/mui-agent-$version-linux-arm64.tar.gz" \
  --title "MUI Agent $tag" --notes-file "$notes" --verify-tag
for old in v0.6.18 v0.6.19 v0.6.20; do
  previous=$(mktemp)
  updated=$(mktemp)
  if ! gh release view "$old" --json body --jq .body > "$previous"; then
    rm -f -- "$previous" "$updated"
    echo "warning: could not read $old release notes; mark it obsolete manually" >&2
    continue
  fi
  if ! grep -Fq 'OBSOLETE: do not use this release for online installs' "$previous"; then
    printf '%s\n\n' 'OBSOLETE: do not use this release for online installs. Its tag points to source that predates GitHub Release distribution. Use v0.6.21 or newer.' > "$updated"
    cat "$previous" >> "$updated"
    gh release edit "$old" --notes-file "$updated"
  fi
  rm -f -- "$previous" "$updated"
done
printf 'Published %s at %s\n' "$tag" "$head"
