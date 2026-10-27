#!/bin/sh
set -eu
umask 077

usage() {
  echo 'usage: sh INSTALL_SCRIPT PANEL_URL SERVER_ID ENROLL_TOKEN|- node|relay [RELEASE_PUBLIC_KEY] [PROXY_DIRECTORY] [GITHUB_RELEASE_VERSION]' >&2
  exit 2
}
[ "$#" -ge 4 ] && [ "$#" -le 7 ] || usage
panel_url=$1
server_id=$2
enroll_token=$3
purpose=$4
release_key=${5:-}
proxy_dir=${6:-}
release_version=${7:-}
# The caller created these credential files with umask 077.
if [ -n "$proxy_dir" ]; then
  test -f "$proxy_dir/proxy.json" && test -f "$proxy_dir/curl.conf" || { echo 'missing proxy files' >&2; exit 1; }
fi
if [ "$enroll_token" = - ]; then
  IFS= read -r enroll_token || {
    echo 'could not read enrollment token from stdin' >&2
    exit 2
  }
fi
case "$purpose" in
  node|relay) ;;
  *) echo 'server purpose must be node or relay' >&2; exit 2 ;;
esac
if [ -z "$enroll_token" ]; then
  echo 'enrollment token is empty; copy the whole command from the panel' >&2
  exit 2
fi

case "$panel_url" in
  https://*|http://127.0.0.1:*) ;;
  *) echo 'panel URL must use HTTPS' >&2; exit 1 ;;
esac
if [ "$(uname -s)" != Linux ]; then
  echo 'MUI Agent requires Linux' >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'unsupported CPU architecture' >&2; exit 1 ;;
esac
for tool in curl sha256sum mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

tempdir="$(mktemp -d)"
workdir=$tempdir
trap 'rm -rf "$tempdir"' EXIT HUP INT TERM
base="${panel_url%/}/download/$arch"
files='mui-agent SHA256SUMS'
if [ "$purpose" = node ]; then files="$files sing-box"; fi
# With a release key the agent itself checks the manifest signature before it
# installs anything, and pins the key for later upgrades.
if [ -n "$release_key" ]; then files="$files SHA256SUMS.sig"; fi
if [ -n "$release_version" ]; then
  printf '%s' "$release_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'invalid GitHub release version' >&2; exit 1; }
  command -v tar >/dev/null 2>&1 || { echo 'tar is required' >&2; exit 1; }
  archive="https://github.com/beanmtcat/mui/releases/download/v$release_version/mui-agent-$release_version-linux-$arch.tar.gz"
  if [ -n "$proxy_dir" ]; then
    curl --config "$proxy_dir/curl.conf" --fail --silent --show-error --location --retry 3 --output "$tempdir/release.tar.gz" "$archive"
  else
    curl --fail --silent --show-error --location --retry 3 --output "$tempdir/release.tar.gz" "$archive"
  fi
  set --
  for name in $files; do set -- "$@" "$arch/$name"; done
  tar -xzf "$tempdir/release.tar.gz" -C "$tempdir" "$@"
  for name in $files; do
    test -f "$tempdir/$arch/$name" && test ! -L "$tempdir/$arch/$name" || { echo "invalid release file: $name" >&2; exit 1; }
  done
  workdir="$tempdir/$arch"
else
  for name in $files; do
    if [ -n "$proxy_dir" ]; then
      curl --config "$proxy_dir/curl.conf" --fail --silent --show-error --location --output "$workdir/$name" "$base/$name"
    else
      curl --fail --silent --show-error --location --output "$workdir/$name" "$base/$name"
    fi
  done
fi
# Strictly verify every downloaded binary against the manifest -- never with
# --ignore-missing, which would silently skip a file whose entry is absent
# from the manifest. The manifest also lists files this install does not
# download (sing-box for a relay), so only the downloaded files are checked,
# and each of them must have exactly one manifest entry.
verify='mui-agent'
if [ "$purpose" = node ]; then verify="$verify sing-box"; fi
(cd "$workdir" && : > checked.txt && for name in $verify; do grep -E " \\*?$name\$" SHA256SUMS >> checked.txt || exit 1; done && test "$(wc -l < checked.txt)" = "$(printf '%s\n' $verify | wc -l)" && sha256sum -c checked.txt >/dev/null) || {
  echo 'download checksum verification failed' >&2
  exit 1
}
chmod 755 "$workdir/mui-agent"
set --
if [ -n "$proxy_dir" ]; then set -- --proxy-file "$proxy_dir/proxy.json"; fi
if [ "$purpose" = node ]; then
  chmod 755 "$workdir/sing-box"
  printf '%s\n' "$enroll_token" | "$workdir/mui-agent" install "$panel_url" "$server_id" - "$workdir/sing-box" "$release_key" --token-stdin "$@"
else
  printf '%s\n' "$enroll_token" | "$workdir/mui-agent" install "$panel_url" "$server_id" - - "$release_key" --token-stdin "$@"
fi
printf '%s\n' 'MUI Agent 安装完成。'
