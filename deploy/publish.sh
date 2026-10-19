#!/usr/bin/env bash
# Run locally; the SSH host builds the images and runs Docker Compose.
set -euo pipefail
umask 077
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
config="$script_dir/publish.env"
service=all
init_env=
with_agent=0

usage() {
  cat <<'HELP'
用法：deploy/publish.sh [选项]
  --config FILE         SSH 发布配置，默认 deploy/publish.env
  --service NAME        all（默认）、backend 或 frontend
  --init-env FILE        首次上传生产 .env；远程已存在时拒绝覆盖
  --with-agent          同步本地 bin/ 下已构建的 Agent/sing-box 发布文件
  -h, --help            显示帮助

首次：cp deploy/publish.env.example deploy/publish.env，填写 SSH 主机和目录。
      deploy/publish.sh --init-env deploy/.env
更新：deploy/publish.sh
      deploy/publish.sh --service frontend
HELP
}
die() { printf '发布失败：%s\n' "$*" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config|--service|--init-env)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 需要参数"
      case "$1" in --config) config=$2;; --service) service=$2;; --init-env) init_env=$2;; esac
      shift 2;;
    --with-agent) with_agent=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "未知选项：$1（使用 --help 查看用法）";;
  esac
done
case "$service" in all|backend|frontend) ;; *) die '--service 只能是 all/backend/frontend';; esac
[[ -f "$config" ]] || die "请复制 deploy/publish.env.example 为 $config 并填写配置"
# Bash expands an unquoted ~/ assignment on this machine when sourcing the
# configuration. Reject it before it silently becomes a path on the remote host.
remote_tilde_assignment='^[[:space:]]*(export[[:space:]]+)?REMOTE_DIR=~'
while IFS= read -r config_line || [[ -n "$config_line" ]]; do
  if [[ "$config_line" =~ $remote_tilde_assignment ]]; then
    die 'REMOTE_DIR 不能使用 ~：它会在本机展开；请填写远程绝对路径，例如 /root/docker/mui'
  fi
done < "$config"
# This is a trusted local Bash configuration file; values containing spaces
# or shell metacharacters must be quoted, as in the example.
source "$config"
: "${SSH_HOST:?请在发布配置中填写 SSH_HOST}"
REMOTE_DIR=${REMOTE_DIR:-/opt/mui}
SSH_PORT=${SSH_PORT:-22}
SSH_KEY=${SSH_KEY:-}
COMPOSE_PROJECT=${COMPOSE_PROJECT:-mui}
COMPOSE_FILES=${COMPOSE_FILES:-compose.yaml}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-120}
[[ "$SSH_HOST" != -* && "$SSH_HOST" != *[$'\r\n\t ']* ]] || die 'SSH_HOST 应为 SSH 配置别名或 user@host'
[[ "$SSH_PORT" =~ ^[0-9]+$ && ${#SSH_PORT} -le 5 && 10#$SSH_PORT -ge 1 && 10#$SSH_PORT -le 65535 ]] || die 'SSH_PORT 无效'
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ && ${#HEALTH_TIMEOUT} -le 5 && 10#$HEALTH_TIMEOUT -ge 1 ]] || die 'HEALTH_TIMEOUT 必须是 1–99999 秒'
[[ "$REMOTE_DIR" == /* && "$REMOTE_DIR" != *[$'\r\n']* ]] || die 'REMOTE_DIR 必须是绝对路径'
while [[ "$REMOTE_DIR" == */ ]]; do REMOTE_DIR=${REMOTE_DIR%/}; done
[[ -n "$REMOTE_DIR" && "$REMOTE_DIR" != */../* && "$REMOTE_DIR" != */.. && "$REMOTE_DIR" != */./* && "$REMOTE_DIR" != */. ]] || die 'REMOTE_DIR 不能是根目录或含 .、.. 段'
[[ "$COMPOSE_PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die 'COMPOSE_PROJECT 只能包含小写字母、数字、短横线和下划线'
[[ -z "$init_env" || -f "$init_env" ]] || die "生产配置文件不存在：$init_env"
[[ "$with_agent" == 0 || "$service" != frontend ]] || die '--with-agent 需要同时发布后端'
for command in ssh tar; do command -v "$command" >/dev/null || die "本机缺少 $command"; done
ssh_args=(-p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
if [[ -n "$SSH_KEY" ]]; then
  [[ -f "$SSH_KEY" ]] || die "SSH 私钥不存在：$SSH_KEY"
  ssh_args+=(-i "$SSH_KEY")
fi
# POSIX shell quoting: SSH passes its remote command through the login shell.
quote() {
  local value="$1" apostrophe="'" replacement="'\"'\"'"
  value=${value//"$apostrophe"/"$replacement"}
  printf "'%s'" "$value"
}
remote() {
  local cmd='bash -s --' arg
  for arg in "$@"; do cmd+=" $(quote "$arg")"; done
  ssh "${ssh_args[@]}" "$SSH_HOST" "$cmd"
}
read -r -a compose_files <<< "$COMPOSE_FILES"
[[ ${#compose_files[@]} -gt 0 ]] || die 'COMPOSE_FILES 不能为空'
for file in "${compose_files[@]}"; do
  case "$file" in compose.yaml|compose.web.yaml|compose.backend.yaml) ;; *) die "不支持的 Compose 文件：$file";; esac
done
if [[ "$COMPOSE_FILES" == *compose.web.yaml* && "$service" != frontend ]]; then
  die 'compose.web.yaml 应使用 --service frontend'
fi
# Explicit allowlist: no Git metadata, local .env, SSH/signing keys, TLS keys,
# database files, node_modules or build caches can enter the source archive.
files=(go.mod go.sum .dockerignore cmd internal web/src web/package.json web/package-lock.json
  web/tsconfig.json web/vite.config.ts web/index.html deploy/Mui.Dockerfile deploy/Web.Dockerfile
  deploy/Agent.Dockerfile deploy/build-agent.sh deploy/compose.yaml deploy/compose.web.yaml
  deploy/compose.backend.yaml deploy/nginx deploy/.env.example deploy/web.env.example
  deploy/publish.sh deploy/publish.env.example)
if [[ "$with_agent" == 1 ]]; then
  release_key=${MUI_RELEASE_KEY:-"$script_dir/.secrets/release.key"}
  if [[ -n "${MUI_RELEASE_KEY:-}" && ! -f "$release_key" ]]; then
    die "发布签名私钥不存在：$release_key"
  fi
  if [[ -f "$release_key" ]]; then
    command -v go >/dev/null || die '自动签名需要本机安装 Go'
  fi
  found=0
  for arch in amd64 arm64; do
    [[ -d "$repo_dir/bin/$arch" ]] || continue
    for file in mui-agent sing-box SHA256SUMS; do
      [[ -f "$repo_dir/bin/$arch/$file" && ! -L "$repo_dir/bin/$arch/$file" ]] || die "缺少普通文件 bin/$arch/$file；先运行 deploy/build-agent.sh $arch"
      files+=("bin/$arch/$file")
    done
    if [[ -f "$release_key" ]]; then
      (cd "$repo_dir" && go run ./cmd/release-sign sign "$release_key" "bin/$arch")
    fi
    if [[ -f "$repo_dir/bin/$arch/SHA256SUMS.sig" ]]; then files+=("bin/$arch/SHA256SUMS.sig"); fi
    found=1
  done
  [[ "$found" == 1 ]] || die '未找到 Agent 发布文件，请先运行 deploy/build-agent.sh'
fi
stage=
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$stage" ]]; then
    # Only remove this invocation's mktemp directory, never a release or data.
    remote "$REMOTE_DIR" "$stage" <<'CLEAN' >/dev/null 2>&1 || true
root=$1; stage=$2
[[ "$stage" == "$root"/.publish-* && -d "$stage" && ! -L "$stage" ]] && rm -rf -- "$stage"
CLEAN
  fi
  exit "$status"
}
trap cleanup EXIT
printf '检查远程主机 %s…\n' "$SSH_HOST"
printf '远程发布目录：%s\n' "$REMOTE_DIR"
stage=$(remote "$REMOTE_DIR" "$init_env" <<'PREFLIGHT'
set -euo pipefail
umask 077
root=$1
for tool in docker tar flock; do command -v "$tool" >/dev/null || { echo "目标机缺少 $tool" >&2; exit 1; }; done
docker info >/dev/null
docker compose version >/dev/null
help=$(docker compose up --help)
[[ "$help" == *--wait-timeout* ]] || { echo '请更新 Docker Compose，需支持 up --wait-timeout' >&2; exit 1; }
if [[ -n "$2" && -e "$root/deploy/.env" ]]; then printf '远程 %s/deploy/.env 已存在，拒绝覆盖；更新时去掉 --init-env\n' "$root" >&2; exit 1; fi
if [[ -z "$2" && ! -s "$root/deploy/.env" ]]; then printf '远程缺少 %s/deploy/.env；首次发布请使用 --init-env 指定生产配置\n' "$root" >&2; exit 1; fi
mkdir -p -- "$root"
[[ "$(cd "$root" && pwd -P)" != / ]] || { echo '发布目录不能指向根目录' >&2; exit 1; }
[[ ! -e "$root/current" || -L "$root/current" ]] || { echo 'current 必须是发布脚本维护的符号链接' >&2; exit 1; }
mkdir -p -- "$root/releases" "$root/deploy" "$root/bin"
mktemp -d "$root/.publish-XXXXXXXX"
PREFLIGHT
)
[[ "$stage" == "$REMOTE_DIR"/.publish-* && "$stage" != *[$'\r\n']* ]] || die '远程返回的临时目录无效'
printf '上传源码…\n'
# COPYFILE_DISABLE prevents macOS AppleDouble metadata in Linux releases.
# macOS bsdtar also stores extended attributes (provenance, ACLs) as pax
# headers that GNU tar on the target reports one warning each for.
tar_flags=()
if tar --version 2>/dev/null | grep -q bsdtar; then tar_flags=(--no-xattrs --no-acls --no-mac-metadata); fi
COPYFILE_DISABLE=1 tar ${tar_flags[@]+"${tar_flags[@]}"} -czf - -C "$repo_dir" "${files[@]}" |
  ssh "${ssh_args[@]}" "$SSH_HOST" "umask 077; tar -xzf - -C $(quote "$stage")"
if [[ -n "$init_env" ]]; then
  ssh "${ssh_args[@]}" "$SSH_HOST" "umask 077; cat > $(quote "$stage/.publish-env")" < "$init_env"
fi
remote "$REMOTE_DIR" "$stage" "$service" "$COMPOSE_PROJECT" "$HEALTH_TIMEOUT" "$with_agent" "${compose_files[@]}" <<'PUBLISH'
set -euo pipefail
umask 077
root=$1; stage=$2; service=$3; project=$4; timeout=$5; with_agent=$6
shift 6
exec 9>"$root/.publish.lock"
flock -n 9 || { echo '另一场发布正在进行，请稍后重试' >&2; exit 1; }
if [[ -f "$stage/.publish-env" ]]; then
  [[ ! -e "$root/deploy/.env" ]] || { echo '远程 .env 已存在，拒绝覆盖' >&2; exit 1; }
  install -m 600 "$stage/.publish-env" "$root/deploy/.env"
  rm -- "$stage/.publish-env"
fi
[[ -s "$root/deploy/.env" ]] || { echo '远程生产 .env 不存在或为空' >&2; exit 1; }
release="$root/releases/$(date -u +%Y%m%dT%H%M%SZ)-${stage##*.publish-}"
mv -- "$stage" "$release"
on_error() {
  printf '\n发布未完成，current 未切换。诊断文件：%s\n' "$release" >&2
  echo '若容器已更新，请检查其状态后重试；数据库迁移不会自动回退。' >&2
}
trap on_error ERR
if [[ "$with_agent" == 1 ]]; then
  for arch in amd64 arm64; do
    [[ -d "$release/bin/$arch" ]] || continue
    # Accept exactly the two known filenames; never let a checksum manifest
    # reference arbitrary files on the remote host.
    (cd "$release/bin/$arch"
      awk 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/ || ($2 != "mui-agent" && $2 != "sing-box") || seen[$2]++ {bad=1} END {exit (bad || NR != 2)}' SHA256SUMS
      sha256sum -c --status SHA256SUMS)
  done
fi
# Build sources first; running containers are untouched if validation/build fails.
compose=(docker compose --project-name "$project" --env-file "$root/deploy/.env")
for file in "$@"; do compose+=(-f "$release/deploy/$file"); done
case "$service" in all) services=(mui-service mui-web);; backend) services=(mui-service);; frontend) services=(mui-web);; esac
"${compose[@]}" config --quiet
"${compose[@]}" build "${services[@]}"
if [[ "$with_agent" == 1 ]]; then
  for arch in amd64 arm64; do
    [[ -d "$release/bin/$arch" ]] || continue
    install -d -m 755 "$root/bin/$arch"
    for file in mui-agent sing-box SHA256SUMS.sig SHA256SUMS; do
      if [[ -f "$release/bin/$arch/$file" ]]; then
        install -m 644 "$release/bin/$arch/$file" "$root/bin/$arch/.$file.new"
        mv -f -- "$root/bin/$arch/.$file.new" "$root/bin/$arch/$file"
      elif [[ "$file" == SHA256SUMS.sig ]]; then
        rm -f -- "$root/bin/$arch/$file"
      fi
    done
  done
  rm -rf -- "$release/bin"
fi
chmod 755 "$root/bin"
ln -s -- "$root/bin" "$release/bin"
"${compose[@]}" up -d --no-build --no-deps --wait --wait-timeout "$timeout" "${services[@]}"
if [[ "$service" != backend ]]; then
  # Check the real API through inner Nginx too; /nginx-health checks static serving only.
  # SSH feeds this Bash program over stdin. Do not let Compose consume the
  # remaining program while forwarding stdin into the health-check process.
  "${compose[@]}" exec -T mui-web wget -T 10 -q -O /dev/null http://127.0.0.1:8086/healthz </dev/null
fi
"${compose[@]}" ps "${services[@]}"
next="$root/.current-${release##*/}"
ln -s -- "$release" "$next"
mv -fT -- "$next" "$root/current"
printf '\n发布成功：%s\n' "$release"
printf '生产配置：%s/deploy/.env\n' "$root"
PUBLISH
stage=
