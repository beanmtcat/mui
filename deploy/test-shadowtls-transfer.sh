#!/bin/sh
# End-to-end regression for sing-shadowtls's vectorised write path, which
# starts after roughly 512 KiB. The container has no network or host ports.
set -eu
if [ "${1:-}" != '--inside' ]; then
  cd "$(dirname "$0")/.."
  server_binary=${1:-bin/amd64/sing-box}
  client_binary=${2:-$server_binary}
  arch=${3:-amd64}
  case "$server_binary" in /*) ;; *) server_binary="$(pwd)/$server_binary" ;; esac
  case "$client_binary" in /*) ;; *) client_binary="$(pwd)/$client_binary" ;; esac
  test -f "$server_binary"
  test -f "$client_binary"
  test_bytes=${MUI_SHADOWTLS_TEST_BYTES:-2097152}
  exec docker run --rm --network none --platform "linux/$arch" \
    -e "MUI_SHADOWTLS_TEST_BYTES=$test_bytes" \
    -v "$server_binary:/server-box:ro" -v "$client_binary:/client-box:ro" \
    -v "$(pwd)/deploy/test-shadowtls-transfer.sh:/test.sh:ro" \
    --entrypoint /bin/sh golang:1.26.10-bookworm /test.sh --inside
fi
cd /tmp
server_core=/server-box
client_core=/client-box
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 1 -subj /CN=localhost >/dev/null 2>&1
python3 - <<'PY'
import os
remaining = int(os.environ['MUI_SHADOWTLS_TEST_BYTES'])
if remaining < 1:
    raise ValueError('MUI_SHADOWTLS_TEST_BYTES must be positive')
with open('blob', 'wb') as output:
    while remaining:
        chunk = os.urandom(min(1024 * 1024, remaining))
        output.write(chunk)
        remaining -= len(chunk)
PY
expected_size=$(wc -c < blob)
expected_hash=$(sha256sum blob | cut -d ' ' -f 1)
openssl s_server -quiet -tls1_3 -accept 127.0.0.1:14443 -cert tls.crt -key tls.key -www >tls.log 2>&1 &
tls_pid=$!
python3 -m http.server 18081 --bind 127.0.0.1 >http.log 2>&1 &
http_pid=$!
trap 'kill "$tls_pid" "$http_pid" ${server_pid:-} ${client_pid:-} 2>/dev/null || true' EXIT
failures=0
for pair in '5 4 true' '5 4 false' '6 6 true' '6 6 false'; do
  set -- $pair
  server_version=$1
  client_version=$2
  strict=$3
  SERVER_VERSION="$server_version" CLIENT_VERSION="$client_version" STRICT="$strict" python3 - <<'PY'
import json, os
sv=int(os.environ['SERVER_VERSION']); cv=int(os.environ['CLIENT_VERSION'])
inner={'type':'snell','tag':'snell','listen':'127.0.0.1','listen_port':8443,'version':sv,'psk':'test-only-psk'}
inner.update({'obfs_mode':'none'} if sv==5 else {'mode':'default'})
server={'log':{'level':'debug'},'inbounds':[{'type':'shadowtls','tag':'shadowtls','listen':'127.0.0.1','listen_port':12306,'detour':'snell','version':3,'users':[{'name':'test','password':'test-only-shadow-password'}],'handshake':{'server':'127.0.0.1','server_port':14443},'strict_mode':os.environ['STRICT']=='true'},inner],'outbounds':[{'type':'direct','tag':'direct'}]}
out={'type':'snell','tag':'snell-out','server':'127.0.0.1','server_port':12306,'version':cv,'psk':'test-only-psk','detour':'shadowtls-out'}
out.update({'mode':'default'} if cv==6 else {'obfs_mode':'none'})
client={'log':{'level':'debug'},'inbounds':[{'type':'mixed','tag':'mixed','listen':'127.0.0.1','listen_port':1080}],'outbounds':[out,{'type':'shadowtls','tag':'shadowtls-out','server':'127.0.0.1','server_port':12306,'version':3,'password':'test-only-shadow-password','tls':{'enabled':True,'server_name':'localhost','insecure':True}}],'route':{'final':'snell-out'}}
for name, config in [('server',server),('client',client)]:
    with open(name+'.json','w') as f: json.dump(config,f)
PY
  "$server_core" check -c server.json
  "$client_core" check -c client.json
  "$server_core" run -c server.json >server.log 2>&1 &
  server_pid=$!
  "$client_core" run -c client.json >client.log 2>&1 &
  client_pid=$!
  sleep 2
  printf 'Snell server v%s, client v%s, strict %s: ' "$server_version" "$client_version" "$strict"
  rm -f received.bin
  if result=$(curl --silent --show-error --fail --max-time 180 --proxy socks5h://127.0.0.1:1080 -o received.bin -w '%{size_download} bytes, HTTP %{http_code}, %{time_total}s' http://127.0.0.1:18081/blob); then
    received_size=$(wc -c < received.bin)
    received_hash=$(sha256sum received.bin | cut -d ' ' -f 1)
    if [ "$received_size" -eq "$expected_size" ] && [ "$received_hash" = "$expected_hash" ]; then
      printf '%s, SHA-256 matched\n' "$result"
    else
      printf '%s, expected %s bytes, SHA-256 mismatch\n' "$result" "$expected_size"
      failures=$((failures + 1))
    fi
  else
    printf '%s\n' "$result"
    grep -E 'ERROR|verification failed|broken pipe' server.log client.log | tail -20 || true
    failures=$((failures + 1))
  fi
  kill "$server_pid" "$client_pid"
  wait "$server_pid" "$client_pid" 2>/dev/null || true
  unset server_pid client_pid
done
test "$failures" -eq 0
