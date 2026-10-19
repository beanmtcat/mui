//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"mui/internal/shared"
)

// Run only in a disposable Linux container, preferably --network none. The
// systemctl fixture starts the real installed CLI as mui-forward; no panel,
// core, UFW or helper is available. Tests real readiness and failed-reload
// rollback rather than treating a successful SIGHUP as an applied config.
func TestOfflineLinuxInstallAndApply(t *testing.T) {
	if os.Getenv("MUI_TEST_OFFLINE") != "1" {
		t.Skip("requires disposable Linux container and MUI_TEST_AGENT_BINARY")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture needs root")
	}
	binary := os.Getenv("MUI_TEST_AGENT_BINARY")
	if binary == "" {
		t.Fatal("MUI_TEST_AGENT_BINARY is required")
	}
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)
	dir, tools := t.TempDir(), t.TempDir()
	state := filepath.Join(dir, "systemd")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
pidfile=/run/mui-forward/process.pid
alive() { test -f "$pidfile" && kill -0 "$(cat "$pidfile")" 2>/dev/null; }
stop() {
  if alive; then
    pid=$(cat "$pidfile")
    kill -TERM "$pid" 2>/dev/null || true
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do sleep 0.05; i=$((i+1)); done
  fi
  rm -f "$pidfile"
}
case "$1" in
  is-active) alive ;;
  is-enabled) test -f "$MUI_OFFLINE_FIXTURE/enabled" ;;
  daemon-reload) : ;;
  enable) touch "$MUI_OFFLINE_FIXTURE/enabled" ;;
  disable) rm -f "$MUI_OFFLINE_FIXTURE/enabled" ;;
  stop) stop ;;
  restart)
    stop
    mkdir -p /run/mui-forward
    chown mui-forward:mui-forward /run/mui-forward
    chmod 700 /run/mui-forward
    /usr/sbin/runuser -u mui-forward -- /bin/sh -c 'echo $$ > /run/mui-forward/process.pid; exec /usr/local/bin/mui-agent forward' </dev/null >"$MUI_OFFLINE_FIXTURE/forward.log" 2>&1 &
    ;;
  reload) alive; kill -HUP "$(cat "$pidfile")" ;;
  *) exit 91 ;;
esac
`
	if err := os.WriteFile(filepath.Join(tools, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ufw", "curl", "sshd", "systemd-run"} {
		if err := os.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\necho unexpected > \"$MUI_OFFLINE_FIXTURE/unexpected\"\nexit 97\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", tools+":"+os.Getenv("PATH"))
	t.Setenv("MUI_OFFLINE_FIXTURE", state)
	t.Cleanup(func() { _, _ = command("systemctl", "stop", "mui-forward.service") })
	// The release is generated inside this disposable fixture. No production
	// signing key is mounted or used by the test.
	self := filepath.Join(dir, "mui-agent")
	if err := copyFile(binary, self, 0755); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(self)
	manifest := []byte(fmt.Sprintf("%x  mui-agent\n", sha256.Sum256(data)))
	for name, contents := range map[string][]byte{"SHA256SUMS": manifest, "SHA256SUMS.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest)))} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(wantOK bool, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, self, args...).CombinedOutput()
		if (err == nil) != wantOK {
			logs, _ := os.ReadFile(filepath.Join(state, "forward.log"))
			t.Fatalf("%v: %v %s; forward log: %s", args, err, out, logs)
		}
		return string(out)
	}
	config := filepath.Join(dir, "forwards.json")
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	_ = free.Close()
	rules := []shared.ForwardRule{{ID: "entry", Name: "entry", Network: shared.ForwardTCPUDP, Listen: "127.0.0.1", Port: port, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}, FirewallPolicy: "manual", Enabled: true}}
	writeConfig := func() {
		t.Helper()
		raw, _ := json.Marshal(rules)
		if err := os.WriteFile(config, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	keyArg := base64.StdEncoding.EncodeToString(pub)
	run(true, "offline", "install", "--config", config, "--release-key", keyArg)
	for _, path := range []string{ConfigDir + "/config.json", "/etc/systemd/system/mui-agent.service", "/etc/systemd/system/mui-agent-helper.service", CoreBinaryPath, filepath.Join(state, "unexpected")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("offline install created or called %s: %v", path, err)
		}
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{ForwardDir, 0750}, {ForwardConfig, 0640}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("wrong permissions: %s %v %v", item.path, info, err)
		}
	}
	// A running service under its real account proves the restrictive-umask
	// install left the directory and config readable by that account.
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err != nil {
		t.Fatalf("offline listener not available: %v", err)
	} else {
		_ = conn.Close()
	}
	// A combined rule must own its UDP socket as well as TCP, while remaining
	// one logical config item and one traffic counter.
	if probe, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		_ = probe.Close()
		t.Fatal("combined offline rule did not bind UDP")
	}
	pidBefore, _ := os.ReadFile("/run/mui-forward/process.pid")
	old, _ := os.ReadFile(ForwardConfig)
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	bad := rules[0]
	bad.ID, bad.Port = "conflicting", blocked.Addr().(*net.TCPAddr).Port
	rules = append(rules, bad)
	writeConfig()
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "已恢复原配置") {
		t.Fatalf("reload did not report rollback: %s", out)
	}
	after, _ := os.ReadFile(ForwardConfig)
	pidAfter, _ := os.ReadFile("/run/mui-forward/process.pid")
	if string(after) != string(old) || string(pidBefore) != string(pidAfter) {
		t.Fatal("failed reload changed old config or restarted the unchanged forwarder")
	}
	// A valid update is acknowledged and keeps the same process running.
	rules = rules[:1]
	rules[0].Targets[0].Port = 444
	writeConfig()
	run(true, "offline", "apply", config)
	// Reinstalling with a corrupted signature or a replacement key must not
	// alter the installed config, binary or running service.
	sigPath := filepath.Join(dir, "SHA256SUMS.sig")
	sig, _ := os.ReadFile(sigPath)
	if err := os.WriteFile(sigPath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	run(false, "offline", "install", "--config", config, "--release-key", keyArg)
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if out := run(false, "offline", "install", "--config", config, "--release-key", base64.StdEncoding.EncodeToString(otherPub)); !strings.Contains(out, "不能替换") {
		t.Fatalf("pinned signing key was not enforced: %s", out)
	}
	// A reinstall/upgrade that cannot start must restore the old on-disk
	// config and confirm that the old service has started successfully.
	beforeInstall, _ := os.ReadFile(ForwardConfig)
	rules = append(rules, bad)
	writeConfig()
	run(false, "offline", "install", "--config", config, "--release-key", keyArg)
	afterInstall, _ := os.ReadFile(ForwardConfig)
	if string(beforeInstall) != string(afterInstall) {
		t.Fatal("failed reinstall did not restore previous config")
	}
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err != nil {
		t.Fatalf("failed reinstall did not restore old listener: %v", err)
	} else {
		_ = conn.Close()
	}
	rules = nil
	if err := os.WriteFile(config, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	run(true, "offline", "apply", config)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("removed rule is still listening")
	}
	// Switch from standalone JSON to a panel-signed config. Installation and
	// subsequent configuration loading still happen with the network disabled.
	_, panelKey, _ := ed25519.GenerateKey(rand.Reader)
	rules = []shared.ForwardRule{{ID: "panel-entry", ServerID: "offline-server", Name: "panel", Network: shared.ForwardTCPUDP, Listen: "127.0.0.1", Port: port, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}, FirewallPolicy: "manual", Enabled: true}}
	bundle := shared.OfflineBundle{ExportID: "first-export", ServerID: "offline-server", Revision: 1, Forwards: rules}
	writeBundle := func(b shared.OfflineBundle) {
		t.Helper()
		b.Sign(panelKey)
		raw, _ := json.Marshal(b)
		if err := os.WriteFile(config, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeBundle(bundle)
	run(true, "offline", "install", "--config", config, "--release-key", keyArg)
	// The exact signed document is saved for identity and rollback checks.
	rawBundle, _ := os.ReadFile(config)
	_ = json.Unmarshal(rawBundle, &bundle)
	info, err := os.Stat(OfflineBundlePath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private bundle mode: %v", err)
	}
	if _, err := os.Stat(ForwardDir + "/receipt.json"); !os.IsNotExist(err) {
		t.Fatal("offline install must not generate a receipt")
	}
	previousBundle, _ := os.ReadFile(OfflineBundlePath)
	badBundle := bundle
	badBundle.Revision = 2
	badBundle.ExportID = "bad-export"
	bad.ServerID = bundle.ServerID
	bad.FirewallPolicy = "manual"
	badBundle.Forwards = append(append([]shared.ForwardRule{}, bundle.Forwards...), bad)
	writeBundle(badBundle)
	run(false, "offline", "apply", config)
	afterBundle, _ := os.ReadFile(OfflineBundlePath)
	if string(previousBundle) != string(afterBundle) {
		t.Fatal("failed application replaced pinned bundle")
	}
	wrong := bundle
	wrong.ServerID = "wrong-server"
	wrong.Forwards = append([]shared.ForwardRule{}, bundle.Forwards...)
	wrong.Forwards[0].ServerID = wrong.ServerID
	writeBundle(wrong)
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "身份") {
		t.Fatalf("wrong target accepted: %s", out)
	}
	changed := bundle
	changed.Forwards = append([]shared.ForwardRule{}, bundle.Forwards...)
	changed.Forwards[0].Port = port + 1
	writeBundle(changed)
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "同版本") {
		t.Fatalf("same version changed config accepted: %s", out)
	}
	// A valid newer export updates the pinned bundle. Replaying revision 1 fails.
	latest := bundle
	latest.Revision = 2
	latest.ExportID = "second-export"
	writeBundle(latest)
	run(true, "offline", "apply", config)
	rawBundle, _ = os.ReadFile(config)
	_ = json.Unmarshal(rawBundle, &latest)
	stored, err := os.ReadFile(OfflineBundlePath)
	if err != nil || string(stored) != string(rawBundle) {
		t.Fatalf("new signed bundle not saved: %v", err)
	}
	writeBundle(bundle)
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "旧版本") {
		t.Fatalf("old revision accepted: %s", out)
	}
	if err := os.WriteFile(config, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "面板离线配置") {
		t.Fatalf("unsigned overwrite accepted: %s", out)
	}
	// Upgrades run through the installed binary, which checks the new one
	// against the pinned release key before running any of it.
	installedBefore, _ := os.ReadFile("/usr/local/bin/mui-agent")
	upgrade := func(wantOK bool, candidate string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/local/bin/mui-agent", "offline", "upgrade", "--binary", candidate).CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("upgrade %s: %v %s", candidate, err, out)
		}
		return string(out)
	}
	release := func(binary []byte, signer ed25519.PrivateKey, manifestFor []byte) string {
		t.Helper()
		release := t.TempDir()
		manifest := []byte(fmt.Sprintf("%x  mui-agent\n", sha256.Sum256(manifestFor)))
		files := map[string][]byte{"mui-agent": binary, "SHA256SUMS": manifest, "SHA256SUMS.sig": []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(signer, manifest)))}
		for name, contents := range files {
			if err := os.WriteFile(filepath.Join(release, name), contents, 0755); err != nil {
				t.Fatal(err)
			}
		}
		return filepath.Join(release, "mui-agent")
	}
	// Without a pinned key, even a matching checksum must never allow the
	// uploaded executable's version command (or install command) to run.
	pinned, err := os.ReadFile(OfflineReleaseKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(OfflineReleaseKeyPath); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "executed")
	unsigned := []byte("#!/bin/sh\necho executed > " + marker + "\necho 0.6.8\n")
	if out := upgrade(false, release(unsigned, private, unsigned)); !strings.Contains(out, "未固定发布公钥") {
		t.Fatalf("missing pinned key not refused: %s", out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unsigned candidate executed before signature verification")
	}
	if err := os.WriteFile(OfflineReleaseKeyPath, pinned, 0644); err != nil {
		t.Fatal(err)
	}

	tampered := append(append([]byte(nil), data...), 0)
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	if out := upgrade(false, release(tampered, otherPrivate, tampered)); !strings.Contains(out, "校验失败") {
		t.Fatalf("a binary signed with another key was not refused: %s", out)
	}
	if out := upgrade(false, release(tampered, private, data)); !strings.Contains(out, "校验失败") {
		t.Fatalf("a binary not matching its manifest was not refused: %s", out)
	}
	if installedNow, _ := os.ReadFile("/usr/local/bin/mui-agent"); string(installedNow) != string(installedBefore) {
		t.Fatal("a refused upgrade changed the installed binary")
	}
	upgrade(true, release(data, private, data))
	stored, err = os.ReadFile(OfflineBundlePath)
	if err != nil || string(stored) != string(rawBundle) {
		t.Fatalf("upgrade changed signed bundle: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err != nil {
		t.Fatalf("listener after upgrade: %v", err)
	} else {
		_ = conn.Close()
	}
	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigDir+"/config.json", []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if out := run(false, "offline", "apply", config); !strings.Contains(out, "面板接入配置") {
		t.Fatalf("competing online/offline management not rejected: %s", out)
	}
}
