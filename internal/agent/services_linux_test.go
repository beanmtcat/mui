//go:build linux

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

// This test installs real services/users and must only run in a disposable
// Alpine container. It deliberately uses the real OpenRC, not a systemctl shim.
func TestOpenRCInstallForwardReloadAndJobs(t *testing.T) {
	if os.Getenv("MUI_TEST_OPENRC") != "1" {
		t.Skip("requires isolated Alpine container")
	}
	if os.Geteuid() != 0 || !openRC() {
		t.Fatal("requires root on OpenRC")
	}
	// The fixture may be rerun inside the same disposable container.
	_ = os.Remove(ReleaseKeyPath)
	if err := checkServiceTools(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/run/openrc", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/run/openrc/softlevel", []byte("default\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A regular Alpine boot creates these state directories. A Docker image
	// has never booted OpenRC, so initialise them before exercising services.
	if _, err := command("rc-status", "--all"); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("MUI_TEST_AGENT_BINARY")
	if binary == "" {
		t.Fatal("MUI_TEST_AGENT_BINARY required")
	}
	dir := t.TempDir()
	self := filepath.Join(dir, "mui-agent")
	if err := copyFile(binary, self, 0755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(self)
	manifest := []byte(fmt.Sprintf("%x  mui-agent\n", sha256.Sum256(data)))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest)))
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), signature, 0644); err != nil {
		t.Fatal(err)
	}
	reports := make(chan shared.AgentReport, 4)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/arm64/mui-agent", "/download/amd64/mui-agent":
			_, _ = w.Write(data)
			return
		case "/download/arm64/SHA256SUMS", "/download/amd64/SHA256SUMS":
			_, _ = w.Write(manifest)
			return
		case "/download/arm64/SHA256SUMS.sig", "/download/amd64/SHA256SUMS.sig":
			_, _ = w.Write(signature)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/agent/enroll" {
			fmt.Fprint(w, `{"agentToken":"fixture-only"}`)
			return
		}
		if r.URL.Path == "/agent/poll" {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/agent/report" {
			var report shared.AgentReport
			_ = json.NewDecoder(r.Body).Decode(&report)
			select {
			case reports <- report:
			default:
			}
		}
		fmt.Fprint(w, `{}`)
	}))
	defer panel.Close()
	if out, err := exec.Command(self, "install", panel.URL, strings.Repeat("a", 32), "fixture-enroll", "-", base64.StdEncoding.EncodeToString(pub)).CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, out)
	}
	t.Cleanup(func() {
		for _, svc := range []string{"mui-agent", "mui-forward", "mui-sing-box", "mui-agent-helper"} {
			_, _ = serviceCommand("stop", svc)
		}
	})
	for _, svc := range []string{"mui-agent", "mui-agent-helper"} {
		if _, err := serviceCommand("is-active", svc); err != nil {
			t.Fatal(err)
		}
		if _, err := serviceCommand("is-enabled", svc); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case report := <-reports:
		if !report.ForwardSupport || !report.ManualFirewallSupport {
			t.Fatal("worker cannot contact real helper")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not report")
	}
	// Install the real core too, then apply a node and a combined forward.
	if err := copyFile(os.Getenv("MUI_TEST_CORE_BINARY"), CoreBinaryPath, 0755); err != nil {
		t.Fatal(err)
	}
	state := shared.DesiredState{Revision: ReadCurrent().Revision + 1, ProtocolVersion: 1, FirewallMode: "manual",
		Nodes:    []shared.ManagedNode{{Node: shared.Node{ID: strings.Repeat("b", 32), Name: "ss", Protocol: "ss", Listen: "0.0.0.0", Port: 51001, Method: "aes-256-gcm", Enabled: true}, Password: "fixture-password"}},
		Forwards: []shared.ForwardRule{{ID: strings.Repeat("c", 32), Name: "forward", Network: "tcp+udp", Listen: "0.0.0.0", Port: 51002, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}, FirewallPolicy: "manual", Enabled: true}},
	}
	if err := applyDesiredInternal(state, nil); err != nil {
		t.Fatal(err)
	}
	if coreMainPID() == "" {
		t.Fatal("cannot read OpenRC core child PID")
	}
	if _, err := os.ReadFile("/proc/" + coreMainPID() + "/stat"); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{51001, 51002} {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err != nil {
			t.Fatalf("listener %d: %v", port, err)
		}
		_ = conn.Close()
	}
	state.Revision++
	state.Forwards = append(state.Forwards, shared.ForwardRule{ID: strings.Repeat("d", 32), Name: "extra", Network: "tcp+udp", Listen: "0.0.0.0", Port: 51003, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}, FirewallPolicy: "manual", Enabled: true})
	if err := applyDesiredInternal(state, nil); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:51003", time.Second); err != nil {
		t.Fatal(err)
	} else {
		_ = conn.Close()
	}
	if udp, err := net.ListenPacket("udp", "0.0.0.0:51003"); err == nil {
		_ = udp.Close()
		t.Fatal("UDP listener missing")
	}
	marker := filepath.Join(dir, "scheduled")
	if err := scheduleServiceJob("mui-test-cancel", time.Second, "/bin/sh", "-c", `printf bad > "$1"`, "sh", marker); err != nil {
		t.Fatal(err)
	}
	cancelServiceJob("mui-test-cancel")
	if err := scheduleServiceJob("mui-test-run", time.Second, "/bin/sh", "-c", `printf ok > "$1"`, "sh", marker); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if got, _ := os.ReadFile(marker); string(got) != "ok" {
		t.Fatalf("scheduled job failed: %s", got)
	}
	// Read PSS rather than adding RSS, which double-counts the shared binary.
	for _, name := range []string{"mui-agent", "mui-agent-helper", "mui-forward", "mui-sing-box"} {
		raw, _ := os.ReadFile("/run/openrc/options/" + name + "/child_pid")
		pid := strings.TrimSpace(string(raw))
		account := map[string]string{"mui-agent": agentUser, "mui-agent-helper": "root", "mui-forward": forwardUser, "mui-sing-box": coreUser}[name]
		uid, _ := userID(account)
		gid, _ := groupID(account)
		read := exec.Command("cat", "/proc/"+pid+"/smaps_rollup")
		read.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		smaps, err := read.Output()
		if err != nil {
			t.Fatalf("read PSS for %s: %v", name, err)
		}
		for _, line := range strings.Split(string(smaps), "\n") {
			if strings.HasPrefix(line, "Pss:") {
				t.Log(name, pid, line)
			}
		}
	}
	// Ensure the core received its budget without requiring manual exports.
	cmd := exec.Command("/bin/sh", "-c", `tr '\000' '\n' < /proc/"$1"/environ`, "sh", coreMainPID())
	uid, _ := userID(coreUser)
	gid, _ := groupID(coreUser)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if raw, err := cmd.Output(); err != nil || !strings.Contains(string(raw), "GOMEMLIMIT=") {
		t.Fatalf("core memory budget missing: %v", err)
	}
	encoded, _ := json.Marshal(state)
	t.Logf("applied %d bytes using real OpenRC in a %d MiB container", len(encoded), availableMemory()/mebibyte)
	// A signed self-update must leave the worker/helper/forwarder running and
	// receive confirmation after the detached restarts, even with OpenRC deps.
	expected := fmt.Sprintf("%x", sha256.Sum256(data))
	oldForwardPID, _ := os.ReadFile("/run/openrc/options/mui-forward/child_pid")
	if err := upgradeAgent(expected); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		newForwardPID, _ := os.ReadFile("/run/openrc/options/mui-forward/child_pid")
		if raw, _ := os.ReadFile(UpgradeConfirmedPath); string(raw) == expected && len(newForwardPID) > 0 && string(newForwardPID) != string(oldForwardPID) {
			for _, service := range []string{"mui-agent", "mui-agent-helper", "mui-forward"} {
				if _, err := serviceCommand("is-active", service); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("signed OpenRC self-update and report confirmation succeeded")
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("self-update did not confirm")
}

func TestOpenRCOfflineInstallApplyUpgrade(t *testing.T) {
	if os.Getenv("MUI_TEST_OPENRC_OFFLINE") != "1" {
		t.Skip("requires a separate isolated Alpine container")
	}
	if os.Geteuid() != 0 || !openRC() {
		t.Fatal("requires root on OpenRC")
	}
	if err := os.MkdirAll("/run/openrc", 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile("/run/openrc/softlevel", []byte("default\n"), 0644)
	if _, err := command("rc-status", "--all"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	self := filepath.Join(dir, "mui-agent")
	if err := copyFile(os.Getenv("MUI_TEST_AGENT_BINARY"), self, 0755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(self)
	manifest := []byte(fmt.Sprintf("%x  mui-agent\n", sha256.Sum256(data)))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), manifest, 0644)
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest))), 0644)
	config := filepath.Join(dir, "forwards.json")
	rules := []shared.ForwardRule{{ID: "offline-test", Name: "offline", Network: "tcp+udp", Listen: "0.0.0.0", Port: 52001, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}, FirewallPolicy: "manual", Enabled: true}}
	writeConfig := func() {
		raw, _ := json.Marshal(rules)
		if err := os.WriteFile(config, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	run := func(binary string, args ...string) {
		t.Helper()
		if out, err := exec.Command(binary, args...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	t.Cleanup(func() { _, _ = serviceCommand("disable", "--now", "mui-forward") })
	run(self, "offline", "install", "--config", config, "--release-key", base64.StdEncoding.EncodeToString(pub))
	rules[0].Port = 52002
	writeConfig()
	run("/usr/local/bin/mui-agent", "offline", "apply", config)
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:52002", time.Second); err != nil {
		t.Fatal(err)
	} else {
		_ = conn.Close()
	}
	if udp, err := net.ListenPacket("udp", "0.0.0.0:52002"); err == nil {
		_ = udp.Close()
		t.Fatal("offline UDP listener missing")
	}
	run("/usr/local/bin/mui-agent", "offline", "upgrade", "--binary", self)
	if _, err := serviceCommand("is-active", "mui-forward"); err != nil {
		t.Fatal(err)
	}
	if fileExists(ConfigDir+"/config.json") || fileExists("/etc/init.d/mui-agent") || fileExists(CoreBinaryPath) {
		t.Fatal("offline install started online components")
	}
	t.Log("signed offline install, combined-protocol apply and trusted upgrade succeeded on OpenRC")
}
