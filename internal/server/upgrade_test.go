package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestAgentSelfUpgradeLifecycle(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", binDir)
	archDir := filepath.Join(binDir, "amd64")
	if err := os.Mkdir(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := []byte("new-agent-binary")
	hash := sha256.Sum256(binary)
	want := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(archDir, "mui-agent"), binary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "SHA256SUMS"), []byte(want+"  mui-agent\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newTestMui(t)
	id, agent := p.enroll("upgrade-test")
	path := "/api/servers/" + id + "/agent/upgrade"
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("old Agent should not receive an upgrade: %d", code)
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.3.0", "agentBuild": "old-build", "agentSelfUpdate": true, "arch": "amd64"}, agent); code != 200 {
		t.Fatalf("capability report: %d", code)
	}
	if code, out, _ := p.do("POST", path, nil, nil); code != 202 || out["targetBuild"] != want {
		t.Fatalf("queue upgrade: %d %v", code, out)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("duplicate upgrade was accepted: %d", code)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "agent.upgrade" || job["state"].(map[string]any)["upgradeSha256"] != want {
		t.Fatalf("upgrade job: %d %v", code, job)
	}
	jobID := job["id"].(string)
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"jobId": jobID, "jobStatus": "success"}, agent); code != 200 {
		t.Fatalf("stage report: %d", code)
	}
	op, err := p.store.Operation(jobID)
	if err != nil || op.Status != "activating" {
		t.Fatalf("upgrade completed before restart: %+v %v", op, err)
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.3.0", "agentBuild": want, "agentSelfUpdate": true, "arch": "amd64"}, agent); code != 200 {
		t.Fatalf("new build report: %d", code)
	}
	op, err = p.store.Operation(jobID)
	if err != nil || op.Status != "success" {
		t.Fatalf("new build not confirmed: %+v %v", op, err)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("up-to-date Agent was queued: %d", code)
	}
	newBinary := []byte("a-later-agent-build")
	newHash := sha256.Sum256(newBinary)
	if err := os.WriteFile(filepath.Join(archDir, "mui-agent"), newBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "SHA256SUMS"), []byte(hex.EncodeToString(newHash[:])+"  mui-agent\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 202 {
		t.Fatalf("later release was not queued: %d", code)
	}
	code, failedJob, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 {
		t.Fatalf("later release job: %d", code)
	}
	failedID := failedJob["id"].(string)
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"jobId": failedID, "jobStatus": "failed", "jobError": "download failed"}, agent); code != 200 {
		t.Fatalf("failed upgrade report: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/operations/"+failedID+"/retry", nil, nil); code != 202 {
		t.Fatalf("failed Agent upgrade could not be retried: %d", code)
	}
	code, retryJob, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || retryJob["kind"] != "agent.upgrade" || retryJob["id"] == failedID {
		t.Fatalf("retry did not queue a new upgrade: %d %v", code, retryJob)
	}
}

func TestRelayInstallsCoreOnlyWhenRequested(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", binDir)
	archDir := filepath.Join(binDir, "amd64")
	if err := os.Mkdir(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := []byte("core-install-test")
	hash := sha256.Sum256(binary)
	want := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(archDir, "sing-box"), binary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "SHA256SUMS"), []byte(want+"  sing-box\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newTestMui(t)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{"name": "relay", "roles": []string{"transit"}, "country": "SG", "ipv4": "203.0.113.11"}, nil)
	if code != 201 || !strings.Contains(created["installCommand"].(string), "relay") {
		t.Fatalf("relay creation: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{"serverId": id, "token": created["enrollToken"].(string)}, nil)
	if code != 200 {
		t.Fatalf("enroll: %d %v", code, enrolled)
	}
	agent := map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + enrolled["agentToken"].(string)}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0", "coreSelfUpdate": true, "forwardSupport": true, "arch": "amd64"}, agent); code != 200 {
		t.Fatalf("Agent report: %d %v", code, out)
	}
	if code, _, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": id, "name": "ss", "protocol": "ss", "port": 51000}, nil); code != 409 {
		t.Fatalf("relay accepted node: %d", code)
	}
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/core/upgrade", nil, nil); code != 202 || out["targetBuild"] != want {
		t.Fatalf("queue core install: %d %v", code, out)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "core.upgrade" {
		t.Fatalf("core install job: %d %v", code, job)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success", "coreBuild": want}, agent); code != 200 {
		t.Fatalf("core install report: %d %v", code, out)
	}
	server, err := p.store.Server(id)
	if err != nil || !shared.HasRole(server, shared.RoleTransit) || shared.HasRole(server, shared.RoleExit) || server.CoreBuild != want {
		t.Fatalf("transit role changed or core missing after install: %+v %v", server, err)
	}
	p.newAgent(agent)
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "transit-ss", "protocol": "ss", "port": 51000, "direct": true}, nil); code != 201 {
		t.Fatalf("installed transit rejected node: %d %v", code, out)
	}
	p.applyAll(agent)
}

func TestAgentUpgradeRejectsBadReleaseAndExpiresUnconfirmed(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", binDir)
	archDir := filepath.Join(binDir, "amd64")
	if err := os.Mkdir(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "mui-agent"), []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  mui-agent\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newTestMui(t)
	id, agent := p.enroll("upgrade-checksum")
	_, _, _ = p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.3.0", "agentBuild": "old", "agentSelfUpdate": true, "arch": "amd64"}, agent)
	if code, _, _ := p.do("POST", "/api/servers/"+id+"/agent/upgrade", nil, nil); code != 409 {
		t.Fatalf("bad release accepted: %d", code)
	}
	if err := p.store.PutOperation(shared.Operation{ID: "expired", ServerID: id, Kind: "agent.upgrade", Status: "activating", TargetBuild: "new", UpdatedAt: time.Now().Add(-6 * time.Minute)}, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_operations SET claimed_at=-1 WHERE id='expired'`); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("GET", "/api/operations", nil, nil); code != 200 {
		t.Fatalf("operations: %d", code)
	}
	op, err := p.store.Operation("expired")
	if err != nil || op.Status != "failed" {
		t.Fatalf("unconfirmed upgrade not expired: %+v %v", op, err)
	}
}

func TestCoreUpgradeLifecycle(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", binDir)
	archDir := filepath.Join(binDir, "amd64")
	if err := os.Mkdir(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := []byte("new-sing-box")
	hash := sha256.Sum256(binary)
	want := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(archDir, "sing-box"), binary, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(archDir, "SHA256SUMS")
	if err := os.WriteFile(manifest, []byte(strings.Repeat("0", 64)+"  sing-box\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p := newTestMui(t)
	id, agent := p.enroll("core-upgrade")
	path := "/api/servers/" + id + "/core/upgrade"
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("old Agent received core upgrade: %d", code)
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.4.0", "agentSelfUpdate": true, "coreSelfUpdate": true, "arch": "amd64", "coreBuild": "old-core"}, agent); code != 200 {
		t.Fatalf("capability report: %d", code)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("bad sing-box checksum accepted: %d", code)
	}
	if err := os.WriteFile(manifest, []byte(want+"  sing-box\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("GET", "/api/core/release", nil, nil); code != 200 || out["amd64"] != want {
		t.Fatalf("core release: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", path, nil, nil); code != 202 || out["targetBuild"] != want {
		t.Fatalf("queue core upgrade: %d %v", code, out)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("duplicate core upgrade accepted: %d", code)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "core.upgrade" || job["state"].(map[string]any)["coreUpgradeSha256"] != want {
		t.Fatalf("core job: %d %v", code, job)
	}
	jobID := job["id"].(string)
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"jobId": jobID, "jobStatus": "success", "coreBuild": "wrong"}, agent); code != 200 {
		t.Fatalf("wrong build report: %d", code)
	}
	op, err := p.store.Operation(jobID)
	if err != nil || op.Status != "failed" {
		t.Fatalf("wrong core build marked successful: %+v %v", op, err)
	}
	if code, _, _ := p.do("POST", "/api/operations/"+jobID+"/retry", nil, nil); code != 202 {
		t.Fatalf("retry core upgrade: %d", code)
	}
	code, retry, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || retry["kind"] != "core.upgrade" || retry["id"] == jobID {
		t.Fatalf("retry core job: %d %v", code, retry)
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"jobId": retry["id"], "jobStatus": "success", "coreBuild": want, "coreVersion": "sing-box version 1.14.2"}, agent); code != 200 {
		t.Fatalf("successful core report: %d", code)
	}
	op, err = p.store.Operation(retry["id"].(string))
	if err != nil || op.Status != "success" {
		t.Fatalf("core upgrade not successful: %+v %v", op, err)
	}
	if code, _, _ := p.do("POST", path, nil, nil); code != 409 {
		t.Fatalf("same core build upgraded again: %d", code)
	}
}

func TestUnsignedReleaseIsRefusedWhenAReleaseKeyIsConfigured(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUI_RELEASE_PUBLIC_KEY", base64.StdEncoding.EncodeToString(public))
	bin := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", bin)
	dir := filepath.Join(bin, "amd64")
	if err = os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := []byte("agent build")
	sum := sha256.Sum256(binary)
	manifest := []byte(hex.EncodeToString(sum[:]) + "  mui-agent\n")
	_ = os.WriteFile(filepath.Join(dir, "mui-agent"), binary, 0755)
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), manifest, 0644)
	p := newTestMui(t)
	if _, err = p.app.releaseHash("amd64"); err == nil {
		t.Fatal("an unsigned release was offered although agents pin a release key")
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest))
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(signature+"\n"), 0644)
	if hash, err := p.app.releaseHash("amd64"); err != nil || hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("signed release: %q %v", hash, err)
	}
	// The install command hands the public key to the agent for pinning.
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "s", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.10"}, nil)
	if code != 201 || !strings.Contains(out["installCommand"].(string), base64.StdEncoding.EncodeToString(public)) {
		t.Fatalf("install command without the release key: %d %v", code, out)
	}
}
