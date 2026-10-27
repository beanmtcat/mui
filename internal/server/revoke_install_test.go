package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestRoleChangeInvalidatesInstallerCoreSelection(t *testing.T) {
	p := newTestMui(t)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "role-change", "country": "SG", "ipv4": "203.0.113.30", "roles": []string{shared.RoleExit},
	}, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)
	if !strings.Contains(created["offlineInstall"].(map[string]any)["command"].(string), "./sing-box") {
		t.Fatal("exit install omitted sing-box")
	}
	server, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	server.Roles = []string{shared.RoleEntry}
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, server, nil); code != 200 {
		t.Fatalf("change role: %d %v", code, out)
	}
	if code, _, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": created["enrollToken"]}, nil); code != 401 {
		t.Fatalf("old exit installer remained valid: %d", code)
	}
	code, renewed, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 {
		t.Fatalf("renew guide: %d %v", code, renewed)
	}
	if strings.Contains(renewed["offlineInstall"].(map[string]any)["command"].(string), "./sing-box") || !strings.Contains(renewed["installCommand"].(string), "'relay'") {
		t.Fatalf("entry install still includes core: %v", renewed)
	}
}

func TestRoleChangeQueuesApplyToStopUnusedCore(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("role-core-stop")
	server, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	server.Roles = []string{shared.RoleEntry}
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, server, nil); code != 200 {
		t.Fatalf("change role: %d %v", code, out)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("role change did not queue an Agent apply: %d %v", code, job)
	}
	state := job["state"].(map[string]any)
	if nodes := state["nodes"].([]any); len(nodes) != 0 {
		t.Fatalf("entry-only server still has node configuration: %v", nodes)
	}
}

func TestAgentUpgradeQueuesIdleCoreCleanupForOldRoleChange(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("legacy-idle-core")
	server, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a role edit saved by the older panel, which did not queue an
	// apply. The core binary is still installed and its service may be live.
	server.Roles = []string{shared.RoleEntry}
	server.AgentVersion = "0.6.21"
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.22", "coreBuild": server.CoreBuild}, agent); code != 200 {
		t.Fatalf("new Agent report: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("upgrade did not queue idle core cleanup: %d %v", code, job)
	}
}

func TestRevokedAgentStopsAuthenticatingAndCanReenroll(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("revoke")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.20"}, auth); code != 200 {
		t.Fatalf("first report: %d %v", code, out)
	}
	if err := p.app.queueApplyLocked(id, "nodes.apply"); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/revoke", nil, nil); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	server, err := p.store.Server(id)
	if err != nil || serverStatus(server) != "revoked" || server.LastSeen != nil {
		t.Fatalf("revoked status: %+v %v", server, err)
	}
	var raw string
	if err := p.store.DB.QueryRow(`SELECT data FROM mui_operations WHERE server_id=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var op shared.Operation
	if err := json.Unmarshal([]byte(raw), &op); err != nil || op.Status != "superseded" {
		t.Fatalf("revoked job remains runnable: %+v %v", op, err)
	}
	for _, req := range []struct{ method, path string }{{"POST", "/agent/report"}, {"GET", "/agent/job"}, {"GET", "/agent/komari"}} {
		if code, _, _ := p.do(req.method, req.path, map[string]any{}, auth); code != 410 {
			t.Fatalf("revoked agent got %d on %s", code, req.path)
		}
	}
	code, guide, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 {
		t.Fatalf("renew enrollment: %d %v", code, guide)
	}
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": guide["enrollToken"]}, nil)
	if code != 200 {
		t.Fatalf("reenroll: %d %v", code, enrolled)
	}
	server, err = p.store.Server(id)
	if err != nil || serverStatus(server) != "pending" {
		t.Fatalf("reenrolled status: %+v %v", server, err)
	}
	newAuth := map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + enrolled["agentToken"].(string)}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.20"}, newAuth); code != 200 {
		t.Fatalf("new agent report: %d %v", code, out)
	}
}

func TestUninstallScriptIsServed(t *testing.T) {
	p := newTestMui(t)
	code, script := p.fetch("/download/uninstall.sh")
	if code != 200 || !strings.Contains(script, "systemctl disable --now") || !strings.Contains(script, "rc-service") || !strings.Contains(script, "rm -f /usr/local/bin/mui-agent") {
		t.Fatalf("uninstall script: %d %s", code, script)
	}
}
