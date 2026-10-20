package server

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestManagementMigrationPreservesForwardsAndRevokesAgent(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("entry")
	p.newAgent(auth)
	s, _ := p.store.Server(id)
	s.Roles, s.FirewallMode = []string{shared.RoleEntry}, "manual"
	p.store.PutServer(s)
	code, f, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": id, "name": "keep", "network": "tcp+udp", "port": 50123, "targets": []map[string]any{{"host": "198.51.100.10", "port": 443}}, "enabled": true}, nil)
	if code != 201 {
		t.Fatal(code, f)
	}
	p.applyAll(auth)
	// Queue a job that must never survive a change of control plane.
	if err := p.app.queueApplyLocked(id, "forwards.apply"); err != nil {
		t.Fatal(err)
	}
	s, _ = p.store.Server(id)
	s.ManagementMode = "offline"
	if c, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); c != 200 {
		t.Fatal(c, out)
	}
	if c, _, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.11"}, auth); c != 401 {
		t.Fatalf("old Agent authenticated after migration: %d", c)
	}
	s, _ = p.store.Server(id)
	if s.ManagementMigrationFrom != "online" || s.LastSeen != nil || s.AppliedRevision != 0 || s.AgentVersion != "" {
		t.Fatalf("stale runtime: %+v", s)
	}
	forwards, _ := p.store.Forwards(id)
	if len(forwards) != 1 || forwards[0].ID != f["id"] || forwards[0].Status != "pending" {
		t.Fatalf("forward lost or stale: %+v", forwards)
	}
	var queued int
	p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations WHERE server_id=$1 AND claimed_at>=0`, id).Scan(&queued)
	if queued != 0 {
		t.Fatalf("old online jobs survived: %d", queued)
	}
	code, out, _ := p.do("POST", "/api/servers/"+id+"/offline/export", nil, nil)
	if code != 200 || !strings.Contains(out["install"].(map[string]any)["migrationCommand"].(string), "/etc/mui-agent/config.json") {
		t.Fatal(code, out)
	}
	s, _ = p.store.Server(id)
	s.ManagementMode = "online"
	if c, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); c != 200 {
		t.Fatal(c, out)
	}
	s, _ = p.store.Server(id)
	if s.ManagementMigrationFrom != "offline" || s.OfflineExportedAt != nil || s.OfflineExportedRevision != 0 {
		t.Fatal("old offline export remained valid", s)
	}
	code, out, _ = p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 || !strings.Contains(out["offlineInstall"].(map[string]any)["migrationCommand"].(string), "/etc/mui-forward/offline.json") {
		t.Fatal(code, out)
	}
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": out["enrollToken"]}, nil)
	if code != 200 {
		t.Fatal(code, enrolled)
	}
	p.newAgent(map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + enrolled["agentToken"].(string)})
	s, _ = p.store.Server(id)
	if s.ManagementMigrationFrom != "" {
		t.Fatal("migration guide not cleared after successful reconnect")
	}
}

func TestOfflineEntryCanMigrateWithSOCKS5(t *testing.T) {
	p := newTestMui(t)
	hostID, auth := p.enroll("proxy")
	p.newAgent(auth)
	n := shared.Node{ID: ID(), ServerID: hostID, Name: "SOCKS", Protocol: "socks5", Username: "entry", Port: 1080, Direct: true, Enabled: true, Status: "active", FirewallPolicy: "all"}
	p.store.PutNode(n, "fixture-password")
	id := createOfflineServer(p, "offline-entry", "198.51.100.8")
	exportOffline(p, id)
	s, _ := p.store.Server(id)
	s.ManagementMode, s.AgentProxyNodeID = "online", n.ID
	if c, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); c != 200 {
		t.Fatal(c, out)
	}
	code, out, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 || !strings.Contains(out["installCommand"].(string), "proxy.json") {
		t.Fatal("migration cannot bootstrap through SOCKS", code, out)
	}
}

func TestManagementMigrationKeepsRouteAndInvalidatesSubscriptionReadiness(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	id := createOfflineServer(p, "offline-entry", "198.51.100.8")
	code, rt := l.route(map[string]any{"name": "keep-route", "entryServerId": id, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatal(code, rt)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "keep-sub", "format": "surge", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatal(code, sub)
	}
	l.applyAll()
	exportOffline(p, id)
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 {
		t.Fatal(code, body)
	}
	oldForwards := l.forwards(id)
	s, _ := p.store.Server(id)
	s.ManagementMode = "online"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatal(code, out)
	}
	if code, body := p.fetch(path); code != 503 {
		t.Fatal("old export made new online mode appear applied", code, body)
	}
	newForwards := l.forwards(id)
	if len(newForwards) != len(oldForwards) {
		t.Fatal("route forwards lost during migration")
	}
	for i := range oldForwards {
		if oldForwards[i].ID != newForwards[i].ID || newForwards[i].Status != "pending" {
			t.Fatal("forward identity or readiness changed incorrectly")
		}
	}
	_, guide, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	code, out, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": guide["enrollToken"]}, nil)
	if code != 200 {
		t.Fatal(code, out)
	}
	auth := map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + out["agentToken"].(string)}
	p.newAgent(auth)
	p.applyAll(auth)
	if code, body := p.fetch(path); code != 200 {
		t.Fatal("route not restored after online apply", code, body)
	}
	s, _ = p.store.Server(id)
	s.ManagementMode = "offline"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatal(code, out)
	}
	if code, body := p.fetch(path); code != 503 {
		t.Fatal("previous online apply made new offline mode appear exported", code, body)
	}
	exportOffline(p, id)
	if code, body := p.fetch(path); code != 200 {
		t.Fatal("route not restored after new export", code, body)
	}
}

func TestManagementMigrationRefusesRunningTasksAndNodes(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("busy")
	p.newAgent(auth)
	s, _ := p.store.Server(id)
	s.Roles, s.FirewallMode = []string{shared.RoleTransit}, "manual"
	p.store.PutServer(s)
	op := shared.Operation{ID: ID(), ServerID: id, Kind: "ufw.init", Status: "running", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_operations SET claimed_at=$1 WHERE id=$2`, time.Now().UnixMilli(), op.ID); err != nil {
		t.Fatal(err)
	}
	s.ManagementMode = "offline"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 409 {
		t.Fatal("running task not protected", code, out)
	}
	stored, _ := p.store.Server(id)
	if shared.OfflineManaged(stored) {
		t.Fatal("failed migration was partially saved")
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{}, auth); code != 200 {
		t.Fatal("failed migration revoked credentials")
	}
	p.store.FinishJob(op.ID, "success", "")
	n := shared.Node{ID: ID(), ServerID: id, Name: "keep", Protocol: "ss", Port: 50123}
	p.store.PutNode(n, "fixture-password")
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 409 {
		t.Fatal("server containing nodes migrated offline", code, out)
	}
}

func TestManagementPreparationCommands(t *testing.T) {
	for _, tc := range []struct {
		name, target, init string
		conflict           bool
	}{
		{"to online systemd", "online", "systemd", false},
		{"to offline systemd", "offline", "systemd", false},
		{"to online OpenRC", "online", "openrc", false},
		{"to offline OpenRC", "offline", "openrc", false},
		{"refuse changed pinned key", "online", "systemd", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, tools := t.TempDir(), t.TempDir()
			for _, dir := range []string{"etc/mui-agent", "etc/mui-forward", "etc/init.d", "etc/runlevels/default"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.init == "systemd" {
				os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0700)
			}
			for _, name := range []string{"mktemp", "mkdir", "mv", "cp", "chmod", "tr"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(tools, name)); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(root, "services.log")
			write := func(path, value string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(value), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(tools, "id"), "#!/bin/sh\nprintf '0\\n'\n", 0755)
			for _, name := range []string{"systemctl", "rc-service", "rc-update"} {
				if tc.init == "openrc" && name == "systemctl" {
					continue
				}
				write(filepath.Join(tools, name), "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "+shellQuote(log)+"\n", 0755)
			}
			for _, unit := range []string{"mui-agent", "mui-agent-helper", "mui-forward", "mui-sing-box"} {
				write(filepath.Join(root, "etc/init.d", unit), "#!/bin/sh\n", 0755)
				write(filepath.Join(root, "etc/runlevels/default", unit), "", 0600)
			}
			marker := filepath.Join(root, "etc/mui-forward/offline.json")
			if tc.target == "offline" {
				marker = filepath.Join(root, "etc/mui-agent/config.json")
			}
			write(marker, "original-config", 0600)
			write(filepath.Join(root, "etc/mui-forward/release.pub"), "pinned-key\n", 0644)
			if tc.conflict {
				write(filepath.Join(root, "etc/mui-agent/release.pub"), "wrong-key\n", 0644)
			}
			command := managementMigrationCommand(shared.Server{ManagementMode: tc.target, ManagementMigrationFrom: "previous"})
			command = strings.NewReplacer("/etc/", root+"/etc/", "/run/systemd/system", root+"/run/systemd/system").Replace(command)
			for _, shell := range []string{"sh", "bash"} {
				check := exec.Command(shell, "-n")
				check.Stdin = strings.NewReader(command)
				if out, err := check.CombinedOutput(); err != nil {
					t.Fatalf("syntax: %v %s", err, out)
				}
			}
			run := func() ([]byte, error) {
				c := exec.Command("sh")
				c.Stdin = strings.NewReader(command)
				c.Env = []string{"PATH=" + tools}
				return c.CombinedOutput()
			}
			out, err := run()
			if tc.conflict {
				if err == nil {
					t.Fatal("changed pinned key accepted")
				}
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("marker removed after failed check")
				}
				if _, err := os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("services touched before key check")
				}
				return
			}
			if err != nil {
				t.Fatalf("prepare: %v %s", err, out)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("old marker still blocks installation")
			}
			backups, _ := filepath.Glob(filepath.Join(root, "etc/mui-management-backup.*", filepath.Base(marker)))
			if len(backups) != 1 {
				t.Fatal("old config was not backed up")
			}
			raw, _ := os.ReadFile(backups[0])
			if string(raw) != "original-config" {
				t.Fatal("backup changed")
			}
			if tc.target == "online" {
				raw, _ := os.ReadFile(filepath.Join(root, "etc/mui-agent/release.pub"))
				if string(raw) != "pinned-key\n" {
					t.Fatal("pinned key lost")
				}
			}
			before, _ := os.ReadFile(log)
			if out, err = run(); err != nil {
				t.Fatal(err, string(out))
			}
			after, _ := os.ReadFile(log)
			if string(before) != string(after) {
				t.Fatal("repeated preparation stopped newly installed services")
			}
		})
	}
}

// Ensure extending installation guides keeps the migration instructions in
// API JSON; they must remain available after leaving/reopening the modal.
func TestManagementGuideJSON(t *testing.T) {
	a := &App{PublicURL: "https://mui.example.test"}
	guide := a.offlineInstall("entry", "token", shared.Server{Roles: []string{shared.RoleEntry}, ManagementMode: "online", ManagementMigrationFrom: "offline"})
	raw, _ := json.Marshal(guide)
	if !strings.Contains(string(raw), "migrationCommand") {
		t.Fatal(string(raw))
	}
}

// An agent that died mid-job leaves a running claim behind. Once its claim
// window has passed it must not block the switch away from that agent.
func TestManagementMigrationSupersedesStaleClaim(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("stale")
	p.newAgent(auth)
	s, _ := p.store.Server(id)
	s.Roles, s.FirewallMode = []string{shared.RoleTransit}, "manual"
	p.store.PutServer(s)
	op := shared.Operation{ID: ID(), ServerID: id, Kind: "forwards.apply", Status: "running", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_operations SET claimed_at=$1 WHERE id=$2`, time.Now().Add(-10*time.Minute).UnixMilli(), op.ID); err != nil {
		t.Fatal(err)
	}
	s.ManagementMode = "offline"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatal("stale claim blocked migration", code, out)
	}
	stored, err := p.store.Operation(op.ID)
	if err != nil || stored.Status != "superseded" {
		t.Fatal("stale job not superseded", stored, err)
	}
}
