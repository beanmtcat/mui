package server

import (
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestTransitNodeSupportsRouteSubscriptionAndRoleChanges(t *testing.T) {
	l := newRouteLab(t)
	// Existing node hosts can retain their nodes when becoming transit-only.
	server, _ := l.p.store.Server(l.exit)
	server.Roles = []string{shared.RoleTransit}
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.exit, server, nil); code != 200 {
		t.Fatal("exit to transit", code, out)
	}
	code, rt := l.route(map[string]any{"name": "transit-endpoint", "entryServerId": l.entry, "nodeId": l.nodeID, "hops": []map[string]any{{"serverIds": []string{l.t1}}}, "enabled": true})
	if code != 201 {
		t.Fatal("route ending on transit", code, rt)
	}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "transit-sub", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatal("subscription", code, sub)
	}
	l.applyAll()
	path := strings.TrimPrefix(sub["url"].(string), l.p.app.PublicURL)
	if code, body := l.p.fetch(path); code != 200 || !strings.Contains(body, "entry.example.com") {
		t.Fatal("transit subscription", code, body)
	}
	// Keep at least one role that supports nodes, even if the node is disabled.
	server, _ = l.p.store.Server(l.exit)
	server.Roles = []string{shared.RoleLine}
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.exit, server, nil); code != 409 {
		t.Fatal("node lost capable role", code, out)
	}
	server.Roles = []string{shared.RoleTransit}
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.exit, server, nil); code != 200 {
		t.Fatal("transit role edit", code, out)
	}
}

func TestOfflineTransitCannotHostNodes(t *testing.T) {
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "offline-transit", "roles": []string{shared.RoleTransit}, "managementMode": "offline", "firewallMode": "manual", "country": "CN", "ipv4": "198.51.100.9"}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "invalid-offline-node", "protocol": "ss", "port": 51000}, nil); code != 409 {
		t.Fatal("offline transit accepted node", code, out)
	}
}

func TestTransitRoleDoesNotInstallCoreByDefault(t *testing.T) {
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "transit", "roles": []string{shared.RoleTransit}, "country": "SG", "ipv4": "198.51.100.3"}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	server, _ := p.store.Server(id)
	guide := p.app.offlineInstall(id, "fixture-token", server)
	for _, download := range guide.Downloads {
		for _, file := range download.Files {
			if file.Name == "sing-box" {
				t.Fatal("pure transit unexpectedly downloads core")
			}
		}
	}
	if !strings.Contains(out["installCommand"].(string), "'relay'") {
		t.Fatal("pure transit installer changed", out["installCommand"])
	}
}

func TestServerRolesCanBeSavedBeforeCoreInstallation(t *testing.T) {
	p := newTestMui(t)
	id, _ := p.enrollAs("relay-without-core", []string{shared.RoleTransit}, map[string]any{"ipv4": "198.51.100.3"})
	s, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if s.AgentVersion == "" || s.CoreBuild != "" {
		t.Fatal("fixture must be enrolled without a core")
	}
	s.Roles = []string{shared.RoleTransit, shared.RoleExit}
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatal("role save depends on core", code, out)
	}
	saved, err := p.store.Server(id)
	if err != nil || !shared.HasRole(saved, shared.RoleTransit) || !shared.HasRole(saved, shared.RoleExit) || saved.CoreBuild != "" {
		t.Fatal("roles not saved independently of installation", saved, err)
	}
	// Saving the intended role must not bypass the real deployment requirement.
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "ss", "protocol": "ss", "port": 51001}, nil); code != 409 {
		t.Fatal("node accepted before core installation", code, out)
	}
	// Other validations remain effective and do not overwrite stored metadata.
	s.Country = "X"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 400 {
		t.Fatal("invalid server accepted", code, out)
	}
	saved, _ = p.store.Server(id)
	if saved.Country == "X" {
		t.Fatal("failed save overwrote server")
	}
}

func TestTransitWithCoreReinstallsCore(t *testing.T) {
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "transit", "roles": []string{shared.RoleTransit}, "country": "SG", "ipv4": "198.51.100.4"}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	server, _ := p.store.Server(id)
	server.CoreBuild = strings.Repeat("a", 64)
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.app.installCommandAt("https://mui.example.test", id, "token", server), "'node'") {
		t.Fatal("repair install of a transit with sing-box would drop the core")
	}
	guide := p.app.offlineInstall(id, "fixture-token", server)
	if !strings.Contains(guide.Command, "./sing-box") {
		t.Fatal("manual repair install of a transit with sing-box would drop the core")
	}
}
