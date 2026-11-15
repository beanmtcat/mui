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

func TestOtherRoleServerBehavior(t *testing.T) {
	l := newRouteLab(t)
	p := l.p

	// 1. Online "other" server installs Agent only ('relay') without sing-box.
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":    "other-vps",
		"roles":   []string{shared.RoleOther},
		"country": "JP",
		"ipv4":    "198.51.100.50",
	}, nil)
	if code != 201 {
		t.Fatalf("create other server: %d %v", code, created)
	}
	if !strings.Contains(created["installCommand"].(string), "'relay'") {
		t.Fatalf("other server installer unexpectedly includes core: %s", created["installCommand"])
	}
	otherID := created["server"].(map[string]any)["id"].(string)
	otherServer, err := p.store.Server(otherID)
	if err != nil {
		t.Fatal(err)
	}
	guide := p.app.offlineInstall(otherID, "fixture-token", otherServer)
	for _, download := range guide.Downloads {
		for _, file := range download.Files {
			if file.Name == "sing-box" {
				t.Fatal("other server unexpectedly downloads sing-box")
			}
		}
	}

	// Enroll the "other" server for route and forward checks.
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": otherID,
		"token":    created["enrollToken"].(string),
	}, nil)
	if code != 200 {
		t.Fatalf("enroll other server: %d %v", code, enrolled)
	}
	p.newAgent(map[string]string{"X-Server-ID": otherID, "Authorization": "Bearer " + enrolled["agentToken"].(string)})

	// 2. "other" server cannot host proxy nodes.
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": otherID,
		"name":     "forbidden-other-node",
		"protocol": "ss",
		"port":     51010,
	}, nil); code != 409 {
		t.Fatalf("other server accepted node: %d %v", code, out)
	}

	// 3. "other" server cannot act as route entry or middle hop.
	if code, out := l.route(map[string]any{
		"name":          "other-as-entry",
		"entryServerId": otherID,
		"nodeId":        l.nodeID,
		"enabled":       true,
		"hops":          []map[string]any{},
	}); code != 400 {
		t.Fatalf("other server accepted as route entry: %d %v", code, out)
	}
	if code, out := l.route(map[string]any{
		"name":          "other-as-hop",
		"entryServerId": l.entry,
		"nodeId":        l.nodeID,
		"enabled":       true,
		"hops":          []map[string]any{{"serverIds": []string{otherID}}},
	}); code != 400 {
		t.Fatalf("other server accepted as route hop: %d %v", code, out)
	}

	// 4. Standalone port forward succeeds, offline mode succeeds, external mode rejects.
	if code, fwd, _ := p.do("POST", "/api/forwards", map[string]any{
		"serverId":       otherID,
		"name":           "other-forward",
		"network":        "tcp",
		"port":           51020,
		"targets":        []map[string]any{{"host": "198.51.100.60", "port": 443}},
		"firewallPolicy": "all",
		"enabled":        true,
	}, nil); code != 201 {
		t.Fatalf("standalone forward on other server failed: %d %v", code, fwd)
	}

	if code, offOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "offline-other",
		"roles":          []string{shared.RoleOther},
		"managementMode": "offline",
		"firewallMode":   "manual",
		"country":        "SG",
		"ipv4":           "198.51.100.51",
	}, nil); code != 201 {
		t.Fatalf("offline other server rejected: %d %v", code, offOut)
	}

	if code, extOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "external-other",
		"roles":          []string{shared.RoleOther},
		"managementMode": "external",
		"firewallMode":   "manual",
		"country":        "SG",
		"ipv4":           "198.51.100.52",
	}, nil); code != 400 {
		t.Fatalf("external other server unexpectedly accepted: %d %v", code, extOut)
	}
}
