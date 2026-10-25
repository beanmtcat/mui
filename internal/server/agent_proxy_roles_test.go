package server

import (
	"strings"
	"testing"

	"mui/internal/shared"
)

func proxyRoleFixture(t *testing.T) (*testMui, string, map[string]string, shared.Node) {
	t.Helper()
	p := newTestMui(t)
	id, auth := p.enroll("proxy-host")
	p.newAgent(auth)
	host, _ := p.store.Server(id)
	host.AgentProxySupport = true
	if err := p.store.PutServer(host); err != nil {
		t.Fatal(err)
	}
	code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "private SOCKS", "protocol": "socks5", "username": "agent", "password": "fixture-password", "port": 1080, "direct": false}, nil)
	if code != 201 {
		t.Fatalf("proxy node: %d %v", code, out)
	}
	p.applyAll(auth)
	n, err := p.store.Node(out["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return p, id, auth, n
}

func TestAgentProxyAllOnlineServerRoles(t *testing.T) {
	for _, role := range []string{shared.RoleEntry, shared.RoleLine, shared.RoleTransit, shared.RoleExit} {
		t.Run(role, func(t *testing.T) {
			p, hostID, hostAuth, node := proxyRoleFixture(t)
			input := map[string]any{"name": role, "roles": []string{role}, "country": "SG", "ipv4": "198.51.100.31", "firewallMode": "manual", "agentProxyNodeId": node.ID}
			code, created, _ := p.do("POST", "/api/servers", input, nil)
			if code != 201 {
				t.Fatalf("new %s proxy: %d %v", role, code, created)
			}
			clientID := created["server"].(map[string]any)["id"].(string)
			client, _ := p.store.Server(clientID)
			if len(client.Roles) != 1 || client.Roles[0] != role || client.AgentProxyNodeID != node.ID {
				t.Fatalf("roles/proxy changed: %+v", client)
			}
			for _, command := range []string{created["installCommand"].(string), created["offlineInstall"].(map[string]any)["command"].(string)} {
				if !strings.Contains(command, "proxy.json") {
					t.Fatal("proxy missing from install guide")
				}
			}
			state, err := p.app.desired(hostID)
			if err != nil || len(state.Nodes) != 1 || state.Nodes[0].Node.FirewallSources != "198.51.100.31/32" {
				t.Fatalf("missing %s source whitelist: %+v %v", role, state, err)
			}
			enrollment := map[string]any{"serverId": clientID, "token": created["enrollToken"]}
			if code, out, _ := p.do("POST", "/agent/enroll", enrollment, nil); code != 409 {
				t.Fatalf("enrolled before source apply: %d %v", code, out)
			}
			p.applyAll(hostAuth)
			code, enrolled, _ := p.do("POST", "/agent/enroll", enrollment, nil)
			if code != 200 {
				t.Fatalf("enroll %s: %d %v", role, code, enrolled)
			}
			auth := map[string]string{"X-Server-ID": clientID, "Authorization": "Bearer " + enrolled["agentToken"].(string)}
			if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.12", "agentProxySupport": true, "manualFirewallSupport": true, "nodeFirewallPolicies": true}, auth); code != 200 {
				t.Fatal(code, out)
			}
			p.applyAll(auth)
			// Editing roles must preserve the selected proxy, including removal of
			// the entry role. Server roles only describe its data-plane function.
			client, _ = p.store.Server(clientID)
			client.Roles = []string{shared.RoleTransit}
			if role == shared.RoleTransit {
				client.Roles = []string{shared.RoleExit}
			}
			if code, out, _ := p.do("PATCH", "/api/servers/"+clientID, client, nil); code != 200 || out["agentProxyNodeId"] != node.ID {
				t.Fatalf("role edit lost proxy: %d %v", code, out)
			}
			// Existing Agents of every role can also switch from direct to SOCKS.
			existingID, existingAuth := p.enroll("existing-" + role)
			p.newAgent(existingAuth)
			existing, _ := p.store.Server(existingID)
			existing.Roles = []string{role}
			existing.AgentProxySupport = true
			existing.IPv4 = "198.51.100.32"
			if err := p.store.PutServer(existing); err != nil {
				t.Fatal(err)
			}
			existing.AgentProxyNodeID = node.ID
			if code, out, _ := p.do("PATCH", "/api/servers/"+existingID, existing, nil); code != 200 {
				t.Fatalf("existing %s proxy: %d %v", role, code, out)
			}
			if code, job, _ := p.do("GET", "/agent/job", nil, existingAuth); code != 204 {
				t.Fatalf("switch before whitelist: %d %v", code, job)
			}
			p.applyAll(hostAuth)
			code, job, _ := p.do("GET", "/agent/job", nil, existingAuth)
			if code != 200 {
				t.Fatalf("switch %s not delivered: %d %v", role, code, job)
			}
			proxy := job["state"].(map[string]any)["agentProxy"].(map[string]any)
			if proxy["username"] != "agent" || proxy["port"] != float64(1080) {
				t.Fatal("incorrect proxy in signed job")
			}
		})
	}
}

func TestAgentProxyRoleRemovalRetainsSafetyChecks(t *testing.T) {
	p, hostID, _, node := proxyRoleFixture(t)
	host, _ := p.store.Server(hostID)
	host.AgentProxyNodeID = node.ID
	if code, out, _ := p.do("PATCH", "/api/servers/"+hostID, host, nil); code != 409 || !strings.Contains(out["error"].(string), "其他服务器") {
		t.Fatalf("self proxy accepted: %d %v", code, out)
	}
	input := map[string]any{"name": "offline", "roles": []string{shared.RoleTransit}, "country": "SG", "ipv4": "198.51.100.41", "firewallMode": "manual", "managementMode": "offline", "agentProxyNodeId": node.ID}
	if code, out, _ := p.do("POST", "/api/servers", input, nil); code != 409 || !strings.Contains(out["error"].(string), "离线") {
		t.Fatalf("offline proxy accepted: %d %v", code, out)
	}
	// Both ends can now be non-entry proxy hosts. Their control-plane chain
	// must remain acyclic even when neither server carries the entry role.
	peerID, peerAuth := p.enroll("peer-proxy-host")
	p.newAgent(peerAuth)
	peer, _ := p.store.Server(peerID)
	peer.Roles = []string{shared.RoleTransit}
	peer.AgentProxySupport = true
	peer.IPv4 = "198.51.100.42"
	if err := p.store.PutServer(peer); err != nil {
		t.Fatal(err)
	}
	code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": peerID, "name": "peer SOCKS", "protocol": "socks5", "username": "agent", "password": "fixture-password", "port": 1080, "direct": false}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	p.applyAll(peerAuth)
	host.AgentProxyNodeID = out["id"].(string)
	if code, out, _ := p.do("PATCH", "/api/servers/"+hostID, host, nil); code != 200 {
		t.Fatal(code, out)
	}
	peer, _ = p.store.Server(peerID)
	peer.AgentProxyNodeID = node.ID
	if code, out, _ := p.do("PATCH", "/api/servers/"+peerID, peer, nil); code != 409 || !strings.Contains(out["error"].(string), "循环") {
		t.Fatalf("proxy cycle accepted: %d %v", code, out)
	}
}

func TestUnchangedAgentProxyDoesNotBlockOtherApplies(t *testing.T) {
	p, _, _, node := proxyRoleFixture(t)
	id, auth := p.enroll("entry-with-existing-proxy")
	p.newAgent(auth)
	p.applyAll(auth)
	server, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	server.Roles = []string{shared.RoleEntry}
	server.IPv4 = "198.51.100.88"
	server.AgentProxyNodeID = node.ID
	server.AgentProxySupport = true
	server.AgentProxySwitchPending = false
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	ready, err := p.app.agentProxyAccessLive(server)
	if err != nil || ready {
		t.Fatalf("fixture unexpectedly has proxy source access: %v, %v", ready, err)
	}
	if err := p.app.queueApply(id, "nodes.apply"); err != nil {
		t.Fatal(err)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("unrelated apply was blocked by unchanged proxy: %d %v", code, job)
	}
}
