package server

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"mui/internal/agent"
	"mui/internal/shared"
)

func TestSOCKS5NodeFirewallProxyAndSubscription(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("socks-host")
	input := map[string]any{"serverId": id, "name": "SOCKS", "protocol": "socks5", "username": "entry-user", "password": "proxy-password", "port": 1080, "listen": "0.0.0.0", "direct": true}
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 409 {
		t.Fatalf("inactive firewall accepted: %d %v", code, out)
	}
	p.newAgent(auth)
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.10", "agentProxySupport": true, "nodeFirewallPolicies": true, "multiUserStats": true}, auth); code != 200 {
		t.Fatal(code, out)
	}
	host, _ := p.store.Server(id)
	host.InternalAddress = "10.10.0.2"
	p.store.PutServer(host)
	code, out, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 {
		t.Fatalf("SOCKS low port rejected: %d %v", code, out)
	}
	nodeID := out["id"].(string)
	p.applyAll(auth)
	n, _ := p.store.Node(nodeID)
	state, err := p.app.desired(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	raw, err := shared.SingBoxConfig(state.Nodes, "/certs")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	json.Unmarshal(raw, &config)
	if config.Inbounds[0]["type"] != "socks" {
		t.Fatal(string(raw))
	}
	if users, ok := config.Inbounds[0]["users"].([]any); !ok || len(users) != 1 {
		t.Fatal("SOCKS authentication empty")
	}
	// A server hosting SOCKS must retain managed UFW.
	host, _ = p.store.Server(id)
	host.FirewallMode = "manual"
	if c, o, _ := p.do("PATCH", "/api/servers/"+id, host, nil); c != 409 {
		t.Fatal(c, o)
	}
	create := map[string]any{"name": "entry", "roles": []string{"entry"}, "country": "CN", "ipv4": "203.0.113.31", "firewallMode": "manual", "agentProxyNodeId": nodeID, "agentProxyInternal": true}
	code, out, _ = p.do("POST", "/api/servers", create, nil)
	if code != 201 {
		t.Fatalf("proxy entry: %d %v", code, out)
	}
	entryID := out["server"].(map[string]any)["id"].(string)
	entry, _ := p.store.Server(entryID)
	proxy, err := p.app.agentProxy(entry)
	if err != nil || proxy.Host != "10.10.0.2" || proxy.Port != 1080 || proxy.Username != "entry-user" || proxy.Password != "proxy-password" {
		t.Fatalf("resolution: %v %v", proxy, err)
	}
	for _, cmd := range []string{out["installCommand"].(string), out["offlineInstall"].(map[string]any)["command"].(string)} {
		for _, shell := range []string{"sh", "bash"} {
			c := exec.Command(shell, "-n")
			c.Stdin = strings.NewReader(cmd)
			if result, e := c.CombinedOutput(); e != nil {
				t.Fatalf("%s syntax: %v %s", shell, e, result)
			}
		}
		if !strings.Contains(cmd, "proxy.json") {
			t.Fatal("missing proxy bootstrap")
		}
		for _, line := range strings.Split(cmd, "\n") {
			if (strings.HasPrefix(line, "curl ") || strings.Contains(line, "./mui-agent install ")) && strings.Contains(line, "proxy-password") {
				t.Fatal("credentials in process argv")
			}
		}
	}
	if !strings.Contains(out["installCommand"].(string), `curl -fsSL --config "$mui_proxy_dir/curl.conf"`) {
		t.Fatal("initial script download bypasses SOCKS")
	}
	// Server metadata never contains a proxy password.
	if strings.Contains(Marshal(out["server"]), "proxy-password") {
		t.Fatal("credential in server metadata")
	}
	if c, o, _ := p.do("DELETE", "/api/nodes/"+nodeID, nil, nil); c != 409 {
		t.Fatal(c, o)
	}
	input["password"] = "replacement-password"
	if c, o, _ := p.do("PATCH", "/api/nodes/"+nodeID, input, nil); c != 409 {
		t.Fatal(c, o)
	}
	host, _ = p.store.Server(id)
	host.IPv4 = "203.0.113.22"
	if c, o, _ := p.do("PATCH", "/api/servers/"+id, host, nil); c != 409 {
		t.Fatal(c, o)
	}
	// The selected node can be bootstrapped before entry enrollment.
	st, e := p.app.desired(entryID)
	if e != nil || st.AgentProxy == nil {
		t.Fatal(st, e)
	}
	// Subscription users have independent SOCKS credentials and rendering works.
	sub := shared.Subscription{ID: ID(), Format: "sing-box", NodeIDs: []string{nodeID}, Enabled: true}
	item, e := p.app.subscriptionItem(sub, n, host)
	if e != nil {
		t.Fatal(e)
	}
	if item.Username == n.Username || item.Password == "proxy-password" {
		t.Fatal("subscription shares Agent login")
	}
	for _, format := range []string{"sing-box", "surge", "v2rayn"} {
		raw, excluded, e := shared.RenderSubscription(format, []shared.SubscriptionItem{item})
		if e != nil || len(excluded) > 0 {
			t.Fatal(format, e, excluded)
		}
		if format == "v2rayn" {
			decoded, _ := base64.StdEncoding.DecodeString(string(raw))
			if !strings.HasPrefix(string(decoded), "socks://") {
				t.Fatal(string(decoded))
			}
		}
	}
}

func TestSOCKS5TemplateAndAgentGate(t *testing.T) {
	p := newTestMui(t)
	id, auth := p.enroll("old-agent")
	p.newAgent(auth)
	input := map[string]any{"serverId": id, "name": "SOCKS", "protocol": "socks5", "username": "user", "password": "valid-password", "port": 1080}
	code, n, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 {
		t.Fatal(code, n)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, auth); code != 204 {
		t.Fatal("old Agent received SOCKS", code, out)
	}
	template := map[string]any{"name": "SOCKS template", "protocol": "socks5", "username": "user", "password": "valid-password", "port": 1080}
	if code, out, _ := p.do("POST", "/api/node-templates", template, nil); code != 201 || out["username"] != "user" {
		t.Fatal(code, out)
	}
	input["username"] = ""
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 400 {
		t.Fatal("empty user accepted", code, out)
	}
	s, _ := p.store.Server(id)
	s.FirewallMode = "manual"
	p.store.PutServer(s)
	input["username"] = "user"
	input["port"] = 1081
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 409 {
		t.Fatal("manual firewall accepted", code, out)
	}
}

func TestAgentProxyFailedSwitchCanRevert(t *testing.T) {
	p := newTestMui(t)
	hostID, hostAuth := p.enroll("socks-host")
	p.newAgent(hostAuth)
	host, _ := p.store.Server(hostID)
	host.AgentProxySupport = true
	p.store.PutServer(host)
	n := shared.Node{ID: ID(), ServerID: hostID, Name: "SOCKS", Protocol: "socks5", Username: "entry", Port: 1080, Listen: "0.0.0.0", Direct: true, Enabled: true, Status: "active", FirewallPolicy: "all"}
	p.store.PutNode(n, "fixture-password")
	entryID, auth := p.enroll("entry")
	p.newAgent(auth)
	s, _ := p.store.Server(entryID)
	s.Roles = []string{"entry"}
	s.AgentProxySupport = true
	p.store.PutServer(s)
	s.AgentProxyNodeID = n.ID
	if code, out, _ := p.do("PATCH", "/api/servers/"+entryID, s, nil); code != 200 {
		t.Fatal(code, out)
	}
	// Apply the proxy host's whitelist before the entry receives its switch.
	p.applyAll(hostAuth)
	// Report a failed connectivity check. The current connection stays direct.
	code, job, _ := p.do("GET", "/agent/job", nil, auth)
	if code != 200 {
		t.Fatal(code, job)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "failed", "jobError": "proxy unreachable"}, auth); code != 200 {
		t.Fatal(code, out)
	}
	s, _ = p.store.Server(entryID)
	if !s.AgentProxySwitchPending {
		t.Fatal("lost switch state")
	}
	s.AgentProxyNodeID = ""
	if code, out, _ := p.do("PATCH", "/api/servers/"+entryID, s, nil); code != 200 {
		t.Fatal("cannot revert failed switch", code, out)
	}
	// Previous SOCKS remains protected until the entry acknowledges its new state.
	if err := p.app.protectProxyNode(n, n, "", true); err == nil {
		t.Fatal("proxy released before acknowledgement")
	}
	p.applyAll(auth)
	s, _ = p.store.Server(entryID)
	if s.AgentProxySwitchPending {
		t.Fatal("switch did not finish")
	}
	if err := p.app.protectProxyNode(n, n, "", true); err != nil {
		t.Fatal("unused proxy still protected", err)
	}
}

func TestAgentSOCKSProxyDoesNotRequireClientDirectAccess(t *testing.T) {
	p := newTestMui(t)
	hostID, hostAuth := p.enroll("private-socks")
	p.newAgent(hostAuth)
	host, _ := p.store.Server(hostID)
	host.AgentProxySupport, host.InternalAddress = true, "10.10.0.2"
	p.store.PutServer(host)
	code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": hostID, "name": "SOCKS", "protocol": "socks5", "username": "agent", "password": "fixture-password", "port": 1080, "direct": false}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	nodeID := out["id"].(string)
	p.applyAll(hostAuth)
	before, _ := p.app.desired(hostID)
	if before.Nodes[0].Node.FirewallPolicy != "closed" {
		t.Fatal("unused private node should be closed")
	}
	code, created, _ := p.do("POST", "/api/servers", map[string]any{"name": "entry", "roles": []string{"entry"}, "country": "CN", "ipv4": "198.51.100.31", "internalAddress": "10.10.0.31", "firewallMode": "manual", "agentProxyNodeId": nodeID, "agentProxyInternal": true}, nil)
	if code != 201 {
		t.Fatal("private SOCKS not selectable", code, created)
	}
	entryID := created["server"].(map[string]any)["id"].(string)
	node, _ := p.store.Node(nodeID)
	if node.Direct || node.AgentProxySources != "10.10.0.31" {
		t.Fatalf("client direct flag changed or source missing: %+v", node)
	}
	state, err := p.app.desired(hostID)
	if err != nil || state.Nodes[0].Node.FirewallPolicy != "restricted" || state.Nodes[0].Node.FirewallSources != "10.10.0.31/32" {
		t.Fatal("Agent sources were not independently allowed", state, err)
	}
	if state.Nodes[0].Node.AgentProxySources != "" {
		t.Fatal("panel metadata leaked into older Agent's signed job")
	}
	entry, _ := p.store.Server(entryID)
	proxy, err := p.app.agentProxy(entry)
	if err != nil || proxy.Host != "10.10.0.2" || proxy.Username != "agent" || proxy.Password != "fixture-password" {
		t.Fatal(proxy, err)
	}
	body := map[string]any{"serverId": entryID, "token": created["enrollToken"]}
	if code, out, _ := p.do("POST", "/agent/enroll", body, nil); code != 409 {
		t.Fatal("enrolled before whitelist applied", code, out)
	}
	p.applyAll(hostAuth)
	if code, out, _ := p.do("POST", "/agent/enroll", body, nil); code != 200 {
		t.Fatal("token consumed while whitelist pending", code, out)
	}
	if code, out, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "not-client-direct", "format": "surge", "nodeIds": []string{nodeID}}, nil); code < 400 {
		t.Fatal("Agent use enabled client direct subscriptions", code, out)
	}
	// Changing the client-facing policy must not remove the Agent's whitelist.
	node.Direct, node.FirewallPolicy, node.FirewallSources = true, "restricted", "203.0.113.99"
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatal(code, out)
	}
	node.Direct = false
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatal("Agent incorrectly locks client direct flag", code, out)
	}
	state, err = p.app.desired(hostID)
	if err != nil || state.Nodes[0].Node.FirewallSources != "10.10.0.31/32" {
		t.Fatal(state, err)
	}
	// Old stored documents lack the new display cache. A client policy edit
	// must still produce the Agent whitelist in its very first queued job.
	node, _ = p.store.Node(nodeID)
	node.AgentProxySources = ""
	p.store.PutNode(node, "fixture-password")
	state, err = p.app.desired(hostID)
	if err != nil || state.Nodes[0].Node.FirewallSources != "10.10.0.31/32" {
		t.Fatal("stale cache removed Agent access", state, err)
	}
	if code, out, _ := p.do("DELETE", "/api/servers/"+entryID, nil, nil); code != 200 {
		t.Fatal(code, out)
	}
	state, err = p.app.desired(hostID)
	if err != nil || state.Nodes[0].Node.FirewallPolicy != "closed" {
		t.Fatal("unused Agent whitelist was retained", state, err)
	}
}

func TestAgentProxySwitchWaitsForPrivateSOCKSWhitelist(t *testing.T) {
	p := newTestMui(t)
	hostID, hostAuth := p.enroll("private-socks")
	p.newAgent(hostAuth)
	host, _ := p.store.Server(hostID)
	host.AgentProxySupport = true
	p.store.PutServer(host)
	n := shared.Node{ID: ID(), ServerID: hostID, Name: "SOCKS", Protocol: "socks5", Username: "agent", Port: 1080, Listen: "0.0.0.0", Enabled: true, Status: "active", FirewallPolicy: "all"}
	p.store.PutNode(n, "fixture-password")
	entryID, auth := p.enrollAs("entry", []string{"entry"}, map[string]any{"ipv4": "198.51.100.32", "firewallMode": "manual"})
	p.applyAll(auth)
	entry, _ := p.store.Server(entryID)
	entry.AgentProxySupport = true
	p.store.PutServer(entry)
	entry.AgentProxyNodeID = n.ID
	if code, out, _ := p.do("PATCH", "/api/servers/"+entryID, entry, nil); code != 200 {
		t.Fatal(code, out)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, auth); code != 204 {
		t.Fatal("switch delivered before source allowed", code, out)
	}
	p.applyAll(hostAuth)
	if code, out, _ := p.do("GET", "/agent/job", nil, auth); code != 200 {
		t.Fatal("switch still blocked after source allowed", code, out)
	}
}

func TestAgentProxySourcesKeepPreviousAddressChoice(t *testing.T) {
	w := routeWorld{
		servers: map[string]shared.Server{
			"entry":     {ID: "entry", IPv4: "198.51.100.31", IPv6: "2001:db8::31", InternalAddress: "10.10.0.31", AgentProxyNodeID: "next", AgentProxyInternal: true, AgentProxyPreviousNodeID: "old"},
			"old-host":  {ID: "old-host", IPv4: "203.0.113.1"},
			"next-host": {ID: "next-host", IPv4: "203.0.113.2", InternalAddress: "10.10.0.2"},
		},
		nodes: map[string]shared.Node{
			"old":  {ID: "old", ServerID: "old-host", Protocol: "socks5"},
			"next": {ID: "next", ServerID: "next-host", Protocol: "socks5"},
		},
	}
	if got := w.nodeAgentProxySources("old"); got != "198.51.100.31" {
		t.Fatal("previous public IPv4 source lost or wrong family", got)
	}
	if got := w.nodeAgentProxySources("next"); got != "10.10.0.31" {
		t.Fatal("internal proxy used public source", got)
	}
	entry := w.servers["entry"]
	entry.AgentProxyPreviousNodeID = ""
	w.servers["entry"] = entry
	if got := w.nodeAgentProxySources("old"); got != "" {
		t.Fatal("confirmed switch retained old source", got)
	}
	policy, sources := effectiveNodeAccess(shared.Node{RouteSources: "192.0.2.5", AgentProxySources: "10.10.0.31"})
	if policy != "restricted" || sources != "192.0.2.5,10.10.0.31" {
		t.Fatal("Agent whitelist replaced route whitelist", policy, sources)
	}
}

func TestAgentProxySourceModeIndependentOfDestination(t *testing.T) {
	entry := shared.Server{IPv4: "198.51.100.31", IPv6: "2001:db8::31", InternalAddress: "10.10.0.31"}
	node := shared.Node{Protocol: "socks5"}
	host := shared.Server{IPv4: "203.0.113.1", InternalAddress: "10.10.0.1"}
	for _, tc := range []struct {
		name     string
		internal bool
		mode     string
		want     []string
	}{
		{"public target private source", false, "internal", []string{"10.10.0.31"}},
		{"private target public source", true, "public", []string{"198.51.100.31"}},
		{"automatic public", false, "auto", []string{"198.51.100.31"}},
		{"automatic private", true, "", []string{"10.10.0.31"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentProxySourceAddresses(entry, node, host, tc.internal, tc.mode); !slices.Equal(got, tc.want) {
				t.Fatal(got, tc.want)
			}
		})
	}
}

func TestAgentProxySourceOnlyChangeUpdatesFirewallWithoutAgentSwitch(t *testing.T) {
	p := newTestMui(t)
	hostID, hostAuth := p.enroll("socks")
	p.newAgent(hostAuth)
	host, _ := p.store.Server(hostID)
	host.AgentProxySupport = true
	p.store.PutServer(host)
	node := shared.Node{ID: ID(), ServerID: hostID, Protocol: "socks5", Name: "SOCKS", Username: "entry", Port: 1080, Listen: "0.0.0.0", Enabled: true, Status: "active", FirewallPolicy: "all"}
	p.store.PutNode(node, "fixture-password")
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "entry", "roles": []string{"entry"}, "country": "CN", "ipv4": "198.51.100.31", "internalAddress": "10.10.0.31", "firewallMode": "manual", "agentProxyNodeId": node.ID, "agentProxySourceMode": "internal"}, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	assertSource := func(want string) {
		t.Helper()
		state, err := p.app.desired(hostID)
		if err != nil || len(state.Nodes) != 1 || state.Nodes[0].Node.FirewallSources != want {
			t.Fatal(state, err, want)
		}
	}
	assertSource("10.10.0.31/32")
	p.applyAll(hostAuth)
	entry, _ := p.store.Server(id)
	proxy, err := p.app.agentProxy(entry)
	if err != nil || proxy.Host != host.IPv4 {
		t.Fatal("source choice changed destination", proxy, err)
	}
	entry.AgentProxySourceMode = "public"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, entry, nil); code != 200 {
		t.Fatal(code, out)
	}
	assertSource("198.51.100.31/32")
	p.applyAll(hostAuth)
	entry, _ = p.store.Server(id)
	entry.AgentProxySourceMode = "internal"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, entry, nil); code != 200 {
		t.Fatal(code, out)
	}
	assertSource("10.10.0.31/32")
	entry, _ = p.store.Server(id)
	if entry.AgentProxySwitchPending || entry.AgentProxyPreviousNodeID != "" || entry.AgentProxyInternal {
		t.Fatal("source-only edit caused proxy switch", entry)
	}
	var count int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations WHERE server_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("source-only edit queued entry jobs", count, err)
	}
	entry.InternalAddress = ""
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, entry, nil); code != 409 {
		t.Fatal("private source silently fell back to public", code, out)
	}
	stored, _ := p.store.Server(id)
	if stored.InternalAddress != "10.10.0.31" {
		t.Fatal("failed source validation was saved")
	}
	entry.InternalAddress, entry.AgentProxySourceMode = "10.10.0.31", "invalid"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, entry, nil); code != 409 {
		t.Fatal("unknown source mode accepted", code, out)
	}
}
