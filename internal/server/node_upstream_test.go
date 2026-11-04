package server

import (
	"encoding/json"
	"testing"

	"mui/internal/shared"
)

func TestNodeSOCKSOutboundThroughSellerNode(t *testing.T) {
	p := newTestMui(t)
	code, result, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "seller", "country": "US", "domain": "res.example.test",
		"roles": []string{"exit"}, "managementMode": "external", "firewallMode": "manual",
	}, nil)
	if code != 201 {
		t.Fatal(code, result)
	}
	sellerID := result["server"].(map[string]any)["id"].(string)
	code, upstream, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": sellerID, "name": "住宅 IP", "protocol": "socks5", "port": 1080, "username": "buyer", "password": "seller-secret-1", "enabled": true}, nil)
	if code != 201 {
		t.Fatal(code, upstream)
	}
	upstreamID := upstream["id"].(string)

	serverID, agent := p.enroll("wrap")
	report := map[string]any{"agentVersion": "0.6.25", "multiUserStats": true, "nodeFirewallPolicies": true, "nodeDomainBlock": true, "ufwStatus": "active"}
	if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
		t.Fatal(code, out)
	}
	input := map[string]any{"direct": true, "serverId": serverID, "name": "SS 住宅", "protocol": "ss", "port": 50001, "method": "2022-blake3-aes-128-gcm",
		"outboundMode": "socks5", "outboundNodeId": upstreamID, "enabled": true}
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 400 {
		t.Fatal("an Agent that ignores the egress would leak this server's address", code, out)
	}
	report["agentVersion"], report["nodeSocksOutbound"] = "0.6.26", true
	if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
		t.Fatal(code, out)
	}
	bad := map[string]any{}
	for k, v := range input {
		bad[k] = v
	}
	bad["outboundNodeId"], bad["port"] = "missing", 50002
	if code, out, _ := p.do("POST", "/api/nodes", bad, nil); code != 400 {
		t.Fatal("unknown egress accepted", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	p.applyNext(agent, "success")
	state, err := p.app.desired(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Nodes) != 1 || state.Nodes[0].Upstream == nil || *state.Nodes[0].Upstream != (shared.SOCKS5Proxy{Host: "res.example.test", Port: 1080, Username: "buyer", Password: "seller-secret-1"}) {
		t.Fatalf("Agent state lacks the egress: %+v", state.Nodes)
	}

	// The seller's node cannot vanish from under the SS node, but its login
	// may change and reaches the Agent.
	if code, out, _ := p.do("DELETE", "/api/nodes/"+upstreamID, nil, nil); code != 409 {
		t.Fatal("egress deleted while in use", code, out)
	}
	upstream["enabled"] = false
	if code, out, _ := p.do("PATCH", "/api/nodes/"+upstreamID, upstream, nil); code != 409 {
		t.Fatal("egress disabled while in use", code, out)
	}
	upstream["enabled"], upstream["password"] = true, "seller-secret-2"
	if code, out, _ := p.do("PATCH", "/api/nodes/"+upstreamID, upstream, nil); code != 200 {
		t.Fatal(code, out)
	}
	if state, _ = p.app.desired(serverID); state.Nodes[0].Upstream.Password != "seller-secret-2" {
		t.Fatal("new seller password not sent", state.Nodes[0].Upstream)
	}
	if job := p.applyNext(agent, "success"); job["kind"] != "nodes.apply" {
		t.Fatal("dependent server was not reconfigured", job)
	}

	// Switching the SS node back to direct egress releases the seller node.
	node["outboundMode"], node["outboundNodeId"] = "inherit", ""
	if code, out, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), node, nil); code != 200 {
		t.Fatal(code, out)
	}
	if code, out, _ := p.do("DELETE", "/api/nodes/"+upstreamID, nil, nil); code != 200 {
		t.Fatal(code, out)
	}
}

func TestSingBoxConfigSOCKSOutbound(t *testing.T) {
	item := shared.ManagedNode{
		Node:     shared.Node{ID: "n1", Name: "SS", Protocol: "ss", Method: "aes-256-gcm", Port: 50001, Enabled: true, OutboundMode: "socks5", OutboundNodeID: "up"},
		Password: "secret",
	}
	if _, err := shared.SingBoxConfig([]shared.ManagedNode{item}, ""); err == nil {
		t.Fatal("a node without its upstream must not fall back to direct egress")
	}
	item.Upstream = &shared.SOCKS5Proxy{Host: "res.example.test", Port: 1080, Username: "buyer", Password: "password1"}
	raw, err := shared.SingBoxConfig([]shared.ManagedNode{item}, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range cfg.Outbounds {
		if o["tag"] == "upstream-n1" && o["type"] == "socks" && o["server"] == "res.example.test" && o["server_port"] == float64(1080) && o["username"] == "buyer" && o["password"] == "password1" && o["version"] == "5" {
			found = true
		}
	}
	routed := false
	for _, r := range cfg.Route.Rules {
		if r["outbound"] == "upstream-n1" && r["action"] == "route" {
			routed = true
		}
	}
	if !found || !routed {
		t.Fatalf("SOCKS5 egress missing: %s", raw)
	}
}
