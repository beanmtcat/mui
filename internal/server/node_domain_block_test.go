package server

import (
	"slices"
	"testing"

	"mui/internal/shared"
)

func TestNodeDomainBlockNeedsCapableAgent(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("block")
	input := map[string]any{"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss", "port": 50001, "method": "2022-blake3-aes-128-gcm",
		"blockedDomains": []string{`"Google.com",`, "*.youtube.com", ""}}
	report := map[string]any{"agentVersion": "0.6.23", "multiUserStats": true, "nodeFirewallPolicies": true, "ufwStatus": "active"}

	// Not reported yet: the node may wait, but no job reaches an older Agent.
	code, node, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 {
		t.Fatalf("pending server: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
		t.Fatalf("old Agent report: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 200 && code != 204 || out["kind"] == "nodes.apply" {
		t.Fatalf("old Agent received a blocked node: %d %v", code, out)
	}
	other := map[string]any{"direct": true, "serverId": serverID, "name": "SS2", "protocol": "ss", "port": 50002, "method": "2022-blake3-aes-128-gcm", "blockedDomains": []string{"google.com"}}
	if code, out, _ := p.do("POST", "/api/nodes", other, nil); code != 400 {
		t.Fatalf("old Agent accepted a block it would ignore: %d %v", code, out)
	}

	// A stopped node does not reach sing-box, so it no longer holds the server back.
	node["enabled"] = false
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatalf("disable blocked node on old Agent: %d %v", code, out)
	}
	p.applyNext(agent, "success")
	node["enabled"] = true
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 400 {
		t.Fatalf("old Agent re-enabled a block it would ignore: %d %v", code, out)
	}

	report["agentVersion"], report["nodeDomainBlock"] = "0.6.24", true
	if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
		t.Fatalf("new Agent report: %d %v", code, out)
	}
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatalf("enable on new Agent: %d %v", code, out)
	}
	p.applyNext(agent, "success")
	stored, err := p.store.Node(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.BlockedDomains, []string{"google.com", "youtube.com"}) || stored.Status != "active" {
		t.Fatalf("stored node: %+v", stored)
	}
	state, err := p.app.desired(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Nodes) != 1 || len(state.Nodes[0].Node.BlockedDomains) != 2 {
		t.Fatalf("Agent state lost the block: %+v", state.Nodes)
	}

	node["blockedDomains"] = []string{"not a domain/x"}
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 400 {
		t.Fatalf("invalid domain accepted: %d %v", code, out)
	}
	node["blockedDomains"] = []string{}
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatalf("clear list: %d %v", code, out)
	}
	if stored, _ = p.store.Node(nodeID); len(stored.BlockedDomains) != 0 {
		t.Fatalf("list not cleared: %+v", stored)
	}
}

func TestAgentProxyNodeCannotBlockPanel(t *testing.T) {
	p := newTestMui(t)
	panel := p.app.publicURLs[0].Hostname()
	if err := p.app.checkProxyReachesPanel(shared.Node{BlockedDomains: []string{panel}}); err == nil {
		t.Fatal("proxy that drops the panel accepted")
	}
	if err := p.app.checkProxyReachesPanel(shared.Node{BlockedDomains: []string{"not-" + panel}}); err != nil {
		t.Fatal(err)
	}
}
