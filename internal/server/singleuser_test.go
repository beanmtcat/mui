package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestSingleUserSS2022WorksWithOldAgent(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("single-user-old-agent")
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"direct": true, "singleUser": true, "serverId": serverID,
		"name": "SS", "protocol": "ss", "port": 50031, "method": "2022-blake3-aes-128-gcm",
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	job := p.applyNext(agent, "success")
	managed := job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if _, ok := managed["users"]; ok {
		t.Fatalf("single-user node has subscription users: %v", managed["users"])
	}
	raw, _ := json.Marshal(managed)
	var managedNode shared.ManagedNode
	if err := json.Unmarshal(raw, &managedNode); err != nil {
		t.Fatal(err)
	}
	config, err := shared.SingBoxConfig([]shared.ManagedNode{managedNode}, "/tmp/certs")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.Inbounds[0]["users"]; ok || parsed.Inbounds[0]["password"] != managedNode.Password {
		t.Fatalf("single-user SS config lost its original password: %s", config)
	}
	nodeID := node["id"].(string)
	password, err := p.store.NodeSecret(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Alice", "Bob"} {
		code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
			"name": name, "format": "sing-box", "nodeIds": []string{nodeID},
		}, nil)
		if code != 201 {
			t.Fatalf("subscription %s: %d %v", name, code, sub)
		}
		path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
		code, body, _ := p.do("GET", path, nil, nil)
		if code != 200 {
			t.Fatalf("download %s: %d %v", name, code, body)
		}
		got := body["outbounds"].([]any)[0].(map[string]any)["password"]
		if got != password {
			t.Fatalf("subscription %s password = %v, want node password", name, got)
		}
	}
	code, share, _ := p.do("GET", "/api/nodes/"+nodeID+"/share", nil, nil)
	server, _ := p.store.Server(serverID)
	stored, _ := p.store.Node(nodeID)
	want, err := shared.ShareURI(shared.SubscriptionItem{Node: stored, Server: server, Password: password})
	if err != nil || code != 200 || share["uri"] != want {
		t.Fatalf("single-user share: %d %v", code, share)
	}
}

func TestSwitchNodeToSingleUserWaitsForApply(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("single-user-switch")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"agentVersion": "test", "multiUserStats": true, "ufwStatus": "active",
	}, agent); code != 200 {
		t.Fatalf("capability: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss",
		"port": 50032, "method": "2022-blake3-aes-128-gcm",
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyNext(agent, "success")
	nodeID := node["id"].(string)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "client", "format": "sing-box", "nodeIds": []string{nodeID},
	}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	p.applyNext(agent, "success")
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	node["singleUser"] = true
	if code, out, _ := p.do("PATCH", "/api/nodes/"+nodeID, node, nil); code != 200 {
		t.Fatalf("switch mode: %d %v", code, out)
	}
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("published single-user login before apply: HTTP %d", code)
	}
	job := p.applyNext(agent, "success")
	managed := job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if _, ok := managed["users"]; ok {
		t.Fatalf("old subscription users were retained: %v", managed["users"])
	}
	code, body, _ := p.do("GET", path, nil, nil)
	if code != 200 {
		t.Fatalf("download after apply: %d %v", code, body)
	}
	password, _ := p.store.NodeSecret(nodeID)
	if got := body["outbounds"].([]any)[0].(map[string]any)["password"]; got != password {
		t.Fatalf("download password = %v, want node password", got)
	}
	stored, _ := p.store.Node(nodeID)
	if !shared.SharedSubscriptionPassword(stored) {
		t.Fatal("node was not marked as sharing its password")
	}
	if code, out, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "second client", "format": "sing-box", "nodeIds": []string{nodeID},
	}, nil); code != 201 {
		t.Fatalf("second subscription: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("shared credential queued an unnecessary restart: %d %v", code, job)
	}
}
