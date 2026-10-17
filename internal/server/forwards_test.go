package server

import (
	"testing"
	"time"

	"mui/internal/shared"
)

func TestForwardLifecycleAndPortConflicts(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("forward")
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.5.0", "nodeFirewallPolicies": true, "multiUserStats": true, "forwardSupport": true, "ufwStatus": "active"}, agent)
	if code != 200 {
		t.Fatalf("Agent: %d %v", code, out)
	}
	input := map[string]any{"serverId": serverID, "name": "relay", "network": "tcp", "listen": "0.0.0.0", "port": 51000, "targets": []map[string]any{{"host": "example.com", "port": 443}}, "firewallPolicy": "restricted", "firewallSources": "192.0.2.1", "enabled": true}
	code, forward, _ := p.do("POST", "/api/forwards", input, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, forward)
	}
	if forward["firewallSources"] != "192.0.2.1/32" {
		t.Fatalf("sources: %v", forward)
	}
	job := p.applyNext(agent, "success")
	forwards := job["state"].(map[string]any)["forwards"].([]any)
	if len(forwards) != 1 {
		t.Fatalf("desired forwards: %v", forwards)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "conflict", "protocol": "ss", "port": 51000, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 409 {
		t.Fatalf("node accepted conflicting port: %d %v", code, node)
	}
	id := forward["id"].(string)
	for _, point := range []map[string]any{
		{"forwardId": id, "instanceId": "process-1", "uplink": 100, "downlink": 200},
		{"forwardId": id, "instanceId": "process-1", "uplink": 100, "downlink": 200},
		{"forwardId": id, "instanceId": "process-1", "uplink": 150, "downlink": 260},
	} {
		code, out, _ = p.do("POST", "/agent/report", map[string]any{"forwardTraffic": []any{point}}, agent)
		if code != 200 {
			t.Fatalf("traffic: %d %v", code, out)
		}
	}
	list, err := p.store.Forwards(serverID)
	if err != nil || len(list) != 1 || list[0].Uplink != 150 || list[0].Downlink != 260 {
		t.Fatalf("forward totals: %+v %v", list, err)
	}
	input["port"] = 51001
	code, out, _ = p.do("PATCH", "/api/forwards/"+id, input, nil)
	if code != 200 {
		t.Fatalf("update: %d %v", code, out)
	}
	p.applyNext(agent, "success")
	code, out, _ = p.do("DELETE", "/api/forwards/"+id, nil, nil)
	if code != 202 {
		t.Fatalf("delete: %d %v", code, out)
	}
	job = p.applyNext(agent, "success")
	if len(job["state"].(map[string]any)["forwards"].([]any)) != 0 {
		t.Fatalf("deleted forward still desired: %v", job)
	}
	list, err = p.store.Forwards(serverID)
	if err != nil || len(list) != 0 {
		t.Fatalf("deleted forward remains: %v %v", list, err)
	}
}

func TestForwardWaitsForCapableAgentWithoutBlockingUpgrade(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("forward-upgrade")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.5.0", "agentSelfUpdate": true, "nodeFirewallPolicies": true, "multiUserStats": true}, agent); code != 200 {
		t.Fatalf("old Agent report: %d %v", code, out)
	}
	if err := p.app.queueApply(serverID, "nodes.apply"); err != nil {
		t.Fatal(err)
	}
	code, oldJob, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 {
		t.Fatalf("old apply: %d %v", code, oldJob)
	}
	input := map[string]any{"serverId": serverID, "name": "relay", "network": "tcp", "port": 51000, "targets": []map[string]any{{"host": "example.com", "port": 443}}, "firewallPolicy": "all", "enabled": true}
	code, created, _ := p.do("POST", "/api/forwards", input, nil)
	if code != 201 {
		t.Fatalf("create pending forward: %d %v", code, created)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": oldJob["id"], "jobStatus": "success"}, agent); code != 200 {
		t.Fatalf("stale apply completion: %d %v", code, out)
	}
	forward, err := p.store.Forward(created["id"].(string))
	if err != nil || forward.Status != "pending" {
		t.Fatalf("stale apply activated forward: %+v %v", forward, err)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old Agent received forward: %d %v", code, out)
	}
	now := time.Now()
	if err := p.store.PutOperation(shared.Operation{ID: "upgrade-forward-test", ServerID: serverID, Kind: "agent.upgrade", Status: "queued", CreatedAt: now, UpdatedAt: now}, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || out["kind"] != "agent.upgrade" {
		t.Fatalf("upgrade blocked by pending forward: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": "upgrade-forward-test", "jobStatus": "failed", "jobError": "test completion"}, agent); code != 200 {
		t.Fatalf("upgrade completion: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0", "forwardSupport": true, "multiUserStats": true}, agent); code != 200 {
		t.Fatalf("capable Agent report: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || out["kind"] != "forwards.apply" {
		t.Fatalf("forward not queued for capable Agent: %d %v", code, out)
	}
}
