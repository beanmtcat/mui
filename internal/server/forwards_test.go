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

func TestForwardTCPUDPLifecycleAndConflicts(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("combined")
	p.newAgent(agent)
	input := map[string]any{"serverId": id, "name": "combined", "network": shared.ForwardTCPUDP, "port": 51000, "targets": []map[string]any{{"host": "198.51.100.5", "port": 51000}}, "enabled": true, "firewallPolicy": "all"}
	code, out, _ := p.do("POST", "/api/forwards", input, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	forwardID := out["id"].(string)
	p.applyAll(agent)
	f, _ := p.store.Forward(forwardID)
	if f.Network != shared.ForwardTCPUDP || f.Status != "active" {
		t.Fatalf("combined apply: %+v", f)
	}
	for _, network := range []string{"tcp", "udp"} {
		conflict := map[string]any{}
		for k, v := range input {
			conflict[k] = v
		}
		conflict["network"] = network
		if code, out, _ := p.do("POST", "/api/forwards", conflict, nil); code != 409 {
			t.Fatalf("%s conflict accepted: %d %v", network, code, out)
		}
	}
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "conflict", "protocol": "ss", "port": 51000, "method": "2022-blake3-aes-128-gcm", "direct": true}, nil); code != 409 {
		t.Fatalf("node conflict accepted: %d %v", code, out)
	}
	// One cumulative traffic record covers both sockets; retrying the report
	// must not count the same bytes twice.
	point := shared.ForwardTrafficPoint{ForwardID: forwardID, InstanceID: "combined-process", Uplink: 70, Downlink: 90}
	for range 2 {
		if err := p.store.SaveForwardTraffic(id, []shared.ForwardTrafficPoint{point}); err != nil {
			t.Fatal(err)
		}
	}
	fs, _ := p.store.Forwards(id)
	if len(fs) != 1 || fs[0].Uplink != 70 || fs[0].Downlink != 90 {
		t.Fatalf("combined totals: %+v", fs)
	}
	input["network"] = "udp"
	if code, out, _ := p.do("PATCH", "/api/forwards/"+forwardID, input, nil); code != 200 {
		t.Fatalf("edit protocol: %d %v", code, out)
	}
	p.applyAll(agent)
	if code, out, _ := p.do("DELETE", "/api/forwards/"+forwardID, nil, nil); code != 202 {
		t.Fatalf("delete: %d %v", code, out)
	}
	p.applyAll(agent)
	fs, _ = p.store.Forwards(id)
	if len(fs) != 0 {
		t.Fatalf("combined delete left forwards: %+v", fs)
	}
}

func TestForwardTCPUDPWaitsForCapableAgentAndAllowsUpgrade(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("combined-upgrade")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.6", "forwardSupport": true, "nodeFirewallPolicies": true, "agentSelfUpdate": true}, agent); code != 200 {
		t.Fatalf("old agent: %d %v", code, out)
	}
	input := map[string]any{"serverId": id, "name": "combined", "network": shared.ForwardTCPUDP, "port": 51000, "targets": []map[string]any{{"host": "198.51.100.5", "port": 51000}}, "enabled": true}
	if code, out, _ := p.do("POST", "/api/forwards", input, nil); code != 201 {
		t.Fatalf("save before upgrade: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old agent received unsupported config: %d %v", code, out)
	}
	now := time.Now()
	if err := p.store.PutOperation(shared.Operation{ID: "combined-upgrade", ServerID: id, Kind: "agent.upgrade", Status: "queued", CreatedAt: now, UpdatedAt: now}, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || out["kind"] != "agent.upgrade" {
		t.Fatalf("upgrade blocked: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": "combined-upgrade", "jobStatus": "failed", "jobError": "fixture complete"}, agent); code != 200 {
		t.Fatalf("complete upgrade fixture: %d %v", code, out)
	}
	p.newAgent(agent)
	p.applyAll(agent)
	fs, _ := p.store.Forwards(id)
	if len(fs) != 1 || fs[0].Status != "active" {
		t.Fatalf("capability report did not trigger apply: %+v", fs)
	}
}
