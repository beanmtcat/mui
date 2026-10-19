package server

import (
	"mui/internal/shared"
	"testing"
	"time"
)

func TestSnellInnerPortPanelValidation(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("exit")
	input := map[string]any{"serverId": serverID, "name": "Snell", "protocol": "snell", "port": 54321, "snellPort": 23456, "shadowTlsHost": "example.com", "enabled": true}
	code, node, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 || node["snellPort"] != float64(23456) {
		t.Fatalf("create: %d %v", code, node)
	}
	stored, err := p.store.Node(node["id"].(string))
	if err != nil || stored.SnellPort != 23456 {
		t.Fatalf("not persisted: %+v %v", stored, err)
	}
	input["port"] = 54322
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 409 {
		t.Fatalf("duplicate inner listener: %d %v", code, out)
	}
	forward := shared.ForwardRule{ID: ID(), ServerID: serverID, Name: "forward", Network: "tcp", Listen: "0.0.0.0", Port: 23456, Targets: []shared.ForwardTarget{{Host: "example.com", Port: 443}}, FirewallPolicy: "all", Enabled: true}
	server, _ := p.store.Server(serverID)
	if err := p.app.checkForward(forward, server); err == nil {
		t.Fatal("forward accepted occupied inner port")
	}
	forward.Port = 23457
	if err := p.store.PutForward(forward); err != nil {
		t.Fatal(err)
	}
	input["snellPort"] = 23457
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 409 {
		t.Fatalf("inner port accepted occupied forward: %d %v", code, out)
	}
	input["snellPort"] = shared.StatsAPIPort
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 400 {
		t.Fatalf("reserved inner port: %d %v", code, out)
	}
	server.SSHPorts = []int{23458}
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	input["snellPort"] = 23458
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 400 {
		t.Fatalf("SSH inner port: %d %v", code, out)
	}
}

func TestSnellFixedPortWaitsForCapableAgent(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("exit")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.1", "nodeFirewallPolicies": true, "ufwStatus": "active"}, agent); code != 200 {
		t.Fatalf("old report: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": serverID, "name": "Snell", "protocol": "snell", "port": 54321, "snellPort": 23456, "shadowTlsHost": "example.com", "enabled": true}, nil); code != 201 {
		t.Fatalf("node: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old agent must not receive fixed-port apply: %d %v", code, out)
	}
	now := time.Now()
	upgrade := shared.Operation{ID: ID(), ServerID: serverID, Kind: "agent.upgrade", Status: "queued", CreatedAt: now, UpdatedAt: now}
	if err := p.store.PutOperation(upgrade, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || job["kind"] != "agent.upgrade" {
		t.Fatalf("upgrade blocked: %d %v", code, job)
	}
	p.newAgent(agent)
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || job["kind"] == "agent.upgrade" {
		t.Fatalf("new agent cannot apply: %d %v", code, job)
	}
}
