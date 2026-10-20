package server

import (
	"encoding/json"
	"mui/internal/agent"
	"mui/internal/shared"
	"strings"
	"testing"
	"time"
)

func TestServerOutboundDefaultAndNodeOverrides(t *testing.T) {
	p := newTestMui(t)
	serverID, auth := p.enroll("egress")
	p.newAgent(auth)
	var saved []shared.Node
	for i, mode := range []string{"inherit", "system", "interface"} {
		in := map[string]any{"serverId": serverID, "name": mode, "protocol": "ss", "method": "aes-256-gcm", "password": "a-test-password", "port": 52000 + i, "enabled": true, "direct": true, "outboundMode": mode}
		if mode == "interface" {
			in["outboundInterface"] = "eth0"
		}
		code, node, _ := p.do("POST", "/api/nodes", in, nil)
		if code != 201 {
			t.Fatalf("create: %d %v", code, node)
		}
		n, _ := p.store.Node(node["id"].(string))
		saved = append(saved, n)
	}
	// The explicit binding must block old Agent applies even when its report
	// falsely sets the capability. Upgrade jobs behind the apply still flow.
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.11", "nodeFirewallPolicies": true, "outboundBindingSupport": true}, auth)
	if code != 200 {
		t.Fatal(code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 204 {
		t.Fatalf("old Agent got apply: %d %v", code, job)
	}
	srv, _ := p.store.Server(serverID)
	state := shared.DesiredState{Revision: srv.Revision, ProtocolVersion: 1}
	if err := p.store.PutOperation(shared.Operation{ID: ID(), ServerID: serverID, Kind: "agent.upgrade", Status: "queued", Revision: srv.Revision, CreatedAt: time.Now(), UpdatedAt: time.Now()}, state); err != nil {
		t.Fatal(err)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 200 || job["kind"] != "agent.upgrade" {
		t.Fatalf("upgrade blocked: %d %v", code, job)
	} else {
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, auth); code != 200 {
			t.Fatal(code, out)
		}
	}
	code, out, _ = p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.12", "outboundBindingSupport": true, "nodeFirewallPolicies": true, "multiUserStats": true}, auth)
	if code != 200 {
		t.Fatal(code, out)
	}
	p.applyAll(auth)
	srv, _ = p.store.Server(serverID)
	before := make([]string, len(saved))
	for i, n := range saved {
		before[i] = p.app.nodeFingerprint(srv, n, "a-test-password", "")
	}
	srv.OutboundInterface = "ppp0"
	code, out, _ = p.do("PATCH", "/api/servers/"+serverID, srv, nil)
	if code != 200 || out["outboundInterface"] != "ppp0" {
		t.Fatalf("default: %d %v", code, out)
	}
	srv, _ = p.store.Server(serverID)
	for i, n := range saved {
		changed := before[i] != p.app.nodeFingerprint(srv, n, "a-test-password", "")
		if changed != (i == 0) {
			t.Fatalf("override fingerprint %s changed=%t", n.OutboundMode, changed)
		}
		stored, _ := p.store.Node(n.ID)
		if (stored.Status == "pending") != (i == 0) {
			t.Fatalf("wrong node status %+v", stored)
		}
		live, err := p.app.nodeLive(stored, srv, "")
		if err != nil || live != (i != 0) {
			t.Fatalf("node readiness mode=%s live=%t err=%v", n.OutboundMode, live, err)
		}
	}
	desired, err := p.app.desired(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if desired.OutboundInterface != "ppp0" {
		t.Fatal("default missing from desired state")
	}
	if err := agent.ValidateDesired(desired); err != nil {
		t.Fatal(err)
	}
	raw, err := shared.SingBoxConfig(desired.Nodes, "/certs", desired.OutboundInterface)
	if err != nil || !strings.Contains(string(raw), `"bind_interface": "ppp0"`) {
		t.Fatal(err, string(raw))
	}
	p.applyAll(auth)
	srv, _ = p.store.Server(serverID)
	live, err := p.app.nodeLive(saved[0], srv, "")
	if err != nil || !live {
		t.Fatalf("applied default not ready: %t %v", live, err)
	}
	// Metadata round-trips through the database; runtime capability cannot be
	// spoofed by an admin server edit.
	var decoded shared.Server
	blob, _ := json.Marshal(out)
	_ = json.Unmarshal(blob, &decoded)
	if decoded.OutboundInterface != "ppp0" {
		t.Fatal("field lost in API response")
	}
	srv.OutboundInterface = "bad/interface"
	if code, out, _ := p.do("PATCH", "/api/servers/"+serverID, srv, nil); code != 400 {
		t.Fatalf("invalid default: %d %v", code, out)
	}
	for _, n := range []map[string]any{{"outboundMode": "interface"}, {"outboundMode": "system", "outboundInterface": "ppp0"}, {"outboundMode": "interface", "outboundInterface": "bad/interface"}} {
		n["serverId"], n["name"], n["protocol"], n["method"], n["port"] = serverID, "bad", "ss", "aes-256-gcm", 53000
		if code, out, _ := p.do("POST", "/api/nodes", n, nil); code != 400 {
			t.Fatalf("invalid node: %d %v", code, out)
		}
	}
}

func TestServerOutboundCreation(t *testing.T) {
	p := newTestMui(t)
	input := map[string]any{"name": "egress", "country": "SG", "ipv4": "203.0.113.9", "roles": []string{"exit"}, "outboundInterface": "ppp0", "outboundBindingSupport": true}
	code, out, _ := p.do("POST", "/api/servers", input, nil)
	if code != 201 {
		t.Fatal(code, out)
	}
	srv := out["server"].(map[string]any)
	if srv["outboundInterface"] != "ppp0" || srv["outboundBindingSupport"] == true {
		t.Fatalf("admin fields: %v", srv)
	}
	input["outboundInterface"] = "ppp0;id"
	if code, out, _ := p.do("POST", "/api/servers", input, nil); code != 400 {
		t.Fatal(code, out)
	}
}
