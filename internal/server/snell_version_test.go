package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mui/internal/agent"
	"mui/internal/shared"
)

func TestSnellV6NodeTemplateAndAgentGate(t *testing.T) {
	p := newTestMui(t)
	serverID, auth := p.enroll("snell-v6")
	input := map[string]any{"serverId": serverID, "name": "v6", "protocol": "snell", "port": 54321,
		"shadowTlsHost": "example.com", "password": "a-valid-v6-psk", "enabled": true, "direct": true}
	code, node, _ := p.do("POST", "/api/nodes", input, nil)
	if code != 201 || node["snellVersion"] != float64(6) {
		t.Fatalf("default v6: %d %v", code, node)
	}
	state, err := p.app.desired(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.10", "snellV6": true, "snellFixedPort": true, "nodeFirewallPolicies": true}, auth); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 204 {
		t.Fatalf("v6 apply sent to old Agent: %d %v", code, job)
	}
	input["enabled"] = false
	if code, out, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), input, nil); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 204 {
		t.Fatalf("disabled v6 node sent to old helper validator: %d %v", code, job)
	}
	p.newAgent(auth)
	if code, job, _ := p.do("GET", "/agent/job", nil, auth); code != 200 {
		t.Fatalf("v6 apply did not resume: %d %v", code, job)
	}
	stored, _ := p.store.Node(node["id"].(string))
	server, _ := p.store.Server(serverID)
	before := p.app.nodeFingerprint(server, stored, "a-valid-v6-psk", "outer-password")
	stored.SnellVersion = 5
	if before == p.app.nodeFingerprint(server, stored, "a-valid-v6-psk", "outer-password") {
		t.Fatal("v6 protocol change did not invalidate client deployment")
	}
	input["port"], input["password"] = 54322, "eight123"
	if code, out, _ := p.do("POST", "/api/nodes", input, nil); code != 400 {
		t.Fatalf("short v6 PSK accepted: %d %v", code, out)
	}
	template := map[string]any{"name": "v6 template", "protocol": "snell", "port": 54323, "shadowTlsHost": "example.com", "password": "eight123"}
	if code, out, _ := p.do("POST", "/api/node-templates", template, nil); code != 400 {
		t.Fatalf("short template PSK accepted: %d %v", code, out)
	}
	template["password"] = "a-valid-template-psk"
	if code, out, _ := p.do("POST", "/api/node-templates", template, nil); code != 201 || out["snellVersion"] != float64(6) {
		t.Fatalf("v6 template: %d %v", code, out)
	}
}

func TestSnellVersionsMatchConfigurationAndSubscriptions(t *testing.T) {
	for _, version := range []int{5, 6} {
		n := shared.Node{ID: ID(), Name: "Snell", Protocol: "snell", SnellVersion: version, SnellPort: 23456,
			Listen: "0.0.0.0", Port: 54321, Obfs: "http", ShadowTLSHost: "example.com", Enabled: true, Status: "active"}
		item := shared.SubscriptionItem{Node: n, Server: shared.Server{IPv4: "203.0.113.1"}, Password: "a-valid-snell-psk", ShadowTLSPassword: "outer-password"}
		raw, err := shared.SingBoxConfig([]shared.ManagedNode{{Node: n, Password: item.Password, ShadowTLSPassword: item.ShadowTLSPassword}}, "/certs")
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Inbounds []map[string]any `json:"inbounds"`
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		if config.Inbounds[1]["version"] != float64(version) {
			t.Fatalf("inbound ignored %d: %s", version, raw)
		}
		if version == 6 {
			if _, exists := config.Inbounds[1]["obfs_mode"]; exists {
				t.Fatalf("v6 emitted obsolete obfs_mode: %s", raw)
			}
			if config.Inbounds[1]["mode"] != "default" {
				t.Fatalf("v6 mode: %s", raw)
			}
		} else if config.Inbounds[1]["obfs_mode"] != "http" {
			t.Fatalf("v5 lost HTTP obfuscation: %s", raw)
		}
		for _, format := range []string{"surge", "sing-box"} {
			out, excluded, err := shared.RenderSubscription(format, []shared.SubscriptionItem{item})
			if err != nil || len(excluded) != 0 {
				t.Fatalf("%s: %v %v", format, excluded, err)
			}
			if format == "surge" {
				want := "version=5"
				if version == 6 {
					want = "version=6"
				}
				if version == 6 && strings.Contains(string(out), "obfs=") {
					t.Fatalf("v6 Surge emitted v5 obfs: %s", out)
				}
				if !strings.Contains(string(out), want) {
					t.Fatalf("wrong Surge version: %s", out)
				}
			} else {
				var client struct {
					Outbounds []map[string]any `json:"outbounds"`
				}
				if err := json.Unmarshal(out, &client); err != nil {
					t.Fatal(err)
				}
				want := 4
				if version == 6 {
					want = 6
				}
				if version == 6 {
					if _, exists := client.Outbounds[0]["obfs_mode"]; exists {
						t.Fatalf("v6 outbound emitted v4 obfs_mode: %s", out)
					}
				}
				if client.Outbounds[0]["version"] != float64(want) {
					t.Fatalf("wrong sing-box version: %s", out)
				}
			}
		}
	}
}

func TestSnellV6PSKByteLimits(t *testing.T) {
	n := shared.Node{Protocol: "snell", SnellVersion: 6}
	for _, size := range []int{11, 12, 255, 256} {
		err := shared.ValidateSnellPSK(n, strings.Repeat("x", size))
		if (err == nil) != (size >= 12 && size <= 255) {
			t.Fatalf("PSK size %d: %v", size, err)
		}
	}
}
