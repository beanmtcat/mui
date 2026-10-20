package server

import (
	"encoding/json"
	"testing"

	"mui/internal/shared"
)

func TestShadowTLSSystemHandshakeUpgradeReappliesBoundNodes(t *testing.T) {
	for _, tc := range []struct {
		name, serverIF, nodeMode, nodeIF, firewall string
		apply                                      bool
	}{
		{name: "inherited", serverIF: "ppp0", apply: true},
		{name: "node override", nodeMode: "interface", nodeIF: "ppp0", apply: true},
		{name: "manual firewall", serverIF: "ppp0", firewall: "manual", apply: true},
		{name: "system override", serverIF: "ppp0", nodeMode: "system"},
		{name: "unbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestMui(t)
			id, auth := p.enroll(tc.name)
			p.newAgent(auth)
			srv, _ := p.store.Server(id)
			srv.AgentVersion, srv.OutboundBindingSupport = "0.6.15", true
			srv.OutboundInterface = tc.serverIF
			if tc.firewall != "" {
				srv.FirewallMode = tc.firewall
			}
			if err := p.store.PutServer(srv); err != nil {
				t.Fatal(err)
			}
			code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "Snell", "protocol": "snell", "port": 12306, "snellPort": 8443, "snellVersion": 6, "shadowTlsHost": "example.com", "password": "a-valid-v6-psk", "enabled": true, "direct": true, "outboundMode": tc.nodeMode, "outboundInterface": tc.nodeIF}, nil)
			if code != 201 {
				t.Fatal(code, node)
			}
			p.applyAll(auth)
			srv, _ = p.store.Server(id)
			report := map[string]any{"agentVersion": "0.6.16", "outboundBindingSupport": true, "forwardSupport": srv.ForwardSupport, "forwardTcpUdp": srv.ForwardTCPUDP, "nodeFirewallPolicies": srv.NodeFirewallPolicies, "multiUserStats": srv.MultiUserStats, "shadowTlsAuth": srv.ShadowTLSAuth, "snellFixedPort": srv.SnellFixedPort, "snellV6": srv.SnellV6, "manualFirewallSupport": srv.ManualFirewallSupport}
			if code, out, _ := p.do("POST", "/agent/report", report, auth); code != 200 {
				t.Fatal(code, out)
			}
			code, job, _ := p.do("GET", "/agent/job", nil, auth)
			if !tc.apply {
				if code != 204 {
					t.Fatal("unaffected node received an unnecessary apply", code, job)
				}
				return
			}
			if code != 200 || job["kind"] != "subscriptions.apply" {
				t.Fatal("bound ShadowTLS node was not reapplied", code, job)
			}
			raw, _ := json.Marshal(job["state"])
			var state shared.DesiredState
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			config, err := shared.SingBoxConfig(state.Nodes, "/certs", state.OutboundInterface)
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct{ Inbounds []map[string]any }
			if err := json.Unmarshal(config, &cfg); err != nil {
				t.Fatal(err)
			}
			for _, inbound := range cfg.Inbounds {
				if inbound["type"] == "shadowtls" && inbound["handshake"].(map[string]any)["bind_interface"] != nil {
					t.Fatal("handshake still bound to proxy exit", inbound)
				}
			}
		})
	}
}
