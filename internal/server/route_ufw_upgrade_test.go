package server

import "testing"

func TestRouteUFWUpgradeReappliesEntryAndLanding(t *testing.T) {
	l := newRouteLab(t)
	code, out := l.route(map[string]any{"name": "existing chain", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatal(code, out)
	}
	l.applyAll()
	for _, index := range []int{0, 3} {
		headers := l.agents[index]
		server, err := l.p.store.Server(headers["X-Server-ID"])
		if err != nil {
			t.Fatal(err)
		}
		server.AgentVersion = "0.6.13"
		if err = l.p.store.PutServer(server); err != nil {
			t.Fatal(err)
		}
		report := map[string]any{"agentVersion": "0.6.14", "forwardSupport": server.ForwardSupport, "forwardTcpUdp": server.ForwardTCPUDP, "nodeFirewallPolicies": server.NodeFirewallPolicies, "multiUserStats": server.MultiUserStats, "shadowTlsAuth": server.ShadowTLSAuth, "snellFixedPort": server.SnellFixedPort, "snellV6": server.SnellV6, "manualFirewallSupport": server.ManualFirewallSupport, "ufwStatus": "active"}
		if code, out, _ := l.p.do("POST", "/agent/report", report, headers); code != 200 {
			t.Fatal(code, out)
		}
		code, job, _ := l.p.do("GET", "/agent/job", nil, headers)
		if code != 200 {
			t.Fatal("upgrade did not reapply firewall policy", index, code, job)
		}
		want := "forwards.apply"
		if index == 3 {
			want = "nodes.apply"
		}
		if job["kind"] != want {
			t.Fatal("wrong reapply job", job)
		}
	}
}
