package server

import (
	"slices"
	"testing"

	"mui/internal/shared"
)

func TestAgentPublicIPAutoSyncIsOptIn(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("dynamic-home")
	server, err := p.store.Server(serverID)
	if err != nil {
		t.Fatal(err)
	}
	server.IPv6 = "2001:4860::10"
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	report := func(ipv4, ipv6 string) {
		t.Helper()
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{
			"hostReported": true, "ipv4": ipv4, "ipv6": ipv6,
		}, agent); code != 200 {
			t.Fatalf("agent report: %d %v", code, out)
		}
	}
	report("198.51.100.20", "2001:4860::20")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "203.0.113.10" || server.IPv6 != "2001:4860::10" || server.DetectedIPv4 != "198.51.100.20" || server.DetectedIPv6 != "2001:4860::20" {
		t.Fatalf("manual addresses were overwritten: %+v", server)
	}
	server.AutoSyncPublicIP = true
	if code, out, _ := p.do("PATCH", "/api/servers/"+serverID, server, nil); code != 200 || out["autoSyncPublicIp"] != true {
		t.Fatalf("enable auto sync: %d %v", code, out)
	}
	report("198.51.100.21", "2001:4860::21")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.21" || server.IPv6 != "2001:4860::21" {
		t.Fatalf("reported addresses were not applied: %+v", server)
	}
	if got := shared.PublishedAddress(shared.SubscriptionItem{Server: server}); got != server.IPv4 {
		t.Fatalf("subscription still uses old address: %q", got)
	}
	if got := hopAddress(server, false); got != server.IPv4 {
		t.Fatalf("route still uses old address: %q", got)
	}
	if got := sourceAddresses(server, false, "198.51.100.99"); !slices.Equal(got, []string{"198.51.100.21"}) {
		t.Fatalf("route firewall retained the old source: %v", got)
	}
	report("198.51.100.22", "")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.22" || server.IPv6 != "2001:4860::21" {
		t.Fatalf("missing IPv6 report erased a known address: %+v", server)
	}
	report("100.72.1.9", "")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.22" {
		t.Fatalf("carrier-grade NAT address replaced a public address: %+v", server)
	}
	report("192.168.1.9", "fd00::9")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.22" || server.IPv6 != "2001:4860::21" {
		t.Fatalf("private outbound address replaced a public address: %+v", server)
	}
	// A home router hides its public IPv4 from the Agent's local interface.
	// A direct panel connection still exposes that address to the server.
	direct := map[string]string{}
	for key, value := range agent {
		direct[key] = value
	}
	direct["RemoteAddr"] = "198.51.100.45:54321"
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"hostReported": true, "ipv4": "", "ipv6": "",
	}, direct); code != 200 {
		t.Fatalf("direct NAT report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.45" || server.DetectedIPv4 != "198.51.100.45" || server.IPv6 != "2001:4860::21" {
		t.Fatalf("panel did not backfill the direct public IPv4: %+v", server)
	}
	server.AgentProxyNodeID = "proxy-node"
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	direct["RemoteAddr"] = "198.51.100.46:54321"
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"hostReported": true, "ipv4": "", "ipv6": "",
	}, direct); code != 200 {
		t.Fatalf("proxied report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.45" {
		t.Fatalf("SOCKS5 proxy exit replaced the host IPv4: %+v", server)
	}
}
