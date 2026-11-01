package server

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestAgentObservedIPv4RequiresDirectPublicSource(t *testing.T) {
	t.Setenv("MUI_TRUSTED_PROXIES", "10.0.0.0/8")
	p := newTestMui(t)
	serverID, agent := p.enroll("nat-v4")
	server, err := p.store.Server(serverID)
	if err != nil {
		t.Fatal(err)
	}
	server.AutoSyncPublicIP = true
	server.IPv4 = ""
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	probe := func(remote, forwarded string) (int, map[string]any) {
		t.Helper()
		headers := map[string]string{}
		for k, v := range agent {
			headers[k] = v
		}
		headers["RemoteAddr"] = remote
		if forwarded != "" {
			headers["X-Forwarded-For"] = forwarded
		}
		code, out, _ := p.do("GET", "/agent/observed-ipv4", nil, headers)
		return code, out
	}
	if code, out := probe("205.206.186.8:55555", "1.2.3.4"); code != 200 || out["ipv4"] != "205.206.186.8" {
		t.Fatalf("direct source was lost or spoofed: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"hostReported": true, "agentVersion": "0.6.23", "observedIpv4": "205.206.186.8", "ipv6": "2001:56a:f972:cd00::101",
	}, agent); code != 200 || out["autoSyncPublicIp"] != true {
		t.Fatalf("auto-sync report response: %d %v", code, out)
	}
	server, err = p.store.Server(serverID)
	if err != nil || server.IPv4 != "" || server.DetectedIPv4 != "205.206.186.8" || server.IPv6 != "2001:56a:f972:cd00::101" {
		t.Fatalf("observed IPv4 became a published address: %+v %v", server, err)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"hostReported": true}, agent); code != 200 {
		t.Fatalf("empty report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "" || server.DetectedIPv4 != "205.206.186.8" {
		t.Fatalf("empty report cleared the last observation: %+v", server)
	}
	direct := map[string]string{}
	for key, value := range agent {
		direct[key] = value
	}
	direct["RemoteAddr"] = "205.206.186.9:55555"
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.22"}, direct); code != 200 {
		t.Fatalf("legacy direct report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "" || server.DetectedIPv4 != "205.206.186.9" {
		t.Fatalf("request-source fallback became a published address: %+v", server)
	}
	if code, out := probe("10.0.0.2:55555", "205.206.186.8"); code != 200 || out["ipv4"] != "205.206.186.8" {
		t.Fatalf("trusted proxy source was lost: %d %v", code, out)
	}
	for _, source := range []string{"192.168.100.11:55555", "100.72.1.9:55555", "[2001:56a:f972:cd00::101]:55555"} {
		if code, _ := probe(source, ""); code != 204 {
			t.Fatalf("accepted non-public IPv4 source %q: %d", source, code)
		}
	}
	server.AgentProxyNodeID = "proxy-node"
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"hostReported": true, "observedIpv4": "205.206.186.10",
	}, direct); code != 200 {
		t.Fatalf("proxied observation report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "" || server.DetectedIPv4 != "" {
		t.Fatalf("proxy observation was retained: %+v", server)
	}
	if code, _ := probe("205.206.186.8:55555", ""); code != 204 {
		t.Fatalf("accepted proxy exit as host IP: %d", code)
	}
	server.AgentProxyNodeID = ""
	server.AutoSyncPublicIP = false
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if code, _ := probe("205.206.186.8:55555", ""); code != 204 {
		t.Fatalf("probed a server without auto sync: %d", code)
	}
}

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
			"hostReported": true, "agentVersion": "0.6.23", "ipv4": ipv4, "ipv6": ipv6,
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
	if server.IPv4 != "198.51.100.21" || server.DetectedIPv4 != "198.51.100.21" || server.IPv6 != "2001:4860::21" {
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
	if server.IPv4 != "198.51.100.22" || server.DetectedIPv4 != "198.51.100.22" || server.IPv6 != "2001:4860::21" {
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
		"hostReported": true, "agentVersion": "0.6.22", "ipv4": "", "ipv6": "",
	}, direct); code != 200 {
		t.Fatalf("direct NAT report: %d %v", code, out)
	}
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.45" || server.DetectedIPv4 != "198.51.100.45" || server.IPv6 != "2001:4860::21" {
		t.Fatalf("legacy panel observation did not follow the previous IPv4: %+v", server)
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
	if server.IPv4 != "198.51.100.45" || server.DetectedIPv4 != "" {
		t.Fatalf("SOCKS5 proxy exit replaced the host IPv4: %+v", server)
	}
}

func TestAgentLocalPublicIPv4AutoSyncUpdatesExistingAddress(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("local-v4")
	server, _ := p.store.Server(serverID)
	server.IPv4, server.IPv6, server.AutoSyncPublicIP = "", "2001:4860::10", true
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	report := func(ip string) {
		t.Helper()
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{"hostReported": true, "ipv4": ip}, agent); code != 200 {
			t.Fatalf("report: %d %v", code, out)
		}
	}
	report("198.51.100.21")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.21" {
		t.Fatalf("local public IPv4 was not synced: %+v", server)
	}
	server.Notes = "unrelated edit"
	if code, out, _ := p.do("PATCH", "/api/servers/"+serverID, server, nil); code != 200 {
		t.Fatalf("unrelated edit: %d %v", code, out)
	}
	report("198.51.100.22")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.22" {
		t.Fatalf("auto-synced IPv4 did not follow the interface: %+v", server)
	}
	server.IPv4 = "198.51.100.99"
	if code, out, _ := p.do("PATCH", "/api/servers/"+serverID, server, nil); code != 200 {
		t.Fatalf("manual edit: %d %v", code, out)
	}
	report("198.51.100.23")
	server, _ = p.store.Server(serverID)
	if server.IPv4 != "198.51.100.23" {
		t.Fatalf("existing IPv4 did not follow the local interface: %+v", server)
	}
}

func TestAgentObservedIPv4OnlyFollowsPreviouslyDetectedAddress(t *testing.T) {
	for _, tc := range []struct {
		name, configured, want string
	}{
		{"previous observation", "205.206.186.8", "205.206.186.9"},
		{"manual address", "203.0.113.10", "203.0.113.10"},
		{"empty address", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestMui(t)
			serverID, agent := p.enroll("observed-v4")
			server, _ := p.store.Server(serverID)
			server.AutoSyncPublicIP = true
			server.IPv4 = tc.configured
			server.IPv6 = "2001:4860::10"
			server.DetectedIPv4 = "205.206.186.8"
			if err := p.store.PutServer(server); err != nil {
				t.Fatal(err)
			}
			if code, out, _ := p.do("POST", "/agent/report", map[string]any{
				"hostReported": true, "observedIpv4": "205.206.186.9",
			}, agent); code != 200 {
				t.Fatalf("report: %d %v", code, out)
			}
			server, _ = p.store.Server(serverID)
			if server.IPv4 != tc.want || server.DetectedIPv4 != "205.206.186.9" {
				t.Fatalf("observation updated configured IPv4 incorrectly: %+v", server)
			}
		})
	}
}

func TestObservedNATIPv4DoesNotReplaceIPv6RouteOrSubscription(t *testing.T) {
	l := newRouteLab(t)
	entry, _ := l.p.store.Server(l.entry)
	entry.IPv6 = "2001:4860::1"
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	exit, _ := l.p.store.Server(l.exit)
	exit.IPv4, exit.IPv6, exit.AutoSyncPublicIP = "", "2001:4860::4", true
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	code, route := l.route(map[string]any{"name": "ipv6 only", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	before := l.forwards(l.entry)
	if len(before) == 0 || before[0].Targets[0].Host != exit.IPv6 {
		t.Fatalf("route did not use IPv6 before observation: %+v", before)
	}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{
		"hostReported": true, "observedIpv4": "205.206.186.8", "ipv6": exit.IPv6,
	}, l.agents[3]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	exit, _ = l.p.store.Server(l.exit)
	if exit.IPv4 != "" || exit.DetectedIPv4 != "205.206.186.8" || hopAddress(exit, false) != exit.IPv6 ||
		shared.PublishedAddress(shared.SubscriptionItem{Server: exit}) != exit.IPv6 {
		t.Fatalf("NAT egress replaced the IPv6 connection address: %+v", exit)
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	after := l.forwards(l.entry)
	if !slices.EqualFunc(before, after, func(a, b shared.ForwardRule) bool {
		return a.ID == b.ID && slices.Equal(a.Targets, b.Targets)
	}) {
		t.Fatalf("stored route forwards changed after NAT observation: before=%+v after=%+v", before, after)
	}
	if refreshed, err := l.p.store.Server(l.exit); err != nil || refreshed.Revision != exit.Revision {
		t.Fatalf("NAT observation unnecessarily advanced exit revision: %+v %v", refreshed, err)
	}
	if source := sourceAddresses(exit, false, "198.51.100.1"); !slices.Contains(source, "205.206.186.8") {
		t.Fatalf("NAT observation missing from firewall source candidates: %v", source)
	}
}

func TestObservedIPv4ChangeTriggersRouteSourceSync(t *testing.T) {
	l := newRouteLab(t)
	code, out := l.route(map[string]any{"name": "source sync", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	entry, _ := l.p.store.Server(l.entry)
	entry.AutoSyncPublicIP = true
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.23", "observedIpv4": "205.206.186.8"}, l.agents[0]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		node, err := l.p.store.Node(l.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(node.RouteSources, "205.206.186.8") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	node, _ := l.p.store.Node(l.nodeID)
	if !strings.Contains(node.RouteSources, "205.206.186.8") {
		t.Fatal("observed IPv4 change did not update the route firewall source")
	}
	before, _ := l.p.store.Server(l.entry)
	forwards := l.forwards(l.entry)
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true}, l.agents[0]); code != 200 {
		t.Fatalf("empty report: %d %v", code, out)
	}
	after, _ := l.p.store.Server(l.entry)
	if after.DetectedIPv4 != before.DetectedIPv4 || after.Revision != before.Revision || !reflect.DeepEqual(l.forwards(l.entry), forwards) {
		t.Fatalf("empty report changed the route source or forwards: before=%+v after=%+v", before, after)
	}
}
