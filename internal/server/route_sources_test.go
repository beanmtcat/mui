package server

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"mui/internal/agent"
	"mui/internal/shared"
)

func TestRouteSourcesMatchDestinationFamily(t *testing.T) {
	s := shared.Server{IPv4: "198.51.100.1", IPv6: "2001:db8::1", DetectedIPv4: "198.51.100.1", DetectedIPv6: "2001:db8::1", InternalAddress: "10.0.0.1"}
	for _, tc := range []struct {
		name          string
		internal      bool
		targets, want []string
	}{
		{"IPv4 exit", false, []string{"198.51.100.4"}, []string{"198.51.100.1"}},
		{"IPv6 exit", false, []string{"2001:db8::4"}, []string{"2001:db8::1"}},
		{"DNS exit", false, []string{"exit.example.com"}, []string{"198.51.100.1", "2001:db8::1"}},
		{"mixed group", false, []string{"198.51.100.4", "2001:db8::4"}, []string{"198.51.100.1", "2001:db8::1"}},
		{"internal IPv4", true, []string{"10.0.0.4"}, []string{"10.0.0.1"}},
		{"mismatched internal", true, []string{"fd00::4"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceAddresses(s, tc.internal, tc.targets...); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestRouteForwardFollowsLandingDomainWhenPublicIPChanges(t *testing.T) {
	l := newRouteLab(t)
	if code, out := l.route(map[string]any{"name": "dynamic exit", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}); code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	forward := l.forwards(l.t1)[0]
	if got := forward.Targets[0].Host; got != "198.51.100.4" {
		t.Fatalf("initial target = %q", got)
	}
	exit, err := l.p.store.Server(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	// A domain alone keeps the literal target: existing routes are not
	// rewritten to depend on DNS when the panel upgrades.
	exit.Domain = "dynamic.example.com"
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApp(l.p.store, "https://mui.example.test"); err != nil {
		t.Fatal(err)
	}
	if got := l.forwards(l.t1)[0].Targets[0].Host; got != "198.51.100.4" {
		t.Fatalf("static server switched to its domain: %q", got)
	}
	exit.AutoSyncPublicIP = true
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApp(l.p.store, "https://mui.example.test"); err != nil {
		t.Fatal(err)
	}
	forward = l.forwards(l.t1)[0]
	if got := forward.Targets[0].Host; got != exit.Domain {
		t.Fatalf("domain did not replace literal target: %q", got)
	}
	exit.IPv4 = "198.51.100.99"
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	forward = l.forwards(l.t1)[0]
	if got := forward.Targets[0].Host; got != exit.Domain {
		t.Fatalf("dynamic IP replaced domain target: %q", got)
	}
}

func TestRouteDesiredCanonicalSourcesForCurrentAgent(t *testing.T) {
	l := newRouteLab(t)
	entry, _ := l.p.store.Server(l.entry)
	entry.IPv6 = "2a12:8d02:2100:364:26a3:f0ff:fe47:bc84"
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	if code, out := l.route(map[string]any{"name": "IPv4 landing", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true}); code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	node, _ := l.p.store.Node(l.nodeID)
	if node.RouteSources != entry.IPv4 {
		t.Fatalf("IPv6 leaked into IPv4 landing sources: %q", node.RouteSources)
	}
	state, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Nodes[0].Node.FirewallSources; got != entry.IPv4+"/32" {
		t.Fatalf("noncanonical node source: %q", got)
	}
	if err := agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	// Domain destinations may choose IPv6, but that source must then carry /128.
	exit, _ := l.p.store.Server(l.exit)
	exit.IPv4 = ""
	exit.Domain = "exit.example.com"
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	state, err = l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state.Nodes[0].Node.FirewallSources, entry.IPv6+"/128") {
		t.Fatalf("IPv6 source is not a host CIDR: %q", state.Nodes[0].Node.FirewallSources)
	}
	for _, cidr := range strings.Split(state.Nodes[0].Node.FirewallSources, ",") {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRouteForwardDesiredSourcesAreCanonical(t *testing.T) {
	l := newRouteLab(t)
	if code, out := l.route(map[string]any{"name": "middle", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}); code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	state, err := l.p.app.desired(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.FirewallSources != "198.51.100.1/32" {
			t.Fatalf("bad intermediate source: %q", f.FirewallSources)
		}
	}
	if err := agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
}

func TestIntermediateSourcesUseIncomingDestinationFamily(t *testing.T) {
	l := newRouteLab(t)
	entry, _ := l.p.store.Server(l.entry)
	entry.IPv6 = "2001:db8::1"
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	middle, _ := l.p.store.Server(l.t1)
	middle.IPv4 = ""
	middle.IPv6 = "2001:db8::2"
	middle.DetectedIPv4 = "198.51.100.2"
	if err := l.p.store.PutServer(middle); err != nil {
		t.Fatal(err)
	}
	if code, out := l.route(map[string]any{"name": "v6 in v4 out", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}); code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	state, err := l.p.app.desired(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.FirewallSources != entry.IPv6+"/128" {
			t.Fatalf("incoming IPv6 used wrong source family: %q", f.FirewallSources)
		}
	}
	exitState, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if exitState.Nodes[0].Node.FirewallSources != middle.DetectedIPv4+"/32" {
		t.Fatalf("outgoing IPv4 used wrong source: %q", exitState.Nodes[0].Node.FirewallSources)
	}
}
