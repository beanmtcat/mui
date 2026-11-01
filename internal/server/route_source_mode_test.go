package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"mui/internal/agent"
	"mui/internal/shared"
)

func TestRouteLoadGroupMixesPublicAndInternalDestinations(t *testing.T) {
	l := newRouteLab(t)
	private, err := l.p.store.Server(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	private.InternalAddress = "10.0.0.2"
	if err = l.p.store.PutServer(private); err != nil {
		t.Fatal(err)
	}
	publicID, agent := l.p.enrollAs("hk7", []string{"transit"}, map[string]any{"ipv4": "198.51.100.7"})
	l.agents = append(l.agents, agent)
	hop := map[string]any{"serverIds": []string{l.t1, publicID, l.t2}, "balance": "round-robin",
		"internal": true, "addressModes": map[string]string{publicID: "public"}, "sourceFamily": "ipv4"}
	code, route := l.route(map[string]any{"name": "mixed", "entryServerId": l.entry, "nodeId": l.nodeID,
		"port": 53631, "enabled": true, "hops": []map[string]any{hop}})
	if code != 201 {
		t.Fatalf("mixed route: %d %v", code, route)
	}
	routeID := route["id"].(string)
	want := []shared.ForwardTarget{{Host: "10.0.0.2", Port: 53631}, {Host: "198.51.100.7", Port: 53631}, {Host: "10.0.0.3", Port: 53631}}
	for _, f := range l.forwards(l.entry) {
		if !slices.Equal(f.Targets, want) {
			t.Fatalf("mixed target order or address: %+v", f.Targets)
		}
	}
	for id, source := range map[string]string{l.t1: "10.0.0.1/32", publicID: "198.51.100.1/32", l.t2: "10.0.0.1/32"} {
		state, err := l.p.app.desired(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range state.Forwards {
			if f.FirewallSources != source {
				t.Fatalf("receiver %s admitted wrong sender: %+v", id, f)
			}
		}
	}
	world, err := l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	entry := world.servers[l.entry]
	for _, target := range want {
		entry.RouteLatencies = append(entry.RouteLatencies, shared.RouteLatency{
			ForwardID: routeForwardID(routeID, l.entry, "tcp"), Host: target.Host, Port: target.Port, TCPMs: 15, OK: true, At: time.Now(),
		})
	}
	world.servers[l.entry] = entry
	if edges := routeEdgeLatencies(world.routes[0], world, time.Now()); len(edges) != 3 {
		t.Fatalf("mixed address latencies missing: %+v", edges)
	}
	invalid := map[string]any{"name": "invalid", "entryServerId": l.entry, "nodeId": l.nodeID,
		"port": 53632, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}, "balance": "failover", "addressModes": map[string]string{publicID: "public"}}}}
	if code, out := l.route(invalid); code != 400 {
		t.Fatalf("accepted override for a server outside the group: %d %v", code, out)
	}
	entry2, agent2 := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.5", "internalAddress": "10.0.0.5"})
	l.agents = append(l.agents, agent2)
	public, _ := l.p.store.Server(publicID)
	public.InternalAddress = "10.0.0.7" // Both choices now exist, but the saved paths still differ.
	if err := l.p.store.PutServer(public); err != nil {
		t.Fatal(err)
	}
	otherHop := map[string]any{"serverIds": []string{l.t1, publicID, l.t2}, "balance": "round-robin", "internal": true, "sourceFamily": "ipv4"}
	if code, out := l.route(map[string]any{"name": "different modes", "entryServerId": entry2, "nodeId": l.nodeID,
		"port": 53631, "enabled": true, "hops": []map[string]any{otherHop}}); code != 409 {
		t.Fatalf("shared listener ignored different member addresses: %d %v", code, out)
	}
	// The group default differs from the first route, but every member's
	// effective address is identical. They must still share each listener.
	otherHop["internal"] = false
	otherHop["addressModes"] = map[string]string{l.t1: "internal", l.t2: "internal"}
	if code, out := l.route(map[string]any{"name": "equivalent modes", "entryServerId": entry2, "nodeId": l.nodeID,
		"port": 53631, "enabled": true, "hops": []map[string]any{otherHop}}); code != 201 {
		t.Fatalf("matching mixed groups cannot share listeners: %d %v", code, out)
	}
	for _, id := range []string{l.t1, publicID, l.t2} {
		if got := len(l.forwards(id)); got != 2 {
			t.Fatalf("server %s has %d listeners; want one TCP and one UDP", id, got)
		}
	}
	l.applyAll()
	requireRouteLive(t, l, routeID)
}

func TestRoutePrivateSourcesWithPublicDestinations(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{
		"name": "private sources", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops":           []map[string]any{{"serverIds": []string{l.t2}, "sourceMode": "internal"}},
		"nodeSourceMode": "internal",
	})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	for _, f := range l.forwards(l.entry) {
		if f.Targets[0].Host != "198.51.100.3" {
			t.Fatal("selecting a private source changed the next-hop destination")
		}
	}
	state, err := l.p.app.desired(l.t2)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.Targets[0].Host != "198.51.100.4" || f.FirewallPolicy != "restricted" || f.FirewallSources != "10.0.0.1/32" {
			t.Fatalf("intermediate must dial public exit and admit only private entry: %+v", f)
		}
	}
	if err := agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	exit, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if exit.Nodes[0].Node.FirewallSources != "10.0.0.3/32" {
		t.Fatalf("exit did not admit the last hop's private source: %+v", exit.Nodes[0].Node)
	}
	if err := agent.ValidateDesired(exit); err != nil {
		t.Fatal(err)
	}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "private source", "format": "sing-box", "routeIds": []string{route["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	l.applyAll()
	if code, body := l.p.fetch(strings.TrimPrefix(sub["url"].(string), l.p.app.PublicURL)); code != 200 || !strings.Contains(body, "entry.example.com") {
		t.Fatalf("subscription liveness used the public source or wrong client address: %d %s", code, body)
	}
}

func TestRoutePublicSourceWithPrivateDestination(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{
		"name": "public sources", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops":         []map[string]any{{"serverIds": []string{l.t2}, "internal": true, "sourceMode": "public"}},
		"nodeInternal": true, "nodeSourceMode": "public",
	})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	for _, f := range l.forwards(l.entry) {
		if f.Targets[0].Host != "10.0.0.3" {
			t.Fatal("public source mode changed private destination")
		}
	}
	state, err := l.p.app.desired(l.t2)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.Targets[0].Host != "10.0.0.4" || f.FirewallSources != "198.51.100.1/32" {
			t.Fatalf("source/destination remained coupled: %+v", f)
		}
	}
	exit, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if exit.Nodes[0].Node.FirewallSources != "198.51.100.3/32" {
		t.Fatal("exit source override ignored")
	}
}

func TestRouteSourceModeValidationAndGroups(t *testing.T) {
	l := newRouteLab(t)
	w, err := l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	rt := shared.Route{ID: ID(), Name: "group", EntryServerID: l.entry, NodeID: l.nodeID, Enabled: true,
		Hops: []shared.RouteHop{{ServerIDs: []string{l.t1, l.t2}, Balance: "failover", SourceMode: "internal"}}, NodeSourceMode: "internal"}
	if err := w.checkRouteShape(rt); err == nil {
		t.Fatal("accepted a group member without its required private source")
	}
	s := w.servers[l.t1]
	s.InternalAddress = "10.0.0.2"
	w.servers[l.t1] = s
	if err := w.checkRouteShape(rt); err != nil {
		t.Fatal(err)
	}
	w.routes = []shared.Route{rt}
	if got := w.nodeRouteSources(l.nodeID); got != "10.0.0.2,10.0.0.3" {
		t.Fatalf("missing private LB sources: %s", got)
	}
	s = w.servers[l.entry]
	s.InternalAddress = "fd00::1"
	w.servers[l.entry] = s
	if err := w.checkRouteShape(rt); err == nil {
		t.Fatal("accepted an IPv6 source for an IPv4 connection")
	}
	s.InternalAddress = "entry.private.example"
	w.servers[l.entry] = s
	if err := w.checkRouteShape(rt); err == nil {
		t.Fatal("accepted a hostname as a firewall source")
	}
	for _, fields := range []map[string]any{
		{"nodeSourceMode": "invalid"},
		{"hops": []map[string]any{{"serverIds": []string{l.t2}, "sourceMode": "invalid"}}},
	} {
		fields["name"], fields["entryServerId"], fields["nodeId"], fields["enabled"] = "invalid mode", l.entry, l.nodeID, true
		if code, _ := l.route(fields); code != 400 {
			t.Fatalf("invalid source mode accepted: %d", code)
		}
	}
}

func TestChangingReceiverSourceDoesNotChangeOfflineEntryConfig(t *testing.T) {
	l := newRouteLab(t)
	entryID := createOfflineServer(l.p, "private offline entry", "198.51.100.8")
	entry, _ := l.p.store.Server(entryID)
	entry.InternalAddress = "10.100.132.41"
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"name": "offline private source", "entryServerId": entryID, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}}
	code, route := l.route(fields)
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	exportOffline(l.p, entryID)
	before, _ := l.p.store.Server(entryID)
	fields["hops"] = []map[string]any{{"serverIds": []string{l.t1}, "sourceMode": "internal"}}
	if code, out, _ := l.p.do("PATCH", "/api/routes/"+route["id"].(string), fields, nil); code != 200 {
		t.Fatalf("source edit: %d %v", code, out)
	}
	after, _ := l.p.store.Server(entryID)
	if after.Revision != before.Revision || after.OfflineExportedRevision != after.Revision {
		t.Fatal("firewall-only edit invalidated unchanged offline configuration")
	}
	state, err := l.p.app.desired(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.FirewallSources != "10.100.132.41/32" || f.FirewallPolicy != "restricted" {
			t.Fatalf("old public source retained: %+v", f)
		}
	}
}
