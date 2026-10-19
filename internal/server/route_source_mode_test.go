package server

import (
	"strings"
	"testing"

	"mui/internal/agent"
	"mui/internal/shared"
)

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
