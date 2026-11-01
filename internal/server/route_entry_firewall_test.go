package server

import (
	"strings"
	"testing"
)

func TestRouteEntryFirewallRestrictsBothTransports(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{
		"name": "private entry", "entryServerId": l.entry, "nodeId": l.nodeID,
		"enabled": true, "entryFirewallPolicy": "restricted",
		"entryFirewallSources": "183.129.141.26\n183.129.141.23/32",
	})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	for _, f := range l.forwards(l.entry) {
		if f.FirewallPolicy != "restricted" || f.FirewallSources != "183.129.141.26/32,183.129.141.23/32" {
			t.Fatalf("entry %s should admit only selected sources: %+v", f.Network, f)
		}
	}
	state, err := l.p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.RouteID == route["id"] && (f.FirewallPolicy != "restricted" || f.FirewallSources != "183.129.141.26/32,183.129.141.23/32") {
			t.Fatalf("Agent state lost the entry restriction: %+v", f)
		}
	}
	code, out, _ := l.p.do("PATCH", "/api/routes/"+route["id"].(string), map[string]any{
		"name": "open entry", "entryServerId": l.entry, "nodeId": l.nodeID,
		"port": route["port"], "enabled": true, "entryFirewallPolicy": "all",
	}, nil)
	if code != 200 {
		t.Fatalf("restore open access: %d %v", code, out)
	}
	for _, f := range l.forwards(l.entry) {
		if f.FirewallPolicy != "all" || f.FirewallSources != "" {
			t.Fatalf("entry did not return to default access: %+v", f)
		}
	}
}

func TestRouteEntryFirewallRejectsInvalidSource(t *testing.T) {
	l := newRouteLab(t)
	for _, tc := range []struct{ policy, sources string }{
		{"restricted", ""},
		{"restricted", "example.com"},
		{"all", "183.129.141.26"},
		{"manual", ""},
	} {
		code, out := l.route(map[string]any{
			"name": "invalid source", "entryServerId": l.entry, "nodeId": l.nodeID,
			"enabled": true, "entryFirewallPolicy": tc.policy, "entryFirewallSources": tc.sources,
		})
		if code != 400 || !strings.Contains(out["error"].(string), "入口") {
			t.Fatalf("%q %q: %d %v", tc.policy, tc.sources, code, out)
		}
	}
}

func TestRouteEntryFirewallManualServerKeepsManualPolicy(t *testing.T) {
	l := newRouteLab(t)
	entry, err := l.p.store.Server(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.FirewallMode = "manual"
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	code, route := l.route(map[string]any{
		"name": "manual entry", "entryServerId": l.entry, "nodeId": l.nodeID,
		"enabled": true, "entryFirewallPolicy": "restricted",
		"entryFirewallSources": "183.129.141.26",
	})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	stored := l.forwards(l.entry)
	if len(stored) != 2 {
		t.Fatalf("expected TCP and UDP entry forwards: %+v", stored)
	}
	for _, f := range stored {
		if f.FirewallPolicy != "manual" || f.FirewallSources != "" {
			t.Fatalf("stored %s forward claimed automatic protection: %+v", f.Network, f)
		}
	}
	state, err := l.p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Forwards) != 2 {
		t.Fatalf("expected TCP and UDP in desired state: %+v", state.Forwards)
	}
	for _, f := range state.Forwards {
		if f.FirewallPolicy != "manual" || f.FirewallSources != "" {
			t.Fatalf("desired %s forward claimed automatic protection: %+v", f.Network, f)
		}
	}
}
