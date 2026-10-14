package agent

import (
	"reflect"
	"testing"

	"mui/internal/shared"
)

const (
	nodeA = "18dd63118f52e9d88c06e4ab51265671c95f"
	nodeB = "18dd63118f52e9d88c06e4ab51265671c960"
	ruleA = "18dd63118f52e9d88c06e4ab51265671c950"
	ruleZ = "18dd63118f52e9d88c06e4ab51265671c999"
)

func ids(rules []shared.FirewallRule) []string {
	out := []string{}
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func TestForwardUFWRestrictedSource(t *testing.T) {
	state := shared.DesiredState{Forwards: []shared.ForwardRule{{ID: "forward-id", Name: "relay", Network: "tcp", Port: 51000, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "192.0.2.1/32"}}}
	rules := ownedRules(state)
	if len(rules) != 1 || rules[0].Network != "tcp" || rules[0].PortFrom != 51000 || rules[0].Source != "192.0.2.1/32" || !restrictedNodesNeedDeny(state) {
		t.Fatalf("forward UFW rules: %+v", rules)
	}
}

func TestOwnedRulesOrder(t *testing.T) {
	state := shared.DesiredState{
		Nodes: []shared.ManagedNode{
			{Node: shared.Node{ID: nodeB, Protocol: "snell", Port: 444, Enabled: true}},
			{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true}},
			{Node: shared.Node{ID: "disabled", Protocol: "ss", Port: 1, Enabled: false}},
		},
		Rules: []shared.FirewallRule{
			{ID: ruleZ, Action: "deny", Network: "tcp", PortFrom: 25, PortTo: 25},
			{ID: ruleA, Action: "allow", Network: "tcp", PortFrom: 80, PortTo: 80},
		},
	}
	want := []string{ruleZ, ruleA, "node-" + nodeA + "-tcp-8388", "node-" + nodeA + "-udp-8388", "node-" + nodeB + "-tcp-444"}
	if got := ids(ownedRules(state)); !reflect.DeepEqual(got, want) {
		t.Fatalf("order:\n got %v\nwant %v", got, want)
	}
}

func TestOwnedRulesRestrictNodeSources(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{
		{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "203.0.113.7/32,2001:db8::/32"}},
		{Node: shared.Node{ID: nodeB, Protocol: "snell", Port: 444, Enabled: true, FirewallPolicy: "manual"}},
	}}
	rules := ownedRules(state)
	if len(rules) != 4 {
		t.Fatalf("restricted SS needs TCP/UDP per source; got %v", rules)
	}
	for i, source := range []string{"203.0.113.7/32", "2001:db8::/32"} {
		if rules[i*2].Source != source || rules[i*2].Network != "tcp" || rules[i*2+1].Source != source || rules[i*2+1].Network != "udp" {
			t.Fatalf("source %d rules: %+v %+v", i, rules[i*2], rules[i*2+1])
		}
		if rules[i*2].ID == "node-"+nodeA+"-tcp-8388" {
			t.Fatal("unrestricted rule survived restricted mode")
		}
	}
	if rules[0].ID == rules[2].ID {
		t.Fatal("different sources shared a rule ID")
	}
	remove, _ := planUFW([]ufwLine{{Index: 1, ID: "node-" + nodeA + "-tcp-8388"}}, ids(rules))
	if !remove["node-"+nodeA+"-tcp-8388"] {
		t.Fatal("old unrestricted rule was not removed")
	}
}

func TestRestrictedNodesRequireDefaultDeny(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{{Node: shared.Node{Enabled: true, FirewallPolicy: "restricted"}}}}
	if !restrictedNodesNeedDeny(state) || !defaultIncomingDeny.MatchString("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n") {
		t.Fatal("restricted node did not require default deny")
	}
	if defaultIncomingDeny.MatchString("Status: active\nDefault: allow (incoming), allow (outgoing)\n") {
		t.Fatal("default allow was accepted")
	}
	state.Nodes[0].Node.Enabled = false
	if restrictedNodesNeedDeny(state) {
		t.Fatal("disabled node required UFW default deny")
	}
}

func TestParseMuiLines(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # mui-ssh
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # my mui-web note
[ 3] 8388/tcp                   ALLOW IN    Anywhere                   # mui-node-x-tcp-8388
[ 4] 443                        ALLOW IN    Anywhere
[12] 8388/tcp (v6)              ALLOW IN    Anywhere (v6)              # mui-node-x-tcp-8388
`
	want := []ufwLine{{3, "node-x-tcp-8388"}, {12, "node-x-tcp-8388"}}
	if got := parseMuiLines(status); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseLegacyLines(t *testing.T) {
	status := "[ 1] 22/tcp ALLOW IN Anywhere # panel-ssh\n[ 2] 8388/tcp ALLOW IN Anywhere # panel-node-x-tcp-8388\n"
	want := []ufwLine{{2, "node-x-tcp-8388"}}
	if got := parseLegacyLines(status); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLegacyRulesRemainManaged(t *testing.T) {
	status := "[ 1] 8388/tcp ALLOW IN Anywhere # panel-node-kept-tcp-8388\n[ 2] 9443/tcp ALLOW IN Anywhere # panel-node-removed-tcp-9443\n"
	present := parseLegacyLines(status)
	remove, add := planUFW(present, []string{"node-kept-tcp-8388"})
	if !remove["node-removed-tcp-9443"] || remove["node-kept-tcp-8388"] || len(add) != 0 {
		t.Fatalf("legacy rules were not reconciled safely: remove=%v add=%v", remove, add)
	}
}

func TestPlanUFW(t *testing.T) {
	lines := func(ids ...string) []ufwLine {
		out := []ufwLine{}
		for i, id := range ids {
			out = append(out, ufwLine{Index: i + 1, ID: id})
		}
		return out
	}
	cases := []struct {
		name       string
		present    []ufwLine
		desired    []string
		wantRemove []string
		wantAdd    []string
	}{
		{"unchanged rules are not touched", lines("a", "b", "a", "b"), []string{"a", "b"}, nil, []string{}},
		{"new rule is appended", lines("a", "b"), []string{"a", "b", "c"}, nil, []string{"c"}},
		{"removed rule leaves the others in place", lines("a", "b", "c"), []string{"a", "c"}, []string{"b"}, []string{}},
		{"reordering rebuilds everything", lines("a", "b"), []string{"x", "a", "b"}, []string{"a", "b"}, []string{"x", "a", "b"}},
		{"empty host gets all rules", nil, []string{"a"}, nil, []string{"a"}},
		{"nothing desired removes all", lines("a"), nil, []string{"a"}, nil},
	}
	for _, c := range cases {
		remove, add := planUFW(c.present, c.desired)
		wantRemove := map[string]bool{}
		for _, id := range c.wantRemove {
			wantRemove[id] = true
		}
		if !reflect.DeepEqual(remove, wantRemove) || len(add) != len(c.wantAdd) || (len(add) > 0 && !reflect.DeepEqual(add, c.wantAdd)) {
			t.Errorf("%s: remove %v add %v", c.name, remove, add)
		}
	}
}

func TestNewListeners(t *testing.T) {
	node := func(id string, port int, enabled bool) shared.ManagedNode {
		return shared.ManagedNode{Node: shared.Node{ID: id, Port: port, Enabled: enabled}}
	}
	current := shared.DesiredState{Nodes: []shared.ManagedNode{node("a", 1000, true), node("b", 2000, false)}}
	next := shared.DesiredState{Nodes: []shared.ManagedNode{node("a", 1000, true), node("b", 2000, true), node("c", 3000, true), node("d", 4000, false)}}
	got := []int{}
	for _, n := range newListeners(current, next) {
		got = append(got, n.Port)
	}
	if !reflect.DeepEqual(got, []int{2000, 3000}) {
		t.Fatalf("ports to probe: %v", got)
	}
}

func TestOwnedRulesTrailingCommaAndEmptySegments(t *testing.T) {
	for _, sources := range []string{"203.0.113.7/32,", "203.0.113.7/32,, 2001:db8::/32"} {
		state := shared.DesiredState{Nodes: []shared.ManagedNode{
			{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true, FirewallPolicy: "restricted", FirewallSources: sources}},
		}}
		rules := ownedRules(state)
		for _, rule := range rules {
			if rule.Source == "" {
				t.Fatalf("sources %q produced an empty-source rule: %+v", sources, rules)
			}
		}
		want := []string{"203.0.113.7/32"}
		if sources == "203.0.113.7/32,, 2001:db8::/32" {
			want = append(want, "2001:db8::/32")
		}
		if len(rules) != len(want)*2 {
			t.Fatalf("sources %q: got %d rules, want %d: %+v", sources, len(rules), len(want)*2, rules)
		}
		for i, source := range want {
			if rules[i*2].Source != source || rules[i*2+1].Source != source {
				t.Fatalf("sources %q: rule pair %d sources %q/%q, want %q", sources, i, rules[i*2].Source, rules[i*2+1].Source, source)
			}
		}
	}
}

func TestOwnedRulesUnknownPolicy(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{
		{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true, FirewallPolicy: "wide-open", FirewallSources: "203.0.113.7/32"}},
	}}
	if err := ownedRulesError(state); err == nil {
		t.Fatal("unknown firewall policy was accepted")
	}
	if rules := ownedRules(state); len(rules) != 0 {
		t.Fatalf("unknown policy generated rules: %+v", rules)
	}
}

func TestOwnedRulesUnknownAction(t *testing.T) {
	state := shared.DesiredState{Rules: []shared.FirewallRule{
		{ID: ruleA, Action: "block", Network: "tcp", PortFrom: 80, PortTo: 80},
	}}
	if err := ownedRulesError(state); err == nil {
		t.Fatal("unknown rule action was accepted")
	}
	if rules := ownedRules(state); len(rules) != 0 {
		t.Fatalf("unknown action generated rules: %+v", rules)
	}
}

func TestOwnedRulesPortBounds(t *testing.T) {
	for _, port := range []int{0, 65536} {
		state := shared.DesiredState{Rules: []shared.FirewallRule{
			{ID: ruleA, Action: "allow", Network: "tcp", PortFrom: port, PortTo: port},
		}}
		if err := ownedRulesError(state); err == nil {
			t.Fatalf("port %d was accepted", port)
		}
		state = shared.DesiredState{Nodes: []shared.ManagedNode{
			{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: port, Enabled: true}},
		}}
		if err := ownedRulesError(state); err == nil {
			t.Fatalf("node port %d was accepted", port)
		}
		if rules := ownedRules(state); len(rules) != 0 {
			t.Fatalf("node port %d generated rules: %+v", port, rules)
		}
	}
}

func TestOwnedRulesInvalidCIDR(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{
		{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "203.0.113.7/32, not-a-cidr"}},
	}}
	if err := ownedRulesError(state); err == nil {
		t.Fatal("invalid CIDR was accepted")
	}
	// Fail-closed per segment: the valid source still gets its rules.
	rules := ownedRules(state)
	if len(rules) != 2 {
		t.Fatalf("invalid segment dropped the whole node: %+v", rules)
	}
	for _, rule := range rules {
		if rule.Source != "203.0.113.7/32" {
			t.Fatalf("invalid segment leaked into rules: %+v", rules)
		}
	}
}

func TestOwnedRulesDuplicateSource(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{
		{Node: shared.Node{ID: nodeA, Protocol: "ss", Port: 8388, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "203.0.113.7/32,203.0.113.7/32"}},
	}}
	rules := ownedRules(state)
	if len(rules) != 2 {
		t.Fatalf("duplicate source generated %d rules, want 2: %+v", len(rules), rules)
	}
	if rules[0].ID == rules[1].ID {
		t.Fatalf("duplicate rule IDs: %+v", rules)
	}
}
