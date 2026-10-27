package shared

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestParseUFWLine(t *testing.T) {
	for _, tc := range []struct {
		line          string
		ok            bool
		action, tag   string
		from, to      int
		protos        []string
		allPorts      bool
		app           string
		admitsSSHon22 bool
	}{
		{line: "[ 1] 22/tcp                     ALLOW IN    Anywhere                   # mui-ssh", ok: true, action: "ALLOW", tag: "mui-ssh", from: 22, to: 22, protos: []string{"tcp"}, admitsSSHon22: true},
		{line: "[ 2] 8000:8010/udp              DENY IN     203.0.113.0/24", ok: true, action: "DENY", from: 8000, to: 8010, protos: []string{"udp"}},
		{line: "[ 3] 8080                       ALLOW IN    Anywhere", ok: true, action: "ALLOW", from: 8080, to: 8080, protos: []string{"tcp", "udp"}},
		{line: "[ 4] 8080 (v6)                  ALLOW IN    Anywhere (v6)", ok: true, action: "ALLOW", from: 8080, to: 8080, protos: []string{"tcp", "udp"}},
		{line: "[ 5] Anywhere                   ALLOW IN    10.0.0.0/8", ok: true, action: "ALLOW", allPorts: true, admitsSSHon22: true},
		{line: "[ 6] OpenSSH                    ALLOW IN    Anywhere", ok: true, action: "ALLOW", app: "OpenSSH", admitsSSHon22: true},
		{line: "[ 7] 20:30/tcp                  LIMIT IN    Anywhere", ok: true, action: "LIMIT", from: 20, to: 30, protos: []string{"tcp"}, admitsSSHon22: true},
		{line: "Status: active"},
		{line: "[ x] 22/tcp ALLOW IN Anywhere"},
	} {
		got, ok := ParseUFWLine(tc.line)
		if ok != tc.ok {
			t.Fatalf("%q: ok=%v", tc.line, ok)
		}
		if !ok {
			continue
		}
		if got.Action != tc.action || got.Tag != tc.tag || got.PortFrom != tc.from || got.PortTo != tc.to || !slices.Equal(got.Protos, tc.protos) || got.AllPorts != tc.allPorts || got.App != tc.app {
			t.Fatalf("%q: %+v", tc.line, got)
		}
		if got.AdmitsSSH([]int{22}) != tc.admitsSSHon22 {
			t.Fatalf("%q: admits SSH = %v", tc.line, !tc.admitsSSHon22)
		}
	}
	a, _ := ParseUFWLine("[ 3] 8080                       ALLOW IN    Anywhere")
	b, _ := ParseUFWLine("[ 4] 8080 (v6)                  ALLOW IN    Anywhere (v6)")
	if UFWRuleKey(a.Rule) == UFWRuleKey(b.Rule) || a.V6 || !b.V6 {
		t.Fatal("the IPv6 line of a rule must be told apart from its IPv4 line")
	}
	if UFWRuleKey("8080   ALLOW IN  Anywhere") != UFWRuleKey(a.Rule) {
		t.Fatal("column padding must not change a key")
	}
}

func TestUFWLineCustomRule(t *testing.T) {
	for line, want := range map[string]string{
		"[ 1] 9000/tcp                   ALLOW IN    203.0.113.0/24": "9000-9000 tcp allow 203.0.113.0/24 ipv4",
		"[ 2] 7000:7010/udp              DENY IN     Anywhere":       "7000-7010 udp deny  ipv4",
		"[ 3] 9000/tcp (v6)              ALLOW IN    2001:db8::/32":  "9000-9000 tcp allow 2001:db8::/32 ipv6",
		"[ 7] 7000/udp (v6)              DENY IN     Anywhere (v6)":  "7000-7000 udp deny  ipv6",
		"[ 4] 8080                       ALLOW IN    Anywhere":       "8080-8080 tcp allow  ipv4; 8080-8080 udp allow  ipv4",
		"[ 8] 8080 (v6)                  ALLOW IN    Anywhere (v6)":  "8080-8080 tcp allow  ipv6; 8080-8080 udp allow  ipv6",
		"[ 5] OpenSSH                    ALLOW IN    Anywhere":       "",
		"[ 6] 9100/tcp                   LIMIT IN    Anywhere":       "",
	} {
		l, ok := ParseUFWLine(line)
		if !ok {
			t.Fatalf("%q did not parse", line)
		}
		rules, ok := l.CustomRules()
		var parts []string
		if ok {
			for _, rule := range rules {
				parts = append(parts, fmt.Sprintf("%d-%d %s %s %s %s", rule.PortFrom, rule.PortTo, rule.Network, rule.Action, rule.Source, rule.Family))
			}
		}
		got := strings.Join(parts, "; ")
		if got != want {
			t.Fatalf("%q: %q, want %q", line, got, want)
		}
	}
}

func TestUncoveredSSHPorts(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # mui-ssh
[ 2] 2200:2210/tcp              ALLOW IN    203.0.113.0/24
[ 3] 3333/udp                   ALLOW IN    Anywhere
[ 4] 4444/tcp                   DENY IN     Anywhere
`
	got := UncoveredSSHPorts(status, []int{22, 2205, 3333, 4444, 5555})
	if !slices.Equal(got, []int{3333, 4444, 5555}) {
		t.Fatalf("uncovered: %v", got)
	}
	if got := UncoveredSSHPorts("[ 1] OpenSSH ALLOW IN Anywhere", []int{22, 2222}); !slices.Equal(got, []int{2222}) {
		t.Fatalf("the OpenSSH profile covers only 22: %v", got)
	}
}

func TestRuleFamilyError(t *testing.T) {
	for _, tc := range []struct {
		family, source string
		ok             bool
	}{
		{"", "", true}, {"ipv4", "", true}, {"ipv6", "", true},
		{"ipv4", "203.0.113.0/24", true}, {"ipv6", "2001:db8::/32", true}, {"", "2001:db8::/32", true},
		{"ipv6", "203.0.113.0/24", false}, {"ipv4", "2001:db8::/32", false}, {"both", "", false},
	} {
		err := RuleFamilyError(FirewallRule{Family: tc.family, Source: tc.source})
		if (err == nil) != tc.ok {
			t.Fatalf("%q %q: %v", tc.family, tc.source, err)
		}
	}
}
