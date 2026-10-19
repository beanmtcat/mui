package server

import (
	"testing"
)

var testHostRules = []string{
	"[ 1] 22/tcp                     ALLOW IN    Anywhere                   # mui-ssh",
	"[ 2] 8080                       ALLOW IN    Anywhere",
	"[ 3] 9000/tcp                   ALLOW IN    203.0.113.0/24",
	"[ 4] 8080 (v6)                  ALLOW IN    Anywhere (v6)",
	"[ 5] 2222/tcp                   ALLOW IN    Anywhere",
}

func hostRuleServer(t *testing.T) (*testMui, string, map[string]string) {
	p := newTestMui(t)
	id, agent := p.enroll("host-rules")
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0", "hostReported": true, "ufwStatus": "active",
		"sshPorts": []int{22, 2222}, "ufwRules": testHostRules}, agent); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	return p, id, agent
}

func TestHostRuleDeleteQueuesSignedJob(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	// Three lines in one job. The IPv6 line is its own rule.
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/delete", map[string]any{"rules": []string{
		"8080                       ALLOW IN    Anywhere", "8080 (v6)                  ALLOW IN    Anywhere (v6)", "9000/tcp                   ALLOW IN    203.0.113.0/24",
	}}, nil); code != 202 || out["queued"] != float64(3) {
		t.Fatalf("delete: %d %v", code, out)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "ufw.delete" {
		t.Fatalf("job: %d %v", code, job)
	}
	state := job["state"].(map[string]any)
	if rules, _ := state["hostRules"].([]any); len(rules) != 3 || state["signature"] == "" {
		t.Fatalf("the job must carry the three lines, signed: %v", state)
	}
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code == 200 {
		t.Fatal("a batch must be one job")
	}
	for rule, why := range map[string]string{
		"22/tcp                     ALLOW IN    Anywhere                   # mui-ssh": "panel rule",
		"2222/tcp                   ALLOW IN    Anywhere":                             "SSH port",
		"7777/tcp                   ALLOW IN    Anywhere":                             "unknown rule",
	} {
		// One bad rule refuses the whole batch.
		if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/delete", map[string]any{"rules": []string{"8080                       ALLOW IN    Anywhere", rule}}, nil); code != 409 {
			t.Fatalf("%s accepted: %d %v", why, code, out)
		}
	}
}

func TestHostRuleConvertsToCustomRule(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	code, rule, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9000, "portTo": 9000, "network": "tcp", "source": "198.51.100.0/24",
		"action": "allow", "comment": "monitoring", "replaceHostRule": "9000/tcp                   ALLOW IN    203.0.113.0/24"}, nil)
	if code != 201 {
		t.Fatalf("convert: %d %v", code, rule)
	}
	// The host rule goes first, so the apply's check for unmanaged rules on
	// managed ports does not trip over it.
	first := p.applyNext(agent, "success")
	if first["kind"] != "ufw.delete" {
		t.Fatalf("first job: %v", first["kind"])
	}
	if second := p.applyNext(agent, "success"); second["kind"] != "firewall.apply" {
		t.Fatalf("second job: %v", second["kind"])
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 2222, "portTo": 2222, "network": "tcp", "action": "allow",
		"replaceHostRule": "2222/tcp                   ALLOW IN    Anywhere"}, nil); code != 409 {
		t.Fatalf("converting an SSH rule: %d %v", code, out)
	}
}

func TestCustomRuleEditReplacesTheRule(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	code, rule, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9100, "portTo": 9100, "network": "tcp", "action": "allow"}, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, rule)
	}
	p.applyAll(agent)
	code, edited, _ := p.do("PATCH", "/api/firewall/"+rule["id"].(string), map[string]any{"portFrom": 9100, "portTo": 9101, "network": "udp", "action": "allow", "comment": "x"}, nil)
	if code != 200 || edited["id"] == rule["id"] || edited["portTo"] != float64(9101) {
		t.Fatalf("edit: %d %v", code, edited)
	}
	state, err := p.app.desired(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Rules) != 1 || state.Rules[0].ID != edited["id"] || state.Rules[0].Network != "udp" {
		t.Fatalf("the apply must carry only the new rule: %+v", state.Rules)
	}
	p.applyAll(agent)
	if rules, _ := p.store.Rules(id); len(rules) != 1 || rules[0].ID != edited["id"] || rules[0].Status != "active" {
		t.Fatalf("after apply: %+v", rules)
	}
	if code, out, _ := p.do("PATCH", "/api/firewall/"+edited["id"].(string), map[string]any{"portFrom": 22, "portTo": 22, "network": "tcp", "action": "deny"}, nil); code != 400 {
		t.Fatalf("deny on SSH: %d %v", code, out)
	}
}

func TestHostRulesAdoptedInOneBatch(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/adopt", map[string]any{"rules": []string{"9000/tcp                   ALLOW IN    203.0.113.0/24"}}, nil)
	if code != 201 {
		t.Fatalf("adopt: %d %v", code, out)
	}
	if first := p.applyNext(agent, "success"); first["kind"] != "ufw.delete" {
		t.Fatalf("first job: %v", first["kind"])
	}
	if second := p.applyNext(agent, "success"); second["kind"] != "firewall.apply" {
		t.Fatalf("second job: %v", second["kind"])
	}
	rules, _ := p.store.Rules(id)
	if len(rules) != 1 || rules[0].PortFrom != 9000 || rules[0].Network != "tcp" || rules[0].Source != "203.0.113.0/24" || rules[0].Action != "allow" || rules[0].Status != "active" {
		t.Fatalf("adopted rule: %+v", rules)
	}
	// A rule a custom rule cannot express refuses the batch before anything is queued.
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/adopt", map[string]any{"rules": []string{"8080                       ALLOW IN    Anywhere"}}, nil); code != 409 {
		t.Fatalf("adopting a TCP+UDP rule: %d %v", code, out)
	}
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code == 200 {
		t.Fatal("a refused batch must queue nothing")
	}
}

// Deleting only the IPv6 line of a rule leaves its IPv4 line: the job names
// that one line, and converting it yields an IPv6-only rule.
func TestHostRuleIPv6LineStandsAlone(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	v6 := "8080 (v6)                  ALLOW IN    Anywhere (v6)"
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/delete", map[string]any{"rules": []string{v6}}, nil); code != 202 || out["queued"] != float64(1) {
		t.Fatalf("delete v6: %d %v", code, out)
	}
	_, job, _ := p.do("GET", "/agent/job", nil, agent)
	if rules := job["state"].(map[string]any)["hostRules"].([]any); len(rules) != 1 || rules[0] != v6 {
		t.Fatalf("only the IPv6 line may be removed: %v", rules)
	}
}

func TestCustomRuleFamily(t *testing.T) {
	p, id, _ := hostRuleServer(t)
	code, rule, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9500, "portTo": 9500, "network": "tcp", "action": "allow", "family": "ipv6"}, nil)
	if code != 201 || rule["family"] != "ipv6" {
		t.Fatalf("ipv6 rule: %d %v", code, rule)
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9501, "portTo": 9501, "network": "tcp", "action": "allow", "family": "ipv6", "source": "203.0.113.0/24"}, nil); code != 400 {
		t.Fatalf("IPv4 source on an IPv6 rule: %d %v", code, out)
	}
	state, err := p.app.desired(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Rules) != 1 || state.Rules[0].Family != "ipv6" {
		t.Fatalf("desired rules: %+v", state.Rules)
	}
}
