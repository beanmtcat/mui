package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// list performs an authenticated GET that answers with a JSON array.
func (p *testMui) list(path string) []map[string]any {
	p.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		p.t.Fatalf("GET %s: %d %v %s", path, rec.Code, err, rec.Body.String())
	}
	return out
}

func TestLogsArePagedAndFiltered(t *testing.T) {
	p := newTestMui(t)
	idA, agentA := p.enroll("a")
	idB, agentB := p.enroll("b")
	p.newAgent(agentA)
	p.newAgent(agentB)
	for i := 0; i < 5; i++ {
		for _, id := range []string{idA, idB} {
			if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 8000 + i, "portTo": 8000 + i, "network": "tcp", "action": "allow", "comment": "50%_rule"}, nil); code != 201 {
				t.Fatalf("rule: %d %v", code, out)
			}
		}
	}

	// Walk a filtered log three rows at a time and expect every row exactly once.
	walk := func(path, cursorKey string) []map[string]any {
		t.Helper()
		all := []map[string]any{}
		seen := map[string]bool{}
		next := path
		for range 20 {
			page := p.list(next)
			for _, row := range page {
				key := row["id"].(string)
				if seen[key] {
					t.Fatalf("%s returned %s twice", path, key)
				}
				seen[key] = true
				all = append(all, row)
			}
			if len(page) < 3 {
				return all
			}
			next = path + "&" + cursorKey + "=" + page[len(page)-1]["id"].(string)
		}
		t.Fatalf("%s never ended", path)
		return nil
	}
	ops := walk("/api/operations?limit=3&serverId="+idA, "before")
	if len(ops) != 5 {
		t.Fatalf("operations for one server: %d", len(ops))
	}
	for i, op := range ops {
		if op["serverId"] != idA || (i > 0 && op["id"].(string) >= ops[i-1]["id"].(string)) {
			t.Fatalf("operations out of order or unfiltered: %v", ops)
		}
	}
	if all := p.list("/api/operations"); len(all) != 10 {
		t.Fatalf("unpaged operations: %d", len(all))
	}

	if rules := walk("/api/audit?limit=3&q=firewall.create", "before"); len(rules) != 10 {
		t.Fatalf("audit entries for firewall.create: %d", len(rules))
	}
	// The search text is matched literally: % and _ are not wildcards.
	if hits := p.list("/api/audit?q=" + "50%25_rule"); len(hits) != 10 {
		t.Fatalf("literal search: %d", len(hits))
	}
	if hits := p.list("/api/audit?q=" + "5%25rule"); len(hits) != 0 {
		t.Fatalf("%% acted as a wildcard: %d", len(hits))
	}

	// Subscription downloads, filtered by customer.
	_, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": idA, "name": "n", "protocol": "ss", "port": 50001}, nil)
	_, customer, _ := p.do("POST", "/api/customers", map[string]string{"name": "Alice"}, nil)
	_, mine, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "mine", "format": "sing-box", "nodeIds": []string{node["id"].(string)}, "customerId": customer["id"]}, nil)
	_, other, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "other", "format": "sing-box", "nodeIds": []string{node["id"].(string)}}, nil)
	p.applyAll(agentA)
	for i := 0; i < 4; i++ {
		for _, sub := range []map[string]any{mine, other} {
			if code, body := p.fetch(strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")); code != 200 {
				t.Fatalf("download: %d %s", code, body)
			}
		}
	}
	accesses := walk("/api/clients/accesses?limit=3&customerId="+customer["id"].(string), "before")
	if len(accesses) != 4 {
		t.Fatalf("accesses for one customer: %d", len(accesses))
	}

	// An IP seen again between pages must not move across the cursor.
	points := []map[string]string{}
	for i := 0; i < 7; i++ {
		points = append(points, map[string]string{"nodeId": node["id"].(string), "ip": "203.0.113." + string(rune('1'+i))})
	}
	p.do("POST", "/agent/report", map[string]any{"connections": points}, agentA)
	first := p.list("/api/clients/connections?limit=4&serverId=" + idA)
	p.do("POST", "/agent/report", map[string]any{"connections": []map[string]string{points[0]}}, agentA)
	rest := p.list("/api/clients/connections?limit=4&before=" + first[len(first)-1]["cursor"].(string) + "&serverId=" + idA)
	ips := map[string]bool{}
	for _, row := range append(first, rest...) {
		ips[row["ip"].(string)] = true
	}
	if len(first) != 4 || len(rest) != 3 || len(ips) != 7 {
		t.Fatalf("connection pages: %d + %d rows, %d distinct", len(first), len(rest), len(ips))
	}
	if none := p.list("/api/clients/connections?serverId=" + idB); len(none) != 0 {
		t.Fatalf("connections leaked across servers: %v", none)
	}
	if code, _, _ := p.do("GET", "/api/clients/connections?before=bad-cursor", nil, nil); code != 400 {
		t.Fatalf("invalid connection cursor accepted: %d", code)
	}
}
