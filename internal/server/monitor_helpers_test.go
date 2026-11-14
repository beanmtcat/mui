package server

import "testing"

func enrollMonitorTestServer(t *testing.T, p *testMui, name string) (string, string, map[string]string) {
	t.Helper()
	code, out, _ := p.do("POST", "/api/servers", map[string]any{
		"name":    name,
		"roles":   []string{"exit"},
		"country": "JP",
		"ipv4":    "203.0.113.10",
	}, nil)
	if code != 201 {
		t.Fatalf("create server %s: %d %v", name, code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": id,
		"token":    out["enrollToken"].(string),
	}, nil)
	if code != 200 {
		t.Fatalf("enroll server %s: %d %v", name, code, enrolled)
	}
	token := enrolled["agentToken"].(string)
	return id, token, map[string]string{
		"X-Server-ID":   id,
		"Authorization": "Bearer " + token,
	}
}
