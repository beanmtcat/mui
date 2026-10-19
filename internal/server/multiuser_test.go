package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestOldAgentApplyDoesNotPublishUninstalledSubscriptionCredential(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("old-agent")
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss", "port": 50011, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyNext(agent, "success")
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "client", "format": "sing-box", "nodeIds": []string{node["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	// A later node apply may record its desired user list even when the old
	// Agent cannot install multi-user credentials.
	if err := p.app.queueApply(serverID, "nodes.apply"); err != nil {
		t.Fatal(err)
	}
	p.applyNext(agent, "success")
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("old Agent published an unusable subscription: HTTP %d", code)
	}
}

func TestSubscriptionUsersAndTraffic(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("users")
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "test", "multiUserStats": true, "nodeFirewallPolicies": true, "ufwStatus": "active"}, agent)
	if code != 200 {
		t.Fatalf("capability: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss", "port": 50001, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	p.applyNext(agent, "success")
	create := func(name string) map[string]any {
		code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": name, "format": "sing-box", "nodeIds": []string{nodeID}}, nil)
		if code != 201 {
			t.Fatalf("subscription %s: %d %v", name, code, sub)
		}
		return sub
	}
	a, b := create("Alice"), create("Bob")
	node["method"] = "invalid-method"
	code, out, _ = p.do("PATCH", "/api/nodes/"+nodeID, node, nil)
	if code != 400 {
		t.Fatalf("subscribed node accepted invalid SS method: %d %v", code, out)
	}
	job := p.applyNext(agent, "success")
	state := job["state"].(map[string]any)
	users := state["nodes"].([]any)[0].(map[string]any)["users"].([]any)
	if len(users) != 3 {
		t.Fatalf("direct and two subscription users: %v", users)
	}
	passwords := map[string]string{}
	for _, user := range users {
		u := user.(map[string]any)
		passwords[u["subscriptionId"].(string)] = u["password"].(string)
	}
	if passwords[a["id"].(string)] == passwords[b["id"].(string)] {
		t.Fatal("subscriptions share a credential")
	}
	for _, sub := range []map[string]any{a, b} {
		path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
		code, body, _ := p.do("GET", path, nil, nil)
		if code != 200 {
			t.Fatalf("download: %d %v", code, body)
		}
		pass := body["outbounds"].([]any)[0].(map[string]any)["password"].(string)
		parts := strings.Split(pass, ":")
		if len(parts) != 2 || parts[1] != passwords[sub["id"].(string)] {
			t.Fatalf("incorrect SS user key: %q", pass)
		}
		if key, err := base64.StdEncoding.DecodeString(parts[1]); err != nil || len(key) != 16 {
			t.Fatalf("invalid SS 2022 key: %q %v", pass, err)
		}
	}
	points := []shared.UserTrafficPoint{
		{NodeID: nodeID, SubscriptionID: a["id"].(string), InstanceID: "core-1", Sequence: 1, Uplink: 100, Downlink: 200, At: time.Now()},
		{NodeID: nodeID, SubscriptionID: b["id"].(string), InstanceID: "core-1", Sequence: 2, Uplink: 300, Downlink: 400, At: time.Now()},
	}
	for i := 0; i < 2; i++ { // Re-sent batches must be idempotent.
		code, out, _ = p.do("POST", "/agent/report", map[string]any{"userTraffic": points}, agent)
		if code != 200 {
			t.Fatalf("traffic report: %d %v", code, out)
		}
	}
	reqList := httptest.NewRequest("GET", "/api/subscriptions", nil)
	reqList.AddCookie(p.cookie)
	recList := httptest.NewRecorder()
	p.handler.ServeHTTP(recList, reqList)
	var apiSubs []shared.Subscription
	if recList.Code != 200 || json.Unmarshal(recList.Body.Bytes(), &apiSubs) != nil || len(apiSubs) != 2 {
		t.Fatalf("subscription totals API: %d %s", recList.Code, recList.Body.String())
	}
	for _, item := range apiSubs {
		if item.ID == a["id"] && (item.Uplink != 100 || item.Downlink != 200) {
			t.Fatalf("Alice API total: %+v", item)
		}
		if item.ID == b["id"] && (item.Uplink != 300 || item.Downlink != 400) {
			t.Fatalf("Bob API total: %+v", item)
		}
	}
	list, err := p.store.Subscriptions()
	if err != nil || len(list) != 2 {
		t.Fatalf("subscriptions: %v %v", list, err)
	}
	var total int64
	if err = p.store.DB.QueryRow(`SELECT SUM(uplink+downlink) FROM mui_user_totals WHERE subscription_id=$1`, a["id"].(string)).Scan(&total); err != nil || total != 300 {
		t.Fatalf("Alice traffic: %d %v", total, err)
	}
	if err = p.store.DB.QueryRow(`SELECT SUM(uplink+downlink) FROM mui_user_totals WHERE subscription_id=$1`, b["id"].(string)).Scan(&total); err != nil || total != 700 {
		t.Fatalf("Bob traffic: %d %v", total, err)
	}
	req := httptest.NewRequest("GET", "/api/subscriptions/"+a["id"].(string)+"/traffic/series", nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	var series []map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &series) != nil || len(series) != 24 {
		t.Fatalf("series: %d %s", rec.Code, rec.Body.String())
	}
	code, out, _ = p.do("PATCH", "/api/subscriptions/"+a["id"].(string), map[string]any{"name": "Alice", "format": "sing-box", "nodeIds": []string{nodeID}, "enabled": false}, nil)
	if code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	job = p.applyNext(agent, "success")
	users = job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("disabled user still configured: %v", users)
	}
}

func TestSurgeSubscriptionProtocolSupport(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("snell")
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.11", "multiUserStats": true, "nodeFirewallPolicies": true, "snellFixedPort": true, "snellV6": true, "ufwStatus": "active"}, agent)
	if code != 200 {
		t.Fatalf("capability: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "Snell", "protocol": "snell", "port": 50002, "shadowTlsHost": "example.com"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	p.applyNext(agent, "success")
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "new sing-box", "format": "sing-box", "nodeIds": []string{nodeID}}, nil)
	if code != 201 {
		t.Fatalf("new subscription: %d %v", code, sub)
	}
	job := p.applyNext(agent, "success")
	n := job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if len(n["users"].([]any)) != 1 {
		t.Fatalf("Snell user not configured: %v", n)
	}
	// Reached through ShadowTLS, a Snell node works with Surge; this agent is an
	// older one, though, and still demands a per-user Snell key Surge cannot send.
	code, surge, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "new Surge", "format": "surge", "nodeIds": []string{nodeID}}, nil)
	if code != 201 {
		t.Fatalf("Surge subscription with a ShadowTLS Snell node: %d %v", code, surge)
	}
	p.applyAll(agent)
	code, preview, _ := p.do("GET", "/api/subscriptions/"+surge["id"].(string)+"/preview", nil, nil)
	if code != 200 || strings.Contains(preview["content"].(string), "snell") || len(preview["excluded"].([]any)) != 1 {
		t.Fatalf("Snell offered to Surge through an agent that requires a user key: %d %v", code, preview)
	}
	p.newAgent(agent)
	p.applyAll(agent)
	code, preview, _ = p.do("GET", "/api/subscriptions/"+surge["id"].(string)+"/preview", nil, nil)
	if code != 200 || !strings.Contains(preview["content"].(string), "shadow-tls-password=") {
		t.Fatalf("Surge Snell line after the agent upgrade: %d %v", code, preview)
	}
}

func TestSubscriptionAlwaysUsesIndependentCredential(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("subscriber")
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.5.0", "multiUserStats": true, "ufwStatus": "active", "nodeFirewallPolicies": true}, agent)
	if code != 200 {
		t.Fatalf("Agent: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss", "port": 50004, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyNext(agent, "success")
	nodeID := node["id"].(string)
	sub := shared.Subscription{ID: ID(), Name: "subscriber", Format: "sing-box", NodeIDs: []string{nodeID}, Enabled: true}
	token := Token()
	if _, err := p.store.DB.Exec(`INSERT INTO mui_subscriptions(id,data,token_hash) VALUES($1,$2,$3)`, sub.ID, Marshal(sub), Hash(token)); err != nil {
		t.Fatal(err)
	}
	if err := p.app.queueSubscriptionApply(sub.NodeIDs); err != nil {
		t.Fatal(err)
	}
	p.applyNext(agent, "success")
	code, body, _ := p.do("GET", "/s/"+token, nil, nil)
	if code != 200 {
		t.Fatalf("download: %d %v", code, body)
	}
	password := body["outbounds"].([]any)[0].(map[string]any)["password"].(string)
	secret, _ := p.store.NodeSecret(nodeID)
	if !strings.HasPrefix(password, secret+":") || strings.TrimPrefix(password, secret+":") != p.store.SubscriptionUser(shared.Node{ID: nodeID, Protocol: "ss", Method: "2022-blake3-aes-128-gcm"}, sub.ID).Password {
		t.Fatalf("subscription did not get an independent key: %q", password)
	}
}

func TestSubscriptionExpiryRemovesNodeUser(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("expiry")
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.5.0", "multiUserStats": true, "nodeFirewallPolicies": true, "ufwStatus": "active"}, agent)
	if code != 200 {
		t.Fatalf("Agent: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss", "port": 50005, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyNext(agent, "success")
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "short", "format": "sing-box", "nodeIds": []string{node["id"].(string)}, "expiresAt": time.Now().Add(time.Hour)}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	job := p.applyNext(agent, "success")
	if len(job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["users"].([]any)) != 2 {
		t.Fatal("user not initially configured")
	}
	list, err := p.store.Subscriptions()
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	list[0].ExpiresAt = &expired
	if _, err = p.store.DB.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(list[0]), list[0].ID); err != nil {
		t.Fatal(err)
	}
	job = p.applyNext(agent, "success")
	if len(job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["users"].([]any)) != 1 {
		t.Fatal("expired user remained configured")
	}
}

func TestSubscriptionKeyLengths(t *testing.T) {
	p := newTestMui(t)
	for method, size := range map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32, "2022-blake3-chacha20-poly1305": 32} {
		n := shared.Node{ID: "node", Protocol: "ss", Method: method}
		a := p.store.SubscriptionUser(n, "a")
		b := p.store.SubscriptionUser(n, "b")
		key, err := base64.StdEncoding.DecodeString(a.Password)
		if err != nil || len(key) != size || a.Password == b.Password {
			t.Fatalf("%s user key: %q %v", method, a.Password, err)
		}
	}
}

func TestSnellAndAnyTLSSubscriptionCredentials(t *testing.T) {
	p := newTestMui(t)
	server := shared.Server{ID: "server", IPv4: "192.0.2.1", AppliedRevision: 1, ShadowTLSAuth: true}
	for _, protocol := range []string{"snell", "anytls"} {
		node := shared.Node{ID: protocol, ServerID: server.ID, Name: protocol, Protocol: protocol, Port: 50000, Enabled: true, Status: "active", ShadowTLSHost: "example.com", TLSName: "example.com"}
		if protocol == "anytls" {
			node.ShadowTLSHost = ""
		}
		if err := p.store.PutNodeWithShadowTLS(node, "legacy-secret", "legacy-outer"); err != nil {
			t.Fatal(err)
		}
		first := shared.Subscription{ID: protocol + "-a"}
		second := shared.Subscription{ID: protocol + "-b"}
		a, err := p.app.subscriptionItem(first, node, server)
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.app.subscriptionItem(second, node, server)
		if err != nil {
			t.Fatal(err)
		}
		if protocol == "snell" {
			if a.Password != "legacy-secret" || a.ShadowTLSPassword == "" || a.ShadowTLSPassword == b.ShadowTLSPassword || a.ShadowTLSPassword == "legacy-outer" {
				t.Fatalf("Snell credentials not isolated: %+v %+v", a, b)
			}
		} else if a.Password == "legacy-secret" || a.Password == b.Password {
			t.Fatalf("AnyTLS credentials not isolated: %+v %+v", a, b)
		}
		config, excluded, err := shared.RenderSubscription("sing-box", []shared.SubscriptionItem{a})
		if err != nil || len(excluded) != 0 {
			t.Fatalf("%s subscription: %s %v %v", protocol, config, excluded, err)
		}
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal(config, &doc); err != nil || len(doc.Outbounds) == 0 {
			t.Fatalf("%s subscription JSON: %s %v", protocol, config, err)
		}
		if protocol == "snell" && (doc.Outbounds[0]["userkey"] != nil || doc.Outbounds[1]["password"] != a.ShadowTLSPassword) {
			t.Fatalf("Snell must be authenticated by the ShadowTLS password alone: %s", config)
		}
		if protocol == "anytls" && doc.Outbounds[0]["password"] != a.Password {
			t.Fatalf("AnyTLS user password missing: %s", config)
		}
	}
}
