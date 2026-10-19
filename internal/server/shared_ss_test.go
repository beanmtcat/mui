package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestLegacySSDirectAndOfflineRouteSubscriptions(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	entry := createOfflineServer(p, "offline-legacy-entry", "198.51.100.8")
	const password = "legacy-shared-password"
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": l.exit, "name": "legacy-ss", "protocol": "ss", "method": "aes-256-gcm",
		"password": password, "port": 50011, "direct": true,
	}, nil)
	if code != 201 {
		t.Fatalf("legacy node: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	code, route := l.route(map[string]any{"name": "legacy-route", "entryServerId": entry, "nodeId": nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("offline route: %d %v", code, route)
	}
	l.applyAll()
	exportOffline(p, entry)
	before, _ := p.store.Server(entry)
	for _, format := range []string{"surge", "sing-box", "v2rayn"} {
		t.Run(format, func(t *testing.T) {
			code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
				"name": format, "format": format, "nodeIds": []string{nodeID}, "routeIds": []string{route["id"].(string)},
			}, nil)
			if code != 201 {
				t.Fatalf("subscription: %d %v", code, sub)
			}
			// The node password was already deployed. No new user key or offline
			// export is needed merely to subscribe to that same working node.
			path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
			code, body := p.fetch(path)
			if code != 200 {
				t.Fatalf("download: %d %s", code, body)
			}
			switch format {
			case "surge":
				if strings.Count(body, "encrypt-method=aes-256-gcm, password="+password) != 2 || !strings.Contains(body, "198.51.100.8, 50011") {
					t.Fatalf("incorrect legacy Surge credentials or route: %s", body)
				}
			case "sing-box":
				var config struct {
					Outbounds []struct{ Method, Password string }
				}
				if err := json.Unmarshal([]byte(body), &config); err != nil {
					t.Fatal(err)
				}
				if len(config.Outbounds) != 2 {
					t.Fatalf("missing direct/route entries: %s", body)
				}
				for _, out := range config.Outbounds {
					if out.Method != "aes-256-gcm" || out.Password != password {
						t.Fatal("invented legacy SS user credential")
					}
				}
			case "v2rayn":
				raw, err := base64.StdEncoding.DecodeString(body)
				if err != nil {
					t.Fatal(err)
				}
				userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:" + password))
				if strings.Count(string(raw), "ss://"+userinfo+"@") != 2 {
					t.Fatalf("invalid legacy share links: %s", raw)
				}
			}
		})
	}
	after, _ := p.store.Server(entry)
	if after.Revision != before.Revision || after.OfflineExportedRevision != after.Revision {
		t.Fatal("adding a subscription invalidated the offline export")
	}
	state, err := p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range state.Nodes {
		if item.Node.ID == nodeID && (len(item.Users) != 0 || item.Password != password) {
			t.Fatal("legacy server was configured with unsupported multi-user credentials")
		}
	}
	raw, err := shared.SingBoxConfig(state.Nodes, "/certs")
	if err != nil {
		t.Fatal(err)
	}
	var config struct{ Inbounds []map[string]any }
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	for _, in := range config.Inbounds {
		if in["tag"] == "node-"+nodeID && (in["users"] != nil || in["password"] != password) {
			t.Fatal("legacy inbound must retain its existing node password")
		}
	}
	var samples int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_user_totals WHERE node_id=$1`, nodeID).Scan(&samples); err != nil || samples != 0 {
		t.Fatalf("shared credentials must not fabricate subscription traffic: %d %v", samples, err)
	}
}

func TestLegacySSStillWaitsForChangedNodePassword(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("legacy-ss")
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": id, "name": "legacy", "protocol": "ss", "method": "aes-256-gcm", "password": "old-password", "port": 50001, "direct": true,
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyAll(agent)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "legacy", "format": "surge", "nodeIds": []string{node["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "password=old-password") {
		t.Fatalf("shared node unavailable: %d %s", code, body)
	}
	node["password"] = "new-password"
	if code, out, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), node, nil); code != 200 {
		t.Fatalf("password change: %d %v", code, out)
	}
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("unapplied password was published: %d", code)
	}
	p.applyAll(agent)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "password=new-password") {
		t.Fatalf("applied password unavailable: %d %s", code, body)
	}
}
