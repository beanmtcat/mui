package server

import (
	"encoding/json"
	"strings"
	"testing"

	"mui/internal/shared"
)

func createOfflineServer(p *testMui, name, ip string) string {
	p.t.Helper()
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": name, "country": "SG", "ipv4": ip, "roles": []string{"entry", "transit"}, "managementMode": "offline", "firewallMode": "manual"}, nil)
	if code != 201 {
		p.t.Fatalf("offline create: %d %v", code, out)
	}
	if out["enrollToken"] != nil || out["installCommand"] != nil {
		p.t.Fatal("offline create exposed online enrollment")
	}
	return out["server"].(map[string]any)["id"].(string)
}

func exportOffline(p *testMui, id string) shared.OfflineBundle {
	p.t.Helper()
	code, out, _ := p.do("POST", "/api/servers/"+id+"/offline/export", nil, nil)
	if code != 200 {
		p.t.Fatalf("export: %d %v", code, out)
	}
	raw, _ := json.Marshal(out["bundle"])
	var bundle shared.OfflineBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		p.t.Fatal(err)
	}
	if err := bundle.Verify(); err != nil {
		p.t.Fatal(err)
	}
	install := out["install"].(map[string]any)
	if strings.Contains(install["command"].(string), "curl") || !strings.Contains(install["command"].(string), "./mui-offline.json") {
		p.t.Fatal("target install command downloads files or uses wrong filename")
	}
	return bundle
}

func TestOfflineEntryRouteExportAndSubscription(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	id := createOfflineServer(p, "offline-entry", "198.51.100.8")
	code, rt := l.route(map[string]any{"name": "offline-route", "entryServerId": id, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "offline-sub", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	l.applyAll()
	if code, body := p.fetch(path); code != 503 {
		t.Fatalf("unapplied offline route published: %d %s", code, body)
	}
	bundle := exportOffline(p, id)
	if len(bundle.Forwards) != 2 {
		t.Fatalf("SS route needs TCP and UDP: %+v", bundle.Forwards)
	}
	if bundle.Forwards[0].Targets[0].Host != "198.51.100.2" {
		t.Fatal("wrong next hop")
	}
	var jobs int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations WHERE server_id=$1`, id).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("offline server queued online jobs: %d %v", jobs, err)
	}
	// Exporting the current snapshot permits subscription output, without
	// claiming the isolated host applied it or requiring an acknowledgement.
	if code, _, _ := p.do("POST", "/api/servers/"+id+"/offline/receipt", map[string]any{}, nil); code != 404 {
		t.Fatalf("removed receipt endpoint remains available: %d", code)
	}
	for range 2 {
		exportOffline(p, id)
	}
	code, body := p.fetch(path)
	if code != 200 || !strings.Contains(body, "198.51.100.8") {
		t.Fatalf("exported entry not in subscription: %d %s", code, body)
	}
	srv, _ := p.store.Server(id)
	if srv.LastSeen != nil || serverStatus(srv) != "offline-managed" || srv.AppliedRevision != 0 {
		t.Fatal("export pretended to be an online heartbeat")
	}
	// Updating a route requires a fresh export, without a remote acknowledgement.
	code, out, _ := p.do("PATCH", "/api/routes/"+rt["id"].(string), map[string]any{"name": "offline-route", "entryServerId": id, "nodeId": l.nodeID, "enabled": true, "port": 50011, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}, nil)
	if code != 200 {
		t.Fatalf("edit: %d %v", code, out)
	}
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("unexported edit published: %d", code)
	}
	latest := exportOffline(p, id)
	if latest.Revision <= bundle.Revision || latest.Forwards[0].Port != 50011 {
		t.Fatal("export not updated")
	}
	l.applyAll()

	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "50011") {
		t.Fatalf("updated subscription: %d %s", code, body)
	}
}

func TestOfflineManagementGuardsAndDeletion(t *testing.T) {
	p := newTestMui(t)
	id := createOfflineServer(p, "entry", "198.51.100.8")
	for _, path := range []string{"enrollment", "agent/upgrade", "core/upgrade", "ufw/init"} {
		if code, _, _ := p.do("POST", "/api/servers/"+id+"/"+path, nil, nil); code < 400 {
			t.Fatalf("online action accepted: %s %d", path, code)
		}
	}
	if code, _, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": "ignored"}, nil); code != 403 {
		t.Fatalf("offline enrolled: %d", code)
	}
	code, forward, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": id, "name": "manual", "network": shared.ForwardTCPUDP, "port": 50020, "targets": []map[string]any{{"host": "198.51.100.10", "port": 50020}}, "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("manual forward: %d %v", code, forward)
	}
	bundle := exportOffline(p, id)
	if len(bundle.Forwards) != 1 || bundle.Forwards[0].Network != shared.ForwardTCPUDP {
		t.Fatalf("combined offline export: %+v", bundle.Forwards)
	}

	if code, _, _ := p.do("DELETE", "/api/forwards/"+forward["id"].(string), nil, nil); code != 202 {
		t.Fatalf("delete: %d", code)
	}
	empty := exportOffline(p, id)
	if len(empty.Forwards) != 0 {
		t.Fatal("deleted forward still exported")
	}

	forwards, _ := p.store.Forwards(id)
	if len(forwards) != 0 {
		t.Fatal("exported deletion not purged")
	}
	srv, _ := p.store.Server(id)
	srv.ManagementMode = "online"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, srv, nil); code != 200 {
		t.Fatalf("exported server cannot change management: %d %v", code, out)
	}
	srv.ManagementMode = "offline"
	srv.FirewallMode = "ufw"
	if code, _, _ := p.do("PATCH", "/api/servers/"+id, srv, nil); code < 400 {
		t.Fatalf("offline UFW accepted: %d", code)
	}
	if code, out, _ := p.do("DELETE", "/api/servers/"+id, nil, nil); code != 200 {
		t.Fatalf("purge offline: %d %v", code, out)
	}

}

func TestOfflineBackupRequiresCurrentExport(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	backup := createOfflineServer(p, "offline-backup", "198.51.100.8")
	code, rt := l.route(map[string]any{"name": "mixed-backup", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1, backup}, "balance": "failover"}}})
	if code != 201 {
		t.Fatalf("mixed route: %d %v", code, rt)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	l.applyAll()
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("unexported offline backup published: %d", code)
	}
	exportOffline(p, backup)

	if code, body := p.fetch(path); code != 200 {
		t.Fatalf("exported backup missing: %d %s", code, body)
	}
	// An unrelated local forward changes the whole config revision while
	// the route's previously exported forwards still have exported status.
	code, out, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": backup, "name": "extra", "network": "tcp", "port": 55001, "targets": []map[string]any{{"host": "198.51.100.10", "port": 55002}}, "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("extra forward: %d %v", code, out)
	}
	if code, _ := p.fetch(path); code != 503 {
		t.Fatalf("offline revision mismatch ignored in LB group: %d", code)
	}
	exportOffline(p, backup)

	if code, body := p.fetch(path); code != 200 {
		t.Fatalf("latest backup missing: %d %s", code, body)
	}
}
