package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestServerNodeSubscriptionLifecycle(t *testing.T) {
	t.Setenv("MUI_ADMIN_PASSWORD", "strong-local-test-password")
	store, err := NewStore(filepath.Join(t.TempDir(), "mui.db"), "Test-Secret-With-32-Bytes-1234!Aa")
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	app, err := NewApp(store, "https://mui.example.test")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	fencing := map[string]string{}
	call := func(method, path string, body any, cookie *http.Cookie, headers map[string]string) (int, map[string]any, *http.Cookie) {
		t.Helper()
		if path == "/agent/report" {
			if m, ok := body.(map[string]any); ok {
				if id, ok := m["jobId"].(string); ok && id != "" {
					if _, has := m["fencingToken"]; !has {
						if token, ok := fencing[id]; ok {
							m["fencingToken"] = token
						}
					}
				}
			}
		}
		var raw []byte
		if body != nil {
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if token, ok := headers["Authorization"]; ok && strings.HasPrefix(token, "Bearer ") && strings.HasPrefix(path, "/agent/") && path != "/agent/enroll" {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				t.Fatal(err)
			}
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			nonceHex := hex.EncodeToString(nonce[:])
			sum := sha256.Sum256(raw)
			msg := method + "\n" + req.URL.Path + "\n" + timestamp + "\n" + nonceHex + "\n" + hex.EncodeToString(sum[:])
			key := sha256.Sum256([]byte(strings.TrimPrefix(token, "Bearer ")))
			mac := hmac.New(sha256.New, key[:])
			mac.Write([]byte(msg))
			req.Header.Set("X-Agent-Timestamp", timestamp)
			req.Header.Set("X-Agent-Nonce", nonceHex)
			req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if method == "GET" && path == "/agent/job" {
			if id, ok := out["id"].(string); ok {
				if token, ok := out["fencingToken"].(string); ok {
					fencing[id] = token
				}
			}
		}
		var got *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "mui_session" {
				got = c
			}
		}
		return rec.Code, out, got
	}
	code, _, cookie := call("POST", "/api/login", map[string]string{"password": "strong-local-test-password"}, nil, nil)
	if code != 200 || cookie == nil {
		t.Fatalf("login: %d", code)
	}
	code, serverResult, _ := call("POST", "/api/servers", map[string]any{"name": "Singapore 1", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.10"}, cookie, nil)
	if code != 201 {
		t.Fatalf("server: %d %v", code, serverResult)
	}
	serverID := serverResult["server"].(map[string]any)["id"].(string)
	enroll := serverResult["enrollToken"].(string)
	code, agentResult, _ := call("POST", "/agent/enroll", map[string]string{"serverId": serverID, "token": enroll}, nil, nil)
	if code != 200 {
		t.Fatalf("enroll: %d %v", code, agentResult)
	}
	code, _, _ = call("POST", "/agent/enroll", map[string]string{"serverId": serverID, "token": enroll}, nil, nil)
	if code != 401 {
		t.Fatalf("enroll replay: %d", code)
	}
	agentHeaders := map[string]string{"X-Server-ID": serverID, "Authorization": "Bearer " + agentResult["agentToken"].(string)}
	code, _, _ = call("POST", "/api/servers/"+serverID+"/ufw/init", nil, cookie, nil)
	if code != 202 {
		t.Fatalf("ufw init: %d", code)
	}
	code, nodeResult, _ := call("POST", "/api/nodes", map[string]any{"direct": true, "serverId": serverID, "name": "SS 1", "protocol": "ss", "port": 8388, "method": "2022-blake3-aes-128-gcm"}, cookie, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, nodeResult)
	}
	nodeID := nodeResult["id"].(string)
	code, job, _ := call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 || job["kind"] != "ufw.init" {
		t.Fatalf("first job: %d %v", code, job)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success", "ufwStatus": "active"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("first report: %d", code)
	}
	node, err := store.Node(nodeID)
	if err != nil || node.Status != "pending" {
		t.Fatalf("ufw init marked node active: %+v %v", node, err)
	}
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("node job: %d %v", code, job)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success", "traffic": []shared.TrafficPoint{{NodeID: nodeID, InstanceID: "instance-1", Sequence: 1, Uplink: 1024, Downlink: 2048, At: time.Now()}}, "serverTraffic": []shared.ServerTrafficPoint{{BootID: "boot-1", Interface: "eth0", Sequence: 1, Rx: 4096, Tx: 8192, At: time.Now()}}}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("node report: %d", code)
	}
	node, err = store.Node(nodeID)
	if err != nil || node.Status != "active" {
		t.Fatalf("node not active: %+v %v", node, err)
	}
	totals, err := store.NodeTotals()
	up, down := totals[nodeID][0], totals[nodeID][1]
	if err != nil || up != 1024 || down != 2048 {
		t.Fatalf("traffic %d/%d", up, down)
	}
	servers, err := store.Servers()
	if err != nil || servers[0].NetworkRx != 4096 || servers[0].NetworkTx != 8192 {
		t.Fatalf("server traffic: %+v %v", servers, err)
	}
	code, summary, _ := call("GET", "/api/traffic/summary", nil, cookie, nil)
	if code != 200 || summary["today"].(map[string]any)["uplink"] != float64(1024) {
		t.Fatalf("traffic summary: %d %v", code, summary)
	}
	code, sub, _ := call("POST", "/api/subscriptions", map[string]any{"name": "Main", "format": "sing-box", "nodeIds": []string{nodeID}}, cookie, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"agentVersion": "test", "multiUserStats": true, "nodeFirewallPolicies": true}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("agent capability report: %d", code)
	}
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("multi-user job: %d", code)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("multi-user apply: %d", code)
	}
	tokenURL := sub["url"].(string)
	if len(tokenURL) < 30 {
		t.Fatal("short subscription URL")
	}
	req := httptest.NewRequest("GET", "/s/"+tokenURL[len("https://mui.example.test/s/"):], nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(`"type": "shadowsocks"`)) {
		t.Fatalf("subscription body: %d %s", rec.Code, rec.Body.String())
	}
	code, rotated, _ := call("POST", "/api/subscriptions/"+sub["id"].(string)+"/rotate", nil, cookie, nil)
	if code != 200 {
		t.Fatalf("rotate: %d", code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("old subscription token still valid: %d", rec.Code)
	}
	newURL := rotated["url"].(string)
	req = httptest.NewRequest("GET", "/s/"+newURL[len("https://mui.example.test/s/"):], nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rotated subscription: %d", rec.Code)
	}
	code, _, _ = call("DELETE", "/api/nodes/"+nodeID, nil, cookie, nil)
	if code != 202 {
		t.Fatalf("node delete: %d", code)
	}
	if _, err = store.Node(nodeID); err != nil {
		t.Fatal("node removed before agent confirmation")
	}
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("delete job: %d", code)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("delete report: %d", code)
	}
	if _, err = store.Node(nodeID); err == nil {
		t.Fatal("node still exists after deletion confirmation")
	}
	code, rule, _ := call("POST", "/api/firewall", map[string]any{"serverId": serverID, "portFrom": 8443, "portTo": 8443, "network": "tcp", "action": "allow", "comment": "extra"}, cookie, nil)
	if code != 201 {
		t.Fatalf("firewall create: %d %v", code, rule)
	}
	ruleID := rule["id"].(string)
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("firewall job: %d", code)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "failed", "jobError": "simulated UFW failure"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("firewall failure report: %d", code)
	}
	rules, err := store.Rules(serverID)
	if err != nil || rules[0].Status != "error" {
		t.Fatalf("firewall error state: %+v %v", rules, err)
	}
	code, _, _ = call("POST", "/api/operations/"+job["id"].(string)+"/retry", nil, cookie, nil)
	if code != 202 {
		t.Fatalf("retry: %d", code)
	}
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("retry job: %d", code)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("retry report: %d", code)
	}
	rules, err = store.Rules(serverID)
	if err != nil || rules[0].Status != "active" {
		t.Fatalf("firewall active state: %+v %v", rules, err)
	}
	code, _, _ = call("DELETE", "/api/firewall/"+ruleID, nil, cookie, nil)
	if code != 202 {
		t.Fatalf("firewall delete: %d", code)
	}
	rules, _ = store.Rules(serverID)
	if len(rules) != 1 || !rules[0].Deleting {
		t.Fatalf("firewall removed before confirmation: %+v", rules)
	}
	code, job, _ = call("GET", "/agent/job", nil, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("firewall delete job: %d", code)
	}
	code, _, _ = call("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, nil, agentHeaders)
	if code != 200 {
		t.Fatalf("firewall delete report: %d", code)
	}
	rules, _ = store.Rules(serverID)
	if len(rules) != 0 {
		t.Fatalf("firewall not removed: %+v", rules)
	}
}
