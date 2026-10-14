package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

const testPassword = "strong-local-test-password"

type testMui struct {
	t       *testing.T
	store   *Store
	app     *App
	handler http.Handler
	cookie  *http.Cookie
	// fencing remembers the fencing token of each claimed job, so reports
	// echo it the way a current agent does.
	fencing map[string]string
}

func newTestMui(t *testing.T) *testMui {
	t.Helper()
	t.Setenv("MUI_ADMIN_PASSWORD", testPassword)
	store, err := NewStore(filepath.Join(t.TempDir(), "mui.db"), "Test-Secret-With-32-Bytes-1234!Aa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	app, err := NewApp(store, "https://mui.example.test")
	if err != nil {
		t.Fatal(err)
	}
	p := &testMui{t: t, store: store, app: app, handler: app.Handler(), fencing: map[string]string{}}
	code, _, cookie := p.do("POST", "/api/login", map[string]string{"password": testPassword}, nil)
	if code != 200 || cookie == nil {
		t.Fatalf("login: %d", code)
	}
	p.cookie = cookie
	return p
}

// signAgentRequest attaches the HMAC request signature for an agent call.
func signAgentRequest(t *testing.T, req *http.Request, token string, body []byte) {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonceHex := hex.EncodeToString(nonce[:])
	sum := sha256.Sum256(body)
	msg := req.Method + "\n" + req.URL.Path + "\n" + timestamp + "\n" + nonceHex + "\n" + hex.EncodeToString(sum[:])
	key := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(msg))
	req.Header.Set("X-Agent-Timestamp", timestamp)
	req.Header.Set("X-Agent-Nonce", nonceHex)
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
}

// do sends a request; headers may carry "RemoteAddr" to set the peer address.
// Agent requests (Authorization present) are signed like a current agent's,
// and reports echo the fencing token of the job they answer.
func (p *testMui) do(method, path string, body any, headers map[string]string) (int, map[string]any, *http.Cookie) {
	p.t.Helper()
	if path == "/agent/report" {
		if m, ok := body.(map[string]any); ok {
			if id, ok := m["jobId"].(string); ok && id != "" {
				if _, has := m["fencingToken"]; !has {
					if token, ok := p.fencing[id]; ok {
						m["fencingToken"] = token
					}
				}
			}
		}
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	for k, v := range headers {
		if k == "RemoteAddr" {
			req.RemoteAddr = v
			continue
		}
		req.Header.Set(k, v)
	}
	if token, ok := headers["Authorization"]; ok && strings.HasPrefix(token, "Bearer ") && strings.HasPrefix(path, "/agent/") && path != "/agent/enroll" {
		signAgentRequest(p.t, req, strings.TrimPrefix(token, "Bearer "), raw)
	}
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if method == "GET" && path == "/agent/job" {
		if id, ok := out["id"].(string); ok {
			if token, ok := out["fencingToken"].(string); ok {
				p.fencing[id] = token
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

// enroll creates a server and returns its ID and agent headers.
func (p *testMui) enroll(name string) (string, map[string]string) {
	p.t.Helper()
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": name, "country": "SG", "ipv4": "203.0.113.10"}, nil)
	if code != 201 {
		p.t.Fatalf("server: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	code, agent, _ := p.do("POST", "/agent/enroll", map[string]string{"serverId": id, "token": out["enrollToken"].(string)}, nil)
	if code != 200 {
		p.t.Fatalf("enroll: %d %v", code, agent)
	}
	return id, map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + agent["agentToken"].(string)}
}

// newAgent reports the capabilities of a current agent.
func (p *testMui) newAgent(agent map[string]string) {
	p.t.Helper()
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0", "multiUserStats": true, "nodeFirewallPolicies": true, "forwardSupport": true, "shadowTlsAuth": true, "ufwStatus": "active"}, agent); code != 200 {
		p.t.Fatalf("capabilities: %d %v", code, out)
	}
}

// applyAll lets the agent work through every queued job successfully.
func (p *testMui) applyAll(agent map[string]string) {
	p.t.Helper()
	for i := 0; i < 20; i++ {
		code, job, _ := p.do("GET", "/agent/job", nil, agent)
		if code != 200 {
			return
		}
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agent); code != 200 {
			p.t.Fatalf("report: %d %v", code, out)
		}
	}
	p.t.Fatal("job queue never drained")
}

// fetch performs an unauthenticated GET and returns the raw body.
func (p *testMui) fetch(path string) (int, string) {
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Body.String()
}

// applyNext claims the next job for a server and reports the given outcome.
func (p *testMui) applyNext(agent map[string]string, status string) map[string]any {
	p.t.Helper()
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 {
		p.t.Fatalf("job: %d %v", code, job)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": status}, agent); code != 200 {
		p.t.Fatalf("report: %d %v", code, out)
	}
	return job
}

func totpCode(secret string, at time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	i := int(sum[len(sum)-1] & 0xf)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[i:i+4])&0x7fffffff)%1000000)
}

func TestQueuedJobStateIsEncryptedAndClearedWhenFinished(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("a")
	const psk = "PLAINTEXT-PSK-MARKER"
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "snell", "port": 8443, "password": psk, "shadowTlsHost": "www.example.com"}, nil); code != 201 {
		t.Fatalf("node: %d %v", code, out)
	}
	var state string
	if err := p.store.DB.QueryRow(`SELECT state FROM mui_operations`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "" || strings.Contains(state, psk) {
		t.Fatalf("queued job state is not encrypted: %.80s", state)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	nodes := job["state"].(map[string]any)["nodes"].([]any)
	if code != 200 || nodes[0].(map[string]any)["password"] != psk {
		t.Fatalf("agent did not receive the secret: %d %v", code, job)
	}
	p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agent)
	if err := p.store.DB.QueryRow(`SELECT state FROM mui_operations`).Scan(&state); err != nil || state != "" {
		t.Fatalf("finished job keeps its state: %q %v", state, err)
	}
}

func TestLoginRateLimitIsPerClient(t *testing.T) {
	t.Setenv("MUI_TRUSTED_PROXIES", "10.0.0.0/8")
	p := newTestMui(t)
	p.cookie = nil
	proxy := func(client string) map[string]string {
		// The left-most entry is whatever the client chose to send.
		return map[string]string{"RemoteAddr": "10.0.0.2:5000", "X-Forwarded-For": "1.2.3.4, " + client}
	}
	for i := 0; i < 10; i++ {
		if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": "wrong"}, proxy("198.51.100.7")); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": testPassword}, proxy("198.51.100.7")); code != 429 {
		t.Fatalf("attacker not limited: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": testPassword}, proxy("198.51.100.8")); code != 200 {
		t.Fatalf("another client behind the same proxy was locked out: %d", code)
	}
	// A direct connection cannot pick its own bucket by sending the header.
	for i := 0; i < 10; i++ {
		p.do("POST", "/api/login", map[string]string{"password": "wrong"}, map[string]string{"RemoteAddr": "203.0.113.50:1", "X-Forwarded-For": fmt.Sprintf("198.51.100.%d", 100+i)})
	}
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": testPassword}, map[string]string{"RemoteAddr": "203.0.113.50:1", "X-Forwarded-For": "198.51.100.200"}); code != 429 {
		t.Fatalf("untrusted X-Forwarded-For was believed: %d", code)
	}
}

func TestSuccessfulLoginsAreNotRateLimited(t *testing.T) {
	p := newTestMui(t)
	p.cookie = nil
	for i := 0; i < 15; i++ {
		if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": testPassword}, nil); code != 200 {
			t.Fatalf("login %d: %d", i, code)
		}
	}
}

func TestNodeTemplateLifecycle(t *testing.T) {
	p := newTestMui(t)
	if code, _, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "Broken", "protocol": "anytls", "port": 443,
	}, nil); code != 400 {
		t.Fatalf("AnyTLS template without a domain accepted: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "Invalid", "protocol": "ss", "port": 8388, "password": "shared-secret",
	}, nil); code != 400 {
		t.Fatalf("template accepted an invalid SS 2022 key: %d", code)
	}
	psk := base64.StdEncoding.EncodeToString([]byte("1234567890abcdef"))
	code, created, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "SS 2022", "protocol": "ss", "port": 8388,
		"method": "2022-blake3-aes-128-gcm", "password": psk,
	}, nil)
	if code != 201 {
		t.Fatalf("create template: %d %v", code, created)
	}
	id := created["id"].(string)
	if created["listen"] != "0.0.0.0" {
		t.Fatalf("template defaults missing: %v", created)
	}
	if _, exposed := created["password"]; exposed {
		t.Fatal("template create response exposed password")
	}
	var count int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_node_templates`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("template migration/store: %d %v", count, err)
	}
	var data, secret string
	if err := p.store.DB.QueryRow(`SELECT data,secret FROM mui_node_templates WHERE id=$1`, id).Scan(&data, &secret); err != nil || strings.Contains(data+secret, psk) {
		t.Fatalf("template secret stored in plaintext: %v", err)
	}
	if code, detail, _ := p.do("GET", "/api/node-templates/"+id, nil, nil); code != 200 || detail["password"] != psk {
		t.Fatalf("template detail: %d %v", code, detail)
	}
	serverID, _ := p.enroll("template-server")
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "from-template", "protocol": "ss", "port": 8388,
		"method": "2022-blake3-aes-128-gcm", "templateId": id,
	}, nil)
	if code != 201 {
		t.Fatalf("create node with template: %d %v", code, node)
	}
	if got, err := p.store.NodeSecret(node["id"].(string)); err != nil || got != psk {
		t.Fatalf("node did not use template password: %q %v", got, err)
	}
	if code, _, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "wrong-method", "protocol": "ss", "port": 8389,
		"method": "2022-blake3-aes-256-gcm", "templateId": id,
	}, nil); code != 400 {
		t.Fatalf("template key used with a different method: %d", code)
	}
	code, _, _ = p.do("PATCH", "/api/node-templates/"+id, map[string]any{
		"name": "Snell", "protocol": "snell", "port": 8443, "obfs": "http", "password": "", "shadowTlsHost": "www.example.com",
	}, nil)
	if code != 200 {
		t.Fatalf("update template: %d", code)
	}
	stored, err := p.store.NodeTemplate(id)
	if err != nil || stored.Protocol != "snell" || stored.SnellVersion != 5 || stored.Obfs != "http" || stored.Method != "" {
		t.Fatalf("updated template: %+v %v", stored, err)
	}
	if code, _, _ = p.do("DELETE", "/api/node-templates/"+id, nil, nil); code != 200 {
		t.Fatalf("delete template: %d", code)
	}
	if code, _, _ = p.do("PATCH", "/api/node-templates/"+id, map[string]any{
		"name": "Gone", "protocol": "ss", "port": 8388,
	}, nil); code != 404 {
		t.Fatalf("deleted template still editable: %d", code)
	}
}

func TestNodeFirewallAccessPolicy(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("restricted-server")
	code, template, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "restricted", "protocol": "ss", "port": 50000,
		"method": "aes-128-gcm", "firewallPolicy": "restricted",
		"firewallSources": "203.0.113.7, 2001:db8::/32",
	}, nil)
	if code != 201 || template["firewallPolicy"] != nil || template["firewallSources"] != nil {
		t.Fatalf("template should ignore legacy firewall fields: %d %v", code, template)
	}
	nodeRequest := map[string]any{
		"serverId": serverID, "name": "restricted-node", "protocol": "ss", "port": 50000,
		"method": "aes-128-gcm", "templateId": template["id"],
		"firewallPolicy": "restricted", "firewallSources": "203.0.113.7, 2001:db8::/32",
	}
	code, node, _ := p.do("POST", "/api/nodes", nodeRequest, nil)
	if code != 201 || node["firewallPolicy"] != "restricted" || node["firewallSources"] != "203.0.113.7/32,2001:db8::/32" {
		t.Fatalf("restricted node should save before Agent upgrade: %d %v", code, node)
	}
	// The apply job is skipped for an agent that cannot apply firewall
	// policies: the poll succeeds with no job instead of failing.
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old Agent poll should skip the restricted job: %d %v", code, out)
	}
	code, updated, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), map[string]any{
		"name": "restricted-node", "protocol": "ss", "port": 50000,
		"method": "aes-128-gcm", "enabled": true, "firewallPolicy": "manual",
	}, nil)
	if code != 200 || updated["firewallPolicy"] != "manual" || updated["firewallSources"] != "" {
		t.Fatalf("manual node update should save before Agent upgrade: %d %v", code, updated)
	}
	if code, out, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old Agent poll should skip the manual job: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.2.0", "nodeFirewallPolicies": true}, agent); code != 200 {
		t.Fatalf("new Agent report: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || !strings.HasSuffix(job["kind"].(string), ".apply") {
		t.Fatalf("new Agent could not receive saved job: %d %v", code, job)
	}
}

func TestSnellShadowTLSTemplateNodeAndSubscription(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("shadowtls-server")
	if code, _, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "missing-host", "protocol": "snell", "port": 54320,
	}, nil); code != 400 {
		t.Fatalf("Snell node without ShadowTLS SNI accepted: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "missing-host", "protocol": "snell", "port": 54321,
	}, nil); code != 400 {
		t.Fatalf("Snell template without ShadowTLS SNI accepted: %d", code)
	}
	const snellPSK = "snell-secret-123"
	const outerPassword = "shadow-secret-456"
	code, template, _ := p.do("POST", "/api/node-templates", map[string]any{
		"name": "Snell TLS", "protocol": "snell", "port": 54321,
		"shadowTlsHost": "www.example.com", "password": snellPSK, "shadowTlsPassword": outerPassword,
	}, nil)
	if code != 201 {
		t.Fatalf("template: %d %v", code, template)
	}
	templateID := template["id"].(string)
	var data, shadowSecret string
	if err := p.store.DB.QueryRow(`SELECT data,shadow_tls_secret FROM mui_node_templates WHERE id=$1`, templateID).Scan(&data, &shadowSecret); err != nil || strings.Contains(data+shadowSecret, outerPassword) {
		t.Fatalf("template ShadowTLS password stored in plaintext: %v", err)
	}
	if code, detail, _ := p.do("GET", "/api/node-templates/"+templateID, nil, nil); code != 200 || detail["shadowTlsPassword"] != outerPassword {
		t.Fatalf("template secret detail: %d %v", code, detail)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "Snell TLS", "protocol": "snell", "port": 54321,
		"shadowTlsHost": "www.example.com", "templateId": templateID,
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	if err := p.store.DB.QueryRow(`SELECT data,shadow_tls_secret FROM mui_nodes WHERE id=$1`, nodeID).Scan(&data, &shadowSecret); err != nil || strings.Contains(data+shadowSecret, outerPassword) {
		t.Fatalf("node ShadowTLS password stored in plaintext: %v", err)
	}
	if got, err := p.store.NodeSecret(nodeID); err != nil || got != snellPSK {
		t.Fatalf("Snell PSK not copied: %q %v", got, err)
	}
	if got, err := p.store.NodeShadowTLSSecret(nodeID); err != nil || got != outerPassword {
		t.Fatalf("ShadowTLS password not copied: %q %v", got, err)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["shadowTlsPassword"] != outerPassword {
		t.Fatalf("agent job missing ShadowTLS secret: %d %v", code, job)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agent); code != 200 {
		t.Fatalf("agent report: %d %v", code, out)
	}
	p.newAgent(agent)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "Snell TLS", "format": "sing-box", "nodeIds": []string{nodeID}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	code, preview, _ := p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/preview", nil, nil)
	if code != 200 || strings.Contains(preview["content"].(string), `"shadowtls"`) || len(preview["excluded"].([]any)) != 1 {
		t.Fatalf("node offered before the server applied the subscription's login: %d %v", code, preview)
	}
	p.applyAll(agent)
	code, preview, _ = p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/preview", nil, nil)
	content := preview["content"].(string)
	// Behind ShadowTLS the subscription's own secret is the ShadowTLS password;
	// Snell stays single-user so that stock clients can connect.
	if code != 200 || strings.Contains(content, `"userkey"`) || !strings.Contains(content, `"shadowtls"`) || strings.Contains(content, outerPassword) || !strings.Contains(content, snellPSK) {
		t.Fatalf("subscription preview: %d %v", code, preview)
	}
	code, surge, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "Surge", "format": "surge", "nodeIds": []string{nodeID}}, nil)
	if code != 201 {
		t.Fatalf("Surge subscription with a ShadowTLS Snell node: %d %v", code, surge)
	}
	p.applyAll(agent)
	code, body := p.fetch(strings.TrimPrefix(surge["url"].(string), "https://mui.example.test"))
	if code != 200 || !strings.Contains(body, "= snell, ") || !strings.Contains(body, "psk="+snellPSK) || !strings.Contains(body, "shadow-tls-sni=www.example.com, shadow-tls-version=3") || strings.Contains(body, outerPassword) {
		t.Fatalf("Surge Snell line: %d %s", code, body)
	}
}

func TestOfflineServerCanBeForceDeleted(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("gone")
	_, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "snell", "port": 8443, "shadowTlsHost": "www.example.com"}, nil)
	nodeID := node["id"].(string)
	p.do("POST", "/agent/report", map[string]any{"traffic": []map[string]any{{"nodeId": nodeID, "instanceId": "i", "sequence": 1, "uplink": 5, "downlink": 5, "at": time.Now()}}}, agent)
	p.applyNext(agent, "success")
	_, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "nodeIds": []string{nodeID}}, nil)

	if code, _, _ := p.do("DELETE", "/api/servers/"+id+"?force=1", nil, nil); code != 409 {
		t.Fatalf("online server was deleted: %d", code)
	}
	// The agent stops reporting.
	server, _ := p.store.Server(id)
	seen := time.Now().Add(-2 * time.Minute)
	server.LastSeen = &seen
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("DELETE", "/api/servers/"+id, nil, nil); code != 409 {
		t.Fatalf("server with nodes deleted without force: %d", code)
	}
	if code, out, _ := p.do("DELETE", "/api/servers/"+id+"?force=1", nil, nil); code != 200 {
		t.Fatalf("force delete: %d %v", code, out)
	}
	for _, table := range []string{"mui_servers", "mui_nodes", "mui_operations", "mui_traffic", "mui_node_totals"} {
		var n int
		if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s rows left: %d %v", table, n, err)
		}
	}
	subs, _ := p.store.Subscriptions()
	if len(subs) != 1 || subs[0].ID != sub["id"] || len(subs[0].NodeIDs) != 0 {
		t.Fatalf("subscription still lists the deleted node: %+v", subs)
	}
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code != 401 {
		t.Fatalf("deleted server's agent still authenticates: %d", code)
	}
}

func TestServerStatusGoesOffline(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("s")
	status := func() string {
		req := httptest.NewRequest("GET", "/api/servers", nil)
		req.AddCookie(p.cookie)
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		var list []shared.Server
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
			t.Fatalf("servers: %v %s", err, rec.Body.String())
		}
		return list[0].Status
	}
	if got := status(); got != "pending" {
		t.Fatalf("before first report: %s", got)
	}
	p.do("POST", "/agent/report", map[string]any{}, agent)
	if got := status(); got != "online" {
		t.Fatalf("after report: %s", got)
	}
	server, _ := p.store.Server(id)
	seen := time.Now().Add(-2 * time.Minute)
	server.LastSeen = &seen
	_ = p.store.PutServer(server)
	if got := status(); got != "offline" {
		t.Fatalf("after silence: %s", got)
	}
}

func TestReservedAndSSHPortsAreRefused(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("s")
	p.do("POST", "/agent/report", map[string]any{"hostReported": true, "sshPorts": []int{22, 2222}, "ufwStatus": "active"}, agent)
	for _, port := range []int{22, 2222, shared.StatsAPIPort} {
		if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "snell", "port": port, "shadowTlsHost": "www.example.com"}, nil); code != 400 {
			t.Fatalf("node on port %d accepted: %d %v", port, code, out)
		}
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 1, "portTo": 1024, "network": "tcp", "action": "deny"}, nil); code != 400 {
		t.Fatalf("deny rule over SSH accepted: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 1, "portTo": 1024, "network": "udp", "action": "deny"}, nil); code != 201 {
		t.Fatalf("UDP deny rule refused: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 50000, "portTo": 50000, "network": "tcp", "action": "allow", "source": "203.0.113.7"}, nil); code != 201 || out["source"] != "203.0.113.7/32" {
		t.Fatalf("single-IP source rule: %d %v", code, out)
	}
}

func TestResentTrafficIsCountedOnceAndTotalsSurvivePruning(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("s")
	_, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "snell", "port": 8443, "shadowTlsHost": "www.example.com"}, nil)
	nodeID := node["id"].(string)
	old := time.Now().Add(-100 * 24 * time.Hour)
	report := map[string]any{
		"traffic":       []map[string]any{{"nodeId": nodeID, "instanceId": "i", "sequence": 1, "uplink": 100, "downlink": 200, "at": old}},
		"serverTraffic": []map[string]any{{"bootId": "b", "interface": "eth0", "sequence": 1, "rx": 10, "tx": 20, "at": old}},
	}
	for i := 0; i < 2; i++ {
		if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
			t.Fatalf("report: %d %v", code, out)
		}
	}
	check := func(when string) {
		totals, err := p.store.NodeTotals()
		if err != nil || totals[nodeID] != [2]int64{100, 200} {
			t.Fatalf("%s: node totals %v %v", when, totals, err)
		}
		servers, err := p.store.Servers()
		if err != nil || servers[0].NetworkRx != 10 || servers[0].NetworkTx != 20 {
			t.Fatalf("%s: server totals %+v %v", when, servers, err)
		}
	}
	check("after duplicate report")
	if err := p.store.PruneTraffic(time.Now().Add(-90 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var samples int
	_ = p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_traffic`).Scan(&samples)
	if samples != 0 {
		t.Fatalf("old samples not pruned: %d", samples)
	}
	check("after pruning")
}

func TestPasswordChangeAndTOTPLifecycle(t *testing.T) {
	p := newTestMui(t)
	_, _, other := p.do("POST", "/api/login", map[string]string{"password": testPassword}, nil)
	const next = "another-strong-password"
	if code, _, _ := p.do("POST", "/api/password", map[string]string{"current": "wrong", "new": next}, nil); code != 403 {
		t.Fatalf("wrong current password accepted: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/password", map[string]string{"current": testPassword, "new": "short"}, nil); code != 400 {
		t.Fatalf("short password accepted: %d", code)
	}
	if code, out, _ := p.do("POST", "/api/password", map[string]string{"current": testPassword, "new": next}, nil); code != 200 {
		t.Fatalf("password change: %d %v", code, out)
	}
	mine := p.cookie
	p.cookie = other
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 401 {
		t.Fatalf("other session survived the password change: %d", code)
	}
	p.cookie = mine
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 200 {
		t.Fatalf("current session lost: %d", code)
	}

	_, setup, _ := p.do("POST", "/api/totp/setup", nil, nil)
	secret := setup["secret"].(string)
	if code, out, _ := p.do("POST", "/api/totp/enable", map[string]string{"code": totpCode(secret, time.Now())}, nil); code != 200 {
		t.Fatalf("totp enable: %d %v", code, out)
	}
	var stored string
	_ = p.store.DB.QueryRow(`SELECT totp_secret FROM mui_admin`).Scan(&stored)
	if stored == "" || strings.Contains(stored, secret) {
		t.Fatalf("TOTP secret stored in the clear: %q", stored)
	}
	p.cookie = nil
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": next}, nil); code != 401 {
		t.Fatalf("login without code: %d", code)
	}
	code, _, cookie := p.do("POST", "/api/login", map[string]string{"password": next, "code": totpCode(secret, time.Now())}, nil)
	if code != 200 {
		t.Fatalf("login with code: %d", code)
	}
	p.cookie = cookie
	if code, _, _ := p.do("POST", "/api/totp/disable", map[string]string{"password": next, "code": "000000"}, nil); code != 403 {
		t.Fatalf("totp disabled with a wrong code: %d", code)
	}
	if code, out, _ := p.do("POST", "/api/totp/disable", map[string]string{"password": next, "code": totpCode(secret, time.Now())}, nil); code != 200 {
		t.Fatalf("totp disable: %d %v", code, out)
	}
	p.cookie = nil
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": next}, nil); code != 200 {
		t.Fatalf("login after disabling TOTP: %d", code)
	}
}

func TestAdminResetFromEnvironment(t *testing.T) {
	p := newTestMui(t)
	t.Setenv("MUI_ADMIN_RESET", "1")
	t.Setenv("MUI_ADMIN_PASSWORD", "recovered-admin-password")
	app, err := NewApp(p.store, "https://mui.example.test")
	if err != nil {
		t.Fatal(err)
	}
	p.handler = app.Handler()
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 401 {
		t.Fatalf("old session survived the reset: %d", code)
	}
	p.cookie = nil
	if code, _, _ := p.do("POST", "/api/login", map[string]string{"password": "recovered-admin-password"}, nil); code != 200 {
		t.Fatalf("login with the reset password: %d", code)
	}
}

func TestExpiredCertificateDoesNotBlockDisablingTheNode(t *testing.T) {
	p := newTestMui(t)
	id, _ := p.enroll("s")
	cert := shared.Certificate{ID: ID(), ServerID: id, Domain: "node.example.com", PEM: "unused", Key: "unused", ExpiresAt: time.Now().Add(time.Hour)}
	if err := p.store.PutCertificate(cert); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"serverId": id, "name": "tls", "protocol": "anytls", "port": 8443, "tlsName": "node.example.com", "certificateId": cert.ID, "enabled": true}
	code, node, _ := p.do("POST", "/api/nodes", body, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	cert.ExpiresAt = time.Now().Add(-time.Hour)
	if _, err := p.store.DB.Exec(`UPDATE mui_certificates SET data=$1 WHERE id=$2`, Marshal(shared.Certificate{ID: cert.ID, ServerID: id, Domain: cert.Domain, PEM: cert.PEM, ExpiresAt: cert.ExpiresAt}), cert.ID); err != nil {
		t.Fatal(err)
	}
	path := "/api/nodes/" + node["id"].(string)
	if code, _, _ := p.do("PATCH", path, body, nil); code != 400 {
		t.Fatalf("enabled node kept with an expired certificate: %d", code)
	}
	body["enabled"] = false
	if code, out, _ := p.do("PATCH", path, body, nil); code != 200 {
		t.Fatalf("could not disable the node: %d %v", code, out)
	}
}

func TestSubscriptionServesLiveNodesWhileAnotherServerLags(t *testing.T) {
	p := newTestMui(t)
	idA, agentA := p.enroll("a")
	idB, agentB := p.enroll("b")
	p.newAgent(agentA)
	p.newAgent(agentB)
	node := func(server, name string, port int) string {
		code, n, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": server, "name": name, "protocol": "ss", "port": port}, nil)
		if code != 201 {
			t.Fatalf("node: %d %v", code, n)
		}
		return n["id"].(string)
	}
	a, b := node(idA, "node-a", 50001), node(idB, "node-b", 50002)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "nodeIds": []string{a, b}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, body := p.fetch(path); code != 503 {
		t.Fatalf("subscription with nothing applied yet should ask the client to retry: %d %s", code, body)
	}
	p.applyAll(agentA)
	p.applyAll(agentB)
	served := func(when string, want ...string) {
		t.Helper()
		code, body := p.fetch(path)
		if code != 200 {
			t.Fatalf("%s: %d %s", when, code, body)
		}
		for _, name := range []string{"node-a", "node-b"} {
			expected := false
			for _, w := range want {
				expected = expected || w == name
			}
			if strings.Contains(body, name) != expected {
				t.Fatalf("%s: %s present=%v, want %v\n%s", when, name, !expected, expected, body)
			}
		}
	}
	served("both applied", "node-a", "node-b")

	// B goes silent; unrelated changes pile up on it. Its node keeps running
	// the configuration it already has, so the subscription still offers it.
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": idB, "portFrom": 8080, "portTo": 8080, "network": "tcp", "action": "allow"}, nil); code != 201 {
		t.Fatalf("firewall rule: %d %v", code, out)
	}
	served("unrelated change queued on an offline server", "node-a", "node-b")

	// An edit that changes what clients must send takes the node out until applied.
	if code, out, _ := p.do("PATCH", "/api/nodes/"+b, map[string]any{"name": "node-b", "protocol": "ss", "port": 50003, "method": "2022-blake3-aes-128-gcm", "enabled": true}, nil); code != 200 {
		t.Fatalf("edit: %d %v", code, out)
	}
	served("node edit not applied yet", "node-a")
	req := httptest.NewRequest("GET", "/api/subscriptions", nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	var subs []shared.Subscription
	if err := json.Unmarshal(rec.Body.Bytes(), &subs); err != nil || len(subs) != 1 || len(subs[0].PendingNodeIDs) != 1 || subs[0].PendingNodeIDs[0] != b || !subs[0].LinkAvailable {
		t.Fatalf("pending nodes not reported: %v %s", err, rec.Body.String())
	}
	p.applyAll(agentB)
	served("edit applied", "node-a", "node-b")

	// A failed job on A changes nothing about what A runs.
	if code, _, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": idA, "portFrom": 8081, "portTo": 8081, "network": "tcp", "action": "allow"}, nil); code != 201 {
		t.Fatal("firewall rule on A")
	}
	p.applyNext(agentA, "failed")
	served("failed job on a healthy server", "node-a", "node-b")

	// The link can be shown again, and matches the one issued.
	code, link, _ := p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/link", nil, nil)
	if code != 200 || link["url"] != sub["url"] {
		t.Fatalf("stored link: %d %v", code, link)
	}
}

func TestUFWInitIsRefusedWhenActiveAndDoesNotAdvanceTheRevision(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("s")
	if code, _, _ := p.do("POST", "/api/servers/"+id+"/ufw/init", nil, nil); code != 202 {
		t.Fatalf("ufw init on a new server: %d", code)
	}
	if server, _ := p.store.Server(id); server.Revision != 0 {
		t.Fatalf("ufw.init advanced the configuration revision to %d", server.Revision)
	}
	p.applyNext(agent, "success")
	p.newAgent(agent) // reports UFW active
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/init", nil, nil); code != 409 {
		t.Fatalf("ufw init with UFW already active: %d %v", code, out)
	}
}

func TestOldAgentWithForwardsStillReceivesNodeJobs(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("old")
	p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.3.0", "multiUserStats": true, "nodeFirewallPolicies": true, "ufwStatus": "active"}, agent)
	code, forward, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": id, "name": "f", "network": "tcp", "port": 30000, "targetHost": "192.0.2.9", "targetPort": 443, "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("forward: %d %v", code, forward)
	}
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("a forward job was sent to an agent that cannot run it: %d", code)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "ss", "port": 50001}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyNext(agent, "success") // fails the test if no job was queued
	if n, _ := p.store.Node(node["id"].(string)); n.Status != "active" {
		t.Fatalf("node status: %s", n.Status)
	}
	if f, _ := p.store.Forward(forward["id"].(string)); f.Status != "pending" {
		t.Fatalf("forward marked %s by an agent that ignored it", f.Status)
	}
	p.newAgent(agent)
	p.applyAll(agent)
	if f, _ := p.store.Forward(forward["id"].(string)); f.Status != "active" {
		t.Fatalf("forward after the agent gained support: %s", f.Status)
	}
}

func TestDeletingNodeCannotBeEdited(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("s")
	p.newAgent(agent)
	_, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "n", "protocol": "ss", "port": 50001}, nil)
	p.applyAll(agent)
	path := "/api/nodes/" + node["id"].(string)
	p.do("DELETE", path, nil, nil)
	if code, _, _ := p.do("PATCH", path, map[string]any{"name": "n", "protocol": "ss", "port": 50001, "enabled": true}, nil); code != 409 {
		t.Fatalf("edit of a node being deleted: %d", code)
	}
	if n, _ := p.store.Node(node["id"].(string)); !n.Deleting {
		t.Fatal("deletion was cancelled by the edit")
	}
}

func TestSecondFactorLocksAfterRepeatedWrongCodesAndRejectsReplay(t *testing.T) {
	p := newTestMui(t)
	_, setup, _ := p.do("POST", "/api/totp/setup", nil, nil)
	secret := setup["secret"].(string)
	if code, _, _ := p.do("POST", "/api/totp/enable", map[string]string{"code": totpCode(secret, time.Now())}, nil); code != 200 {
		t.Fatal("enable")
	}
	p.cookie = nil
	login := func(code string, from string) int {
		status, _, _ := p.do("POST", "/api/login", map[string]string{"password": testPassword, "code": code}, map[string]string{"RemoteAddr": from})
		return status
	}
	good := totpCode(secret, time.Now())
	if status := login(good, "198.51.100.1:1"); status != 200 {
		t.Fatalf("login: %d", status)
	}
	if status := login(good, "198.51.100.2:1"); status != 401 {
		t.Fatalf("a code was accepted twice: %d", status)
	}
	// Wrong codes from different addresses still add up for the account.
	for i := 0; i < 5; i++ {
		login("000000", fmt.Sprintf("198.51.100.%d:1", 10+i))
	}
	if status := login(totpCode(secret, time.Now().Add(30*time.Second)), "198.51.100.99:1"); status != 401 {
		t.Fatalf("second factor not locked after repeated failures: %d", status)
	}
}
