package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

// createTestNode creates a node and returns its decoded response.
func createTestNode(t *testing.T, p *testMui, serverID, name string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"serverId": serverID, "name": name, "protocol": "ss", "port": 50000, "direct": true,
		"method": "2022-blake3-aes-128-gcm",
	}
	for k, v := range extra {
		body[k] = v
	}
	code, node, _ := p.do("POST", "/api/nodes", body, nil)
	if code != 201 {
		t.Fatalf("node create: %d %v", code, node)
	}
	return node
}

// rawDo performs a request without the do() harness signing, for tests that
// need precise control over the agent signature headers.
func rawDo(t *testing.T, p *testMui, method, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// TestOldAgentStillReceivesUpgradeBehindFirewallGate: an agent that cannot
// apply firewall policies skips *.apply jobs but still receives upgrades.
func TestOldAgentStillReceivesUpgradeBehindFirewallGate(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("gate-server")
	node := createTestNode(t, p, serverID, "manual-node", nil)
	if code, updated, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), map[string]any{
		"name": "manual-node", "protocol": "ss", "port": 50000,
		"method": "aes-128-gcm", "enabled": true, "firewallPolicy": "manual",
	}, nil); code != 200 {
		t.Fatalf("manual node update: %d %v", code, updated)
	}
	now := time.Now()
	op := shared.Operation{ID: ID(), ServerID: serverID, Kind: "agent.upgrade", Status: "queued", TargetBuild: "deadbeef", Revision: 0, CreatedAt: now, UpdatedAt: now}
	if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "agent.upgrade" {
		t.Fatalf("old Agent should receive the upgrade job: %d %v", code, job)
	}
}

// TestValidateNodeRejectsPrivilegedPorts: node ports must be >= 1024.
func TestValidateNodeAcceptsPrivilegedPorts(t *testing.T) {
	// sing-box runs with CAP_NET_BIND_SERVICE; 443 is the usual AnyTLS and
	// ShadowTLS port and existing nodes use it.
	node := shared.Node{Name: "test", Protocol: "ss", Port: 443, Method: "aes-128-gcm"}
	if err := shared.ValidateNode(node, nil, false); err != nil {
		t.Fatalf("port 443 should be accepted: %v", err)
	}
	for _, port := range []int{0, 65536, shared.StatsAPIPort} {
		node.Port = port
		if err := shared.ValidateNode(node, nil, false); err == nil {
			t.Fatalf("port %d should be rejected", port)
		}
	}
}

// TestForwardTargetResolvingToServerIsRejected: a target that resolves to
// the server's own address or to loopback is refused.
func TestForwardTargetResolvingToServerIsRejected(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("forward-server")
	self := map[string]any{
		"serverId": serverID, "name": "self", "network": "tcp",
		"port": 18080, "targets": []map[string]any{{"host": "203.0.113.10", "port": 9999}}, "enabled": true,
	}
	if code, out, _ := p.do("POST", "/api/forwards", self, nil); code != 409 {
		t.Fatalf("forward to the server's own address should be rejected: %d %v", code, out)
	}
	unresolvable := map[string]any{
		"serverId": serverID, "name": "ghost", "network": "tcp",
		"port": 18081, "targets": []map[string]any{{"host": "nonexistent.invalid", "port": 9999}}, "enabled": true,
	}
	// The panel's resolver is not the relay's (split-horizon names, a DDNS name
	// that is briefly down); the agent resolves at run time and applies the
	// address rules there, so an unresolvable name is accepted here.
	if code, out, _ := p.do("POST", "/api/forwards", unresolvable, nil); code != 201 {
		t.Fatalf("forward to a name the panel cannot resolve: %d %v", code, out)
	}
	loopback := map[string]any{
		"serverId": serverID, "name": "loop", "network": "tcp",
		"port": 18082, "targets": []map[string]any{{"host": "127.0.0.1", "port": 9999}}, "enabled": true,
	}
	if code, out, _ := p.do("POST", "/api/forwards", loopback, nil); code != 409 {
		t.Fatalf("forward to loopback should be rejected: %d %v", code, out)
	}
}

// TestFencingTokenMismatchRejected: a report with the wrong fencing token is
// refused; the same job reported with the right token succeeds.
func TestFencingTokenMismatchRejected(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("fencing-server")
	createTestNode(t, p, serverID, "fenced-node", nil)
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 {
		t.Fatalf("job: %d %v", code, job)
	}
	if job["fencingToken"] == nil || job["fencingToken"] == "" {
		t.Fatal("job should carry a fencing token")
	}
	code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"jobId": job["id"], "jobStatus": "success", "fencingToken": "wrong-token",
	}, agent)
	if code != 409 {
		t.Fatalf("wrong fencing token should be rejected: %d %v", code, out)
	}
	code, out, _ = p.do("POST", "/agent/report", map[string]any{
		"jobId": job["id"], "jobStatus": "success",
	}, agent)
	if code != 200 {
		t.Fatalf("correct fencing token should be accepted: %d %v", code, out)
	}
}

// TestAgentReportValidationBeforeWrites: an invalid job status, or a job
// that belongs to another server, must not leave traffic behind.
func TestAgentReportValidationBeforeWrites(t *testing.T) {
	p := newTestMui(t)
	serverAID, agentA := p.enroll("report-a")
	nodeA := createTestNode(t, p, serverAID, "node-a", nil)
	code, jobA, _ := p.do("GET", "/agent/job", nil, agentA)
	if code != 200 {
		t.Fatalf("job A: %d %v", code, jobA)
	}
	point := func(nodeID string) map[string]any {
		return map[string]any{"nodeId": nodeID, "instanceId": "i1", "sequence": 1, "uplink": 10, "downlink": 20, "at": time.Now()}
	}
	code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"jobId": jobA["id"], "jobStatus": "bogus", "traffic": []any{point(nodeA["id"].(string))},
	}, agentA)
	if code != 400 {
		t.Fatalf("invalid job status should be rejected: %d %v", code, out)
	}
	totals, err := p.store.NodeTotals()
	if err != nil {
		t.Fatal(err)
	}
	if got := totals[nodeA["id"].(string)]; got[0] != 0 || got[1] != 0 {
		t.Fatalf("invalid report left traffic behind: %v", got)
	}

	serverBID, agentB := p.enroll("report-b")
	nodeB := createTestNode(t, p, serverBID, "node-b", nil)
	code, out, _ = p.do("POST", "/agent/report", map[string]any{
		"jobId": jobA["id"], "jobStatus": "success", "traffic": []any{point(nodeB["id"].(string))},
	}, agentB)
	if code != 404 {
		t.Fatalf("another server's job should be rejected: %d %v", code, out)
	}
	totals, err = p.store.NodeTotals()
	if err != nil {
		t.Fatal(err)
	}
	if got := totals[nodeB["id"].(string)]; got[0] != 0 || got[1] != 0 {
		t.Fatalf("cross-server report left traffic behind: %v", got)
	}
}

// TestSubscriptionDownloadAllSkippedReturns503: when every node is skipped
// for a permanent reason the download fails loudly instead of serving an
// empty configuration.
func TestSubscriptionDownloadAllSkippedReturns503(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("sub-server")
	node := createTestNode(t, p, serverID, "off-node", map[string]any{"enabled": false})
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "Main", "format": "sing-box", "nodeIds": []string{node["id"].(string)},
	}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	url := sub["url"].(string)
	token := url[strings.LastIndex(url, "/")+1:]
	code, body := rawDo(t, p, "GET", "/s/"+token, nil, nil)
	if code != 503 {
		t.Fatalf("all-skipped subscription should return 503: %d %s", code, body)
	}
}

// TestCreateRespectsEnabledFalse: creation honors an explicit enabled:false.
func TestCreateRespectsEnabledFalse(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("enabled-server")
	node := createTestNode(t, p, serverID, "off-node", map[string]any{"enabled": false})
	if node["enabled"] != false {
		t.Fatalf("node enabled should be false: %v", node)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "Off", "format": "sing-box", "enabled": false, "nodeIds": []string{},
	}, nil)
	if code != 201 || sub["enabled"] != false {
		t.Fatalf("subscription enabled should be false: %d %v", code, sub)
	}
}

// TestCreateForcesDeletingFalse: a client cannot create a node or firewall
// rule that is already marked deleting.
func TestCreateForcesDeletingFalse(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("deleting-server")
	node := createTestNode(t, p, serverID, "fresh-node", map[string]any{"deleting": true})
	if node["deleting"] != false {
		t.Fatalf("node deleting should be false: %v", node)
	}
	code, rule, _ := p.do("POST", "/api/firewall", map[string]any{
		"serverId": serverID, "portFrom": 8443, "portTo": 8443,
		"network": "tcp", "action": "allow", "deleting": true,
	}, nil)
	if code != 201 || rule["deleting"] != false {
		t.Fatalf("firewall deleting should be false: %d %v", code, rule)
	}
}

// TestWeakSecretRejected: a short or single-class secret must not open a store.
func TestWeakSecretRejected(t *testing.T) {
	for _, secret := range []string{"short", strings.Repeat("a", 32), strings.Repeat("a1", 16)} {
		if _, err := NewStore(filepath.Join(t.TempDir(), "mui.db"), secret); err == nil {
			t.Fatalf("weak secret %q should be rejected", secret)
		}
	}
}

// TestListPaginationEnvelope: ?limit= returns the envelope; no parameter
// returns the legacy bare array.
func TestListPaginationEnvelope(t *testing.T) {
	p := newTestMui(t)
	for _, name := range []string{"page-a", "page-b", "page-c"} {
		if code, _, _ := p.do("POST", "/api/servers", map[string]any{"name": name, "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.10"}, nil); code != 201 {
			t.Fatalf("server %s: %d", name, code)
		}
	}
	code, body := rawDo(t, p, "GET", "/api/servers?limit=2", nil, nil)
	if code != 200 {
		t.Fatalf("paged list: %d %s", code, body)
	}
	var page map[string]any
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	items, ok := page["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("first page should have 2 items: %v", page)
	}
	if page["total"] != float64(3) || page["nextCursor"] == nil || page["nextCursor"] == "" {
		t.Fatalf("envelope should carry total and nextCursor: %v", page)
	}
	code, body = rawDo(t, p, "GET", "/api/servers?limit=2&cursor="+page["nextCursor"].(string), nil, nil)
	if code != 200 {
		t.Fatalf("second page: %d %s", code, body)
	}
	var page2 map[string]any
	if err := json.Unmarshal(body, &page2); err != nil {
		t.Fatal(err)
	}
	if items2, ok := page2["items"].([]any); !ok || len(items2) != 1 {
		t.Fatalf("second page should have 1 item: %v", page2)
	}
	code, body = rawDo(t, p, "GET", "/api/servers", nil, nil)
	var bare []any
	if err := json.Unmarshal(body, &bare); err != nil || len(bare) != 3 {
		t.Fatalf("unpaged list should be a bare array of 3: %d %s", code, body)
	}
}

// TestSecurityHeadersIncludeCSP: responses carry a restrictive CSP.
func TestSecurityHeadersIncludeCSP(t *testing.T) {
	p := newTestMui(t)
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "object-src 'none'") || !strings.Contains(csp, "img-src 'self' data:") {
		t.Fatalf("CSP is missing or too loose: %q", csp)
	}
}

// TestUpgradeFailureDoesNotMarkNodesError: a failed job only marks pending
// nodes as errored when it is a configuration apply. Upgrade failures, and
// failures of non-apply jobs, must not.
func TestUpgradeFailureDoesNotMarkNodesError(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("upgrade-fail-server")
	now := time.Now()
	op := shared.Operation{ID: ID(), ServerID: serverID, Kind: "agent.upgrade", Status: "queued", TargetBuild: "deadbeef", Revision: 0, CreatedAt: now, UpdatedAt: now}
	if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	node := createTestNode(t, p, serverID, "upgrade-node", nil)
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "agent.upgrade" {
		t.Fatalf("upgrade job: %d %v", code, job)
	}
	code, out, _ := p.do("POST", "/agent/report", map[string]any{
		"jobId": job["id"], "jobStatus": "failed", "jobError": "download failed",
	}, agent)
	if code != 200 {
		t.Fatalf("upgrade failure report: %d %v", code, out)
	}
	stored, err := p.store.Node(node["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "pending" {
		t.Fatalf("upgrade failure marked node %s: %s", stored.ID, stored.Status)
	}

	// A failed non-apply job at the current revision must not mark nodes
	// either: only *.apply failures touch node/rule/forward status.
	serverID2, agent2 := p.enroll("non-apply-fail-server")
	node2 := createTestNode(t, p, serverID2, "non-apply-node", nil)
	if err := p.store.SupersedeQueuedApply(serverID2); err != nil {
		t.Fatal(err)
	}
	server2, err := p.store.Server(serverID2)
	if err != nil {
		t.Fatal(err)
	}
	op2 := shared.Operation{ID: ID(), ServerID: serverID2, Kind: "health.check", Status: "queued", Revision: server2.Revision, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := p.store.PutOperation(op2, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	code, job2, _ := p.do("GET", "/agent/job", nil, agent2)
	if code != 200 || job2["kind"] != "health.check" {
		t.Fatalf("non-apply job: %d %v", code, job2)
	}
	code, out, _ = p.do("POST", "/agent/report", map[string]any{
		"jobId": job2["id"], "jobStatus": "failed", "jobError": "check failed",
	}, agent2)
	if code != 200 {
		t.Fatalf("non-apply failure report: %d %v", code, out)
	}
	stored2, err := p.store.Node(node2["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if stored2.Status != "pending" {
		t.Fatalf("non-apply failure marked node %s: %s", stored2.ID, stored2.Status)
	}
}

// TestAuditPruning: PruneAudit removes only rows older than the cutoff.
func TestAuditPruning(t *testing.T) {
	p := newTestMui(t)
	oldAt := time.Now().Add(-48 * time.Hour).UnixMilli()
	if _, err := p.store.DB.Exec(`INSERT INTO mui_audit(id,at_ms,action,target,detail) VALUES($1,$2,'test.old','x','')`, ID(), oldAt); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PruneAudit(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_audit WHERE action='test.old'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old audit row should be pruned: %d %v", count, err)
	}
	p.store.Audit("test.fresh", "x", "")
	if err := p.store.PruneAudit(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_audit WHERE action='test.fresh'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("fresh audit row should survive: %d %v", count, err)
	}
}

// TestTOTPPendingSecretEncrypted: the pending TOTP secret is stored encrypted.
func TestTOTPPendingSecretEncrypted(t *testing.T) {
	p := newTestMui(t)
	if code, _, _ := p.do("POST", "/api/totp/setup", nil, nil); code != 200 {
		t.Fatalf("totp setup: %d", code)
	}
	var stored string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_totp_pending`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("pending TOTP secret should be encrypted, got %q", stored)
	}
}

// TestSessionIdleTimeout: a session idle for more than 24h is rejected.
func TestSessionIdleTimeout(t *testing.T) {
	p := newTestMui(t)
	if _, err := p.store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, time.Now().Add(-49*time.Hour).Unix(), Hash(p.cookie.Value)); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 401 {
		t.Fatalf("idle session should be rejected: %d", code)
	}
}

// TestDesiredStateIsSigned: a claimed job's desired state carries the panel
// signature and protocol version 1.
func TestDesiredStateIsSigned(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("signed-server")
	createTestNode(t, p, serverID, "signed-node", nil)
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 {
		t.Fatalf("job: %d %v", code, job)
	}
	state, ok := job["state"].(map[string]any)
	if !ok {
		t.Fatalf("job should carry a desired state: %v", job)
	}
	if state["signature"] == nil || state["signature"] == "" {
		t.Fatal("desired state should be signed")
	}
	if state["protocolVersion"] != float64(1) {
		t.Fatalf("desired state protocolVersion should be 1: %v", state["protocolVersion"])
	}
}

// TestReportArrayLimit: more than 2000 points in one report array is rejected.
func TestReportArrayLimit(t *testing.T) {
	p := newTestMui(t)
	_, agent := p.enroll("limit-server")
	points := make([]any, 0, 2001)
	for i := 0; i < 2001; i++ {
		points = append(points, map[string]any{"nodeId": "x", "instanceId": "i", "sequence": i, "uplink": 1, "downlink": 1, "at": time.Now()})
	}
	code, out, _ := p.do("POST", "/agent/report", map[string]any{"traffic": points}, agent)
	if code != 400 {
		t.Fatalf("oversized report should be rejected: %d %v", code, out)
	}
}

// TestEnrollReturnsPanelPublicKey: enrollment returns the panel signing key.
func TestEnrollReturnsPanelPublicKey(t *testing.T) {
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "key-server", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.10"}, nil)
	if code != 201 {
		t.Fatalf("server: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	code, agent, _ := p.do("POST", "/agent/enroll", map[string]string{"serverId": id, "token": out["enrollToken"].(string)}, nil)
	if code != 200 || agent["panelPublicKey"] == nil || agent["panelPublicKey"] == "" {
		t.Fatalf("enroll should return panelPublicKey: %d %v", code, agent)
	}
}

// TestUnsignedAgentRequests: reports require a signature; job polling does
// not, so an old agent can still fetch its upgrade.
func TestUnsignedAgentRequests(t *testing.T) {
	p := newTestMui(t)
	_, agent := p.enroll("unsigned-server")
	// An agent that predates request signing keeps reporting until upgraded.
	if code, body := rawDo(t, p, "POST", "/agent/report", map[string]any{"agentVersion": "0.1.0"}, agent); code != 200 {
		t.Fatalf("unsigned report from an agent that never signed: %d %s", code, body)
	}
	if code, _ := rawDo(t, p, "GET", "/agent/job", nil, agent); code != 200 && code != 204 {
		t.Fatalf("unsigned job poll should be allowed for migration: %d", code)
	}
	// It can also complete a job without echoing the fencing token it never knew about.
	p.do("POST", "/api/servers/"+serverIDOf(agent)+"/ufw/init", nil, nil)
	if code, body := rawDo(t, p, "GET", "/agent/job", nil, agent); code == 200 {
		var job map[string]any
		_ = json.Unmarshal(body, &job)
		if code, body := rawDo(t, p, "POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agent); code != 200 {
			t.Fatalf("legacy job result: %d %s", code, body)
		}
	} else {
		t.Fatalf("legacy agent did not receive its job: %d", code)
	}
	// Once the agent has signed a request, unsigned ones are refused, so a
	// stripped signature cannot downgrade it.
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0"}, agent); code != 200 {
		t.Fatalf("signed report: %d %v", code, out)
	}
	if code, _ := rawDo(t, p, "POST", "/agent/report", map[string]any{"agentVersion": "0.1.0"}, agent); code != 401 {
		t.Fatalf("unsigned report after the agent started signing: %d", code)
	}
	if code, _ := rawDo(t, p, "GET", "/agent/job", nil, agent); code != 401 {
		t.Fatalf("unsigned job poll after the agent started signing: %d", code)
	}
}

// makeTestCertificate generates a self-signed certificate for cert tests.
func makeTestCertificate(t *testing.T, isCA bool, eku []x509.ExtKeyUsage, days int) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           eku,
		DNSNames:              []string{"example.com"},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}

// TestCertificateEKUAndExpiry: certificates need ServerAuth EKU and must not
// be CAs; the list reports days until expiry.
func TestCertificateEKUAndExpiry(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("cert-server")
	post := func(certPEM, keyPEM string) (int, map[string]any) {
		code, out, _ := p.do("POST", "/api/certificates", map[string]any{
			"serverId": serverID, "domain": "example.com", "pem": certPEM, "key": keyPEM,
		}, nil)
		return code, out
	}
	certPEM, keyPEM := makeTestCertificate(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 10)
	code, cert := post(certPEM, keyPEM)
	if code != 201 {
		t.Fatalf("serverAuth certificate should be accepted: %d %v", code, cert)
	}
	certPEM, keyPEM = makeTestCertificate(t, false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 10)
	if code, out := post(certPEM, keyPEM); code != 400 {
		t.Fatalf("clientAuth-only certificate should be rejected: %d %v", code, out)
	}
	certPEM, keyPEM = makeTestCertificate(t, true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 10)
	if code, out := post(certPEM, keyPEM); code != 400 {
		t.Fatalf("CA certificate should be rejected: %d %v", code, out)
	}
	certPEM, keyPEM = makeTestCertificate(t, false, nil, 400)
	if code, out := post(certPEM, keyPEM); code != 201 {
		t.Fatalf("certificate without EKU should be accepted: %d %v", code, out)
	}
	code, body := rawDo(t, p, "GET", "/api/certificates?serverId="+serverID, nil, nil)
	if code != 200 {
		t.Fatalf("certificate list: %d %s", code, body)
	}
	var list []map[string]any
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 2 {
		t.Fatalf("certificate list should have 2 entries: %d %s", code, body)
	}
	for _, c := range list {
		if c["expiringSoon"] == nil || c["daysUntilExpiry"] == nil {
			t.Fatalf("certificate should report expiry: %v", c)
		}
	}
}

func serverIDOf(agent map[string]string) string { return agent["X-Server-ID"] }
