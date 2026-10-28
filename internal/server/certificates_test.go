package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestNginxPEMChainAndRSAKeyUpload(t *testing.T) {
	p := newTestMui(t)
	rootPEM, rootKeyPEM := makeTestCertificate(t, true, nil, 30)
	block, _ := pem.Decode([]byte(rootPEM))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode([]byte(rootKeyPEM))
	rootKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "*.example.com"}, DNSNames: []string{"*.example.com", "example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + rootPEM
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind string
		der        []byte
	}{{"nginx RSA PKCS1", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)}, {"nginx PKCS8", "PRIVATE KEY", pkcs8}} {
		t.Run(tc.name, func(t *testing.T) {
			private := string(pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.der}))
			code, out, _ := p.do("POST", "/api/certificates", map[string]any{"pem": chain, "key": private}, nil)
			if code != 201 {
				t.Fatalf("standard Nginx pair rejected: %d %v", code, out)
			}
			if out["domain"] != "*.example.com" || out["name"] != "*.example.com" || out["key"] != nil {
				t.Fatal("incorrect inferred metadata or private key in response")
			}
			cert, err := p.store.Certificate(out["id"].(string))
			if err != nil || cert.PEM != chain || len(cert.DNSNames) != 2 {
				t.Fatal("chain or DNS names lost", err)
			}
			storedKey, err := p.store.CertificateKey(cert.ID)
			if err != nil || storedKey != private {
				t.Fatal("private key changed", err)
			}
			if !shared.CertificateCovers(cert.PEM, "node.example.com") || shared.CertificateCovers(cert.PEM, "a.b.example.com") {
				t.Fatal("wildcard coverage is wrong")
			}
		})
	}
	if code, out, _ := p.do("POST", "/api/certificates", map[string]any{"pem": chain, "key": rootKeyPEM}, nil); code != 400 || !strings.Contains(out["error"].(string), "证书与私钥不匹配") {
		t.Fatal("mismatched pair accepted or error unclear", code)
	}
	code, out, _ := p.do("GET", "/api/certificates", nil, nil)
	if code != 200 {
		t.Fatal(code, out)
	}
}

func TestCertificateSharedAcrossServers(t *testing.T) {
	p := newTestMui(t)
	certPEM, keyPEM := makeTestCertificate(t, false, nil, 30)
	// Upload before any server exists, without a serverId.
	code, cert, _ := p.do("POST", "/api/certificates", map[string]any{
		"name": "shared", "domain": "example.com", "pem": certPEM, "key": keyPEM,
	}, nil)
	if code != 201 || cert["key"] != nil || cert["serverId"] != nil {
		t.Fatalf("global certificate upload: %d %v", code, cert)
	}
	certID := cert["id"].(string)
	var encrypted string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_certificates WHERE id=$1`, certID).Scan(&encrypted); err != nil || strings.Contains(encrypted, keyPEM) {
		t.Fatalf("private key not encrypted: %v", err)
	}
	if key, err := p.store.CertificateKey(certID); err != nil || key != keyPEM {
		t.Fatalf("private key changed: %v", err)
	}

	servers := []string{}
	agents := []map[string]string{}
	for _, name := range []string{"first", "second", "unrelated"} {
		id, agent := p.enrollAs(name, []string{shared.RoleExit}, map[string]any{"ipv4": "192.0.2.1"})
		servers = append(servers, id)
		agents = append(agents, agent)
	}
	nodeIDs := []string{}
	for _, id := range servers[:2] {
		body := map[string]any{"serverId": id, "name": "AnyTLS", "protocol": "anytls", "port": 50443,
			"tlsName": "example.com", "certificateId": certID, "enabled": true}
		code, node, _ := p.do("POST", "/api/nodes", body, nil)
		if code != 201 {
			t.Fatalf("node sharing certificate: %d %v", code, node)
		}
		nodeIDs = append(nodeIDs, node["id"].(string))
		if code, out, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), body, nil); code != 200 {
			t.Fatalf("edit node sharing certificate: %d %v", code, out)
		}
		body["tlsName"] = "uncovered.example.net"
		if code, out, _ := p.do("PATCH", "/api/nodes/"+node["id"].(string), body, nil); code != 400 {
			t.Fatalf("uncovered TLS name accepted: %d %v", code, out)
		}
	}
	for i, id := range servers {
		state, err := p.app.desired(id)
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if len(state.Nodes) != 0 || strings.Contains(Marshal(state), keyPEM) {
				t.Fatal("unrelated server received shared private key")
			}
			continue
		}
		if len(state.Nodes) != 1 || state.Nodes[0].CertificatePEM != certPEM || state.Nodes[0].CertificateKey != keyPEM {
			t.Fatal("certificate was not dispatched to the referencing server")
		}
		p.applyAll(agents[i]) // Includes real Agent configuration validation.
	}
	if code, out, _ := p.do("DELETE", "/api/certificates/"+certID, nil, nil); code != 409 {
		t.Fatalf("in-use certificate deleted: %d %v", code, out)
	}
	// An offline server's force deletion must preserve certificates shared by
	// nodes on another server, including their original encrypted private key.
	first, _ := p.store.Server(servers[0])
	first.LastSeen = nil
	if _, err := p.store.DB.Exec(`UPDATE mui_servers SET data=$1 WHERE id=$2`, Marshal(first), first.ID); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("DELETE", "/api/servers/"+first.ID+"?force=1", nil, nil); code != 200 {
		t.Fatalf("server deletion: %d %v", code, out)
	}
	if key, err := p.store.CertificateKey(certID); err != nil || key != keyPEM {
		t.Fatalf("server deletion removed shared certificate: %v", err)
	}
	if code, out, _ := p.do("DELETE", "/api/certificates/"+certID, nil, nil); code != 409 {
		t.Fatalf("certificate still used on second server deleted: %d %v", code, out)
	}
	if code, out, _ := p.do("DELETE", "/api/nodes/"+nodeIDs[1], nil, nil); code != 202 {
		t.Fatalf("last node deletion: %d %v", code, out)
	}
	if code, _, _ := p.do("DELETE", "/api/certificates/"+certID, nil, nil); code != 409 {
		t.Fatal("certificate deleted before Agent confirmed node removal")
	}
	p.applyAll(agents[1])
	if code, out, _ := p.do("DELETE", "/api/certificates/"+certID, nil, nil); code != 200 {
		t.Fatalf("unused certificate deletion: %d %v", code, out)
	}
}

func TestCertificateRenewalKeepsReferencesAndQueuesAffectedServers(t *testing.T) {
	p := newTestMui(t)
	oldPEM, oldKey := makeTestCertificate(t, false, nil, 30)
	code, created, _ := p.do("POST", "/api/certificates", map[string]any{"pem": oldPEM, "key": oldKey}, nil)
	if code != 201 {
		t.Fatal(code, created)
	}
	id := created["id"].(string)
	servers := make([]string, 0, 3)
	agents := make([]map[string]string, 0, 3)
	for _, name := range []string{"first", "second", "unrelated"} {
		serverID, agent := p.enrollAs(name, []string{shared.RoleExit}, map[string]any{"ipv4": "192.0.2.1"})
		servers = append(servers, serverID)
		agents = append(agents, agent)
	}
	for i, serverID := range servers[:2] {
		code, node, _ := p.do("POST", "/api/nodes", map[string]any{
			"serverId": serverID, "name": "TLS " + servers[i], "protocol": "anytls", "port": 50443,
			"tlsName": "example.com", "certificateId": id, "enabled": true,
		}, nil)
		if code != 201 {
			t.Fatal(code, node)
		}
		p.applyAll(agents[i])
	}
	before := make([]shared.Server, len(servers))
	for i, serverID := range servers {
		var err error
		before[i], err = p.store.Server(serverID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"id": id, "name": "renamed"}, nil); code != 200 || out["name"] != "renamed" || out["key"] != nil || out["pem"] != nil {
		t.Fatalf("metadata-only edit failed or leaked PEM: %d %v", code, out)
	}
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"id": "wrong", "name": "invalid"}, nil); code != 400 {
		t.Fatalf("mismatched certificate ID accepted: %d %v", code, out)
	}
	if key, err := p.store.CertificateKey(id); err != nil || key != oldKey {
		t.Fatalf("metadata edit replaced key: %v", err)
	}
	for i, serverID := range servers {
		server, err := p.store.Server(serverID)
		if err != nil || server.Revision != before[i].Revision {
			t.Fatalf("metadata edit unexpectedly queued server %d: %v", i, err)
		}
	}
	newPEM, newKey := makeTestCertificate(t, false, nil, 60)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"pem": newPEM}, nil); code != 400 {
		t.Fatalf("accepted replacement without matching key: %d %v", code, out)
	}
	otherPEM, otherKey := makeTestCertificate(t, false, nil, 60, "other.example.net")
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"pem": otherPEM, "key": otherKey, "domain": "other.example.net"}, nil); code != 409 {
		t.Fatalf("accepted certificate that does not cover referencing nodes: %d %v", code, out)
	}
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"pem": newPEM, "key": newKey}, nil); code != 200 || out["id"] != id || out["key"] != nil || out["pem"] != nil {
		t.Fatalf("certificate renewal failed or leaked PEM: %d %v", code, out)
	}
	for i, serverID := range servers {
		server, err := p.store.Server(serverID)
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if server.Revision != before[i].Revision {
				t.Fatal("unrelated server was reconfigured")
			}
			continue
		}
		if server.Revision != before[i].Revision+1 {
			t.Fatalf("server %d was not queued for one certificate update: %d -> %d", i, before[i].Revision, server.Revision)
		}
		state, err := p.app.desired(serverID)
		if err != nil || len(state.Nodes) != 1 || state.Nodes[0].CertificatePEM != newPEM || state.Nodes[0].CertificateKey != newKey || state.Nodes[0].Node.CertificateID != id {
			t.Fatalf("new certificate not dispatched to server %d: %v", i, err)
		}
		code, job, _ := p.do("GET", "/agent/job", nil, agents[i])
		if code != 200 || job["kind"] != "nodes.apply" {
			t.Fatalf("server %d did not receive certificate apply job: %d %v", i, code, job)
		}
		raw, err := json.Marshal(job["state"])
		if err != nil {
			t.Fatal(err)
		}
		var queued shared.DesiredState
		if err := json.Unmarshal(raw, &queued); err != nil || len(queued.Nodes) != 1 || queued.Nodes[0].CertificatePEM != newPEM || queued.Nodes[0].CertificateKey != newKey {
			t.Fatalf("server %d job snapshot has stale certificate: %v", i, err)
		}
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agents[i]); code != 200 {
			t.Fatalf("server %d did not acknowledge certificate apply: %d %v", i, code, out)
		}
		p.applyAll(agents[i])
		server, _ = p.store.Server(serverID)
		if server.AppliedRevision != server.Revision {
			t.Fatalf("server %d did not apply new certificate", i)
		}
	}
	var encrypted string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_certificates WHERE id=$1`, id).Scan(&encrypted); err != nil || strings.Contains(encrypted, newKey) {
		t.Fatalf("renewed key not encrypted: %v", err)
	}
	// A failure to build one server's desired state must not prevent the other
	// servers from receiving their new certificate snapshots.
	var originalNodeSecret string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE server_id=$1`, servers[0]).Scan(&originalNodeSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret='invalid' WHERE server_id=$1`, servers[0]); err != nil {
		t.Fatal(err)
	}
	newerPEM, newerKey := makeTestCertificate(t, false, nil, 90)
	secondBefore, _ := p.store.Server(servers[1])
	code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"pem": newerPEM, "key": newerKey}, nil)
	if code != 503 || !strings.Contains(out["error"].(string), "first") {
		t.Fatalf("partial apply failure was not reported: %d %v", code, out)
	}
	secondAfter, _ := p.store.Server(servers[1])
	if secondAfter.Revision != secondBefore.Revision+1 {
		t.Fatal("a failed server prevented another server from being queued")
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agents[1])
	if code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("healthy server lost its certificate job: %d %v", code, job)
	}
	raw, err := json.Marshal(job["state"])
	if err != nil {
		t.Fatal(err)
	}
	var queued shared.DesiredState
	if err := json.Unmarshal(raw, &queued); err != nil || len(queued.Nodes) != 1 || queued.Nodes[0].CertificatePEM != newerPEM || queued.Nodes[0].CertificateKey != newerKey {
		t.Fatalf("healthy server received stale certificate after partial failure: %v", err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret=$1 WHERE server_id=$2`, originalNodeSecret, servers[0]); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{"pem": newerPEM, "key": newerKey}, nil); code != 200 {
		t.Fatalf("retry with the same certificate did not queue the recovered server: %d %v", code, out)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, agents[0]); code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("recovered server did not receive certificate job: %d %v", code, job)
	}
}

func certificatePendingServers(t *testing.T, p *testMui, id string) []string {
	t.Helper()
	code, raw := rawDo(t, p, "GET", "/api/certificates", nil, nil)
	if code != 200 {
		t.Fatalf("certificate list: %d %s", code, raw)
	}
	var list []struct {
		ID             string   `json:"id"`
		PendingServers []string `json:"pendingServers"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.ID == id {
			return c.PendingServers
		}
	}
	t.Fatalf("certificate %s missing from list", id)
	return nil
}

func TestCertificateReplacementPendingPreservesSubscription(t *testing.T) {
	p := newTestMui(t)
	oldPEM, oldKey := makeTestCertificate(t, false, nil, 30)
	code, cert, _ := p.do("POST", "/api/certificates", map[string]any{"pem": oldPEM, "key": oldKey}, nil)
	if code != 201 {
		t.Fatal(code, cert)
	}
	certID := cert["id"].(string)
	serverID, agent := p.enroll("certificate-server")
	p.newAgent(agent)
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "AnyTLS", "protocol": "anytls", "port": 50443,
		"tlsName": "example.com", "certificateId": certID, "enabled": true, "direct": true,
	}, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	nodeID := node["id"].(string)
	code, disabledNode, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "Disabled AnyTLS", "protocol": "anytls", "port": 50444,
		"tlsName": "example.com", "certificateId": certID, "enabled": false,
	}, nil)
	if code != 201 {
		t.Fatal(code, disabledNode)
	}
	disabledNodeID := disabledNode["id"].(string)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "certificate-sub", "format": "surge", "nodeIds": []string{nodeID}, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatal(code, sub)
	}
	p.applyAll(agent)
	// Older installations may still rely on the server-wide applied revision
	// because no per-node deployment snapshot has been recorded yet.
	if _, err := p.store.DB.Exec(`DELETE FROM mui_server_applied WHERE server_id=$1`, serverID); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	beforeCode, beforeContent := p.fetch(path)
	if beforeCode != 200 {
		t.Fatalf("subscription unavailable before renewal: %d %s", beforeCode, beforeContent)
	}
	var nodeSecretBefore string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, nodeID).Scan(&nodeSecretBefore); err != nil {
		t.Fatal(err)
	}
	newPEM, newKey := makeTestCertificate(t, false, nil, 60)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"pem": newPEM, "key": newKey}, nil); code != 200 {
		t.Fatalf("renewal: %d %v", code, out)
	}
	updated, err := p.store.Node(nodeID)
	if err != nil || updated.Status != "pending" || updated.Error != "" {
		t.Fatalf("renewed node is not pending: %v %v", updated, err)
	}
	disabledUpdated, err := p.store.Node(disabledNodeID)
	if err != nil || disabledUpdated.Status != "pending" {
		t.Fatalf("disabled referencing node is not pending: %v %v", disabledUpdated, err)
	}
	var nodeSecretAfter string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, nodeID).Scan(&nodeSecretAfter); err != nil || nodeSecretAfter != nodeSecretBefore {
		t.Fatalf("renewal changed encrypted node credential: %v", err)
	}
	if got := certificatePendingServers(t, p, certID); len(got) != 1 || got[0] != "certificate-server" {
		t.Fatalf("pending certificate servers: %v", got)
	}
	if code, content := p.fetch(path); code != 200 || content != beforeContent {
		t.Fatalf("renewal removed the existing subscription node: %d %s", code, content)
	}
	p.applyAll(agent)
	updated, err = p.store.Node(nodeID)
	if err != nil || updated.Status != "active" {
		t.Fatalf("applied node is not active: %v %v", updated, err)
	}
	disabledUpdated, err = p.store.Node(disabledNodeID)
	if err != nil || disabledUpdated.Status != "disabled" {
		t.Fatalf("disabled node did not return to disabled status: %v %v", disabledUpdated, err)
	}
	if got := certificatePendingServers(t, p, certID); len(got) != 0 {
		t.Fatalf("pending servers remained after successful apply: %v", got)
	}
}

func TestCertificateRetryWithoutFiles(t *testing.T) {
	p := newTestMui(t)
	oldPEM, oldKey := makeTestCertificate(t, false, nil, 30)
	code, cert, _ := p.do("POST", "/api/certificates", map[string]any{"pem": oldPEM, "key": oldKey}, nil)
	if code != 201 {
		t.Fatal(code, cert)
	}
	certID := cert["id"].(string)
	serverID, agent := p.enroll("retry-server")
	p.newAgent(agent)
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "AnyTLS", "protocol": "anytls", "port": 50443,
		"tlsName": "example.com", "certificateId": certID, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	p.applyAll(agent)
	nodeID := node["id"].(string)
	var originalSecret string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, nodeID).Scan(&originalSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret='invalid' WHERE id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	newPEM, newKey := makeTestCertificate(t, false, nil, 60)
	code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"pem": newPEM, "key": newKey}, nil)
	if code != 503 || !strings.Contains(out["error"].(string), "无需重新选择文件") {
		t.Fatalf("failed queue did not explain file-free retry: %d %v", code, out)
	}
	if got := certificatePendingServers(t, p, certID); len(got) != 1 || got[0] != "retry-server" {
		t.Fatalf("failed queue lost pending status: %v", got)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret=$1 WHERE id=$2`, originalSecret, nodeID); err != nil {
		t.Fatal(err)
	}
	before, _ := p.store.Server(serverID)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"name": "retried"}, nil); code != 200 {
		t.Fatalf("metadata-only retry did not queue: %d %v", code, out)
	}
	after, _ := p.store.Server(serverID)
	if after.Revision != before.Revision+1 {
		t.Fatal("pending server was not requeued by metadata-only save")
	}
	code, job, _ := p.do("GET", "/agent/job", nil, agent)
	if code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("retry did not reach Agent: %d %v", code, job)
	}
	raw, err := json.Marshal(job["state"])
	if err != nil {
		t.Fatal(err)
	}
	var state shared.DesiredState
	if err := json.Unmarshal(raw, &state); err != nil || len(state.Nodes) != 1 || state.Nodes[0].CertificatePEM != newPEM || state.Nodes[0].CertificateKey != newKey {
		t.Fatalf("retry job has stale certificate: %v", err)
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"jobId": job["id"], "jobStatus": "success"}, agent); code != 200 {
		t.Fatalf("retry report: %d %v", code, out)
	}
	if got := certificatePendingServers(t, p, certID); len(got) != 0 {
		t.Fatalf("retry success did not clear pending status: %v", got)
	}
	before, _ = p.store.Server(serverID)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"name": "renamed again"}, nil); code != 200 {
		t.Fatalf("metadata-only save after apply: %d %v", code, out)
	}
	after, _ = p.store.Server(serverID)
	if after.Revision != before.Revision {
		t.Fatal("metadata-only save requeued an already applied certificate")
	}

	// A failed Agent apply remains retryable without sending PEM files again.
	newerPEM, newerKey := makeTestCertificate(t, false, nil, 90)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"pem": newerPEM, "key": newerKey}, nil); code != 200 {
		t.Fatalf("second renewal: %d %v", code, out)
	}
	p.applyNext(agent, "failed")
	failedNode, err := p.store.Node(nodeID)
	if err != nil || failedNode.Status != "error" {
		t.Fatalf("failed apply did not mark node error: %v %v", failedNode, err)
	}
	if got := certificatePendingServers(t, p, certID); len(got) != 1 {
		t.Fatalf("failed Agent apply missing from pending servers: %v", got)
	}
	before, _ = p.store.Server(serverID)
	if code, out, _ := p.do("PATCH", "/api/certificates/"+certID, map[string]any{"name": "retry failed job"}, nil); code != 200 {
		t.Fatalf("error-status retry without files: %d %v", code, out)
	}
	after, _ = p.store.Server(serverID)
	if after.Revision != before.Revision+1 {
		t.Fatal("failed node was not requeued by metadata-only save")
	}
	p.applyAll(agent)
	if got := certificatePendingServers(t, p, certID); len(got) != 0 {
		t.Fatalf("failed Agent apply retry did not clear status: %v", got)
	}
}

func TestCertificateReplacementNamesDisabledBlocker(t *testing.T) {
	p := newTestMui(t)
	oldPEM, oldKey := makeTestCertificate(t, false, nil, 30)
	code, cert, _ := p.do("POST", "/api/certificates", map[string]any{"pem": oldPEM, "key": oldKey}, nil)
	if code != 201 {
		t.Fatal(code, cert)
	}
	id := cert["id"].(string)
	serverID, _ := p.enroll("disabled-server")
	if code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": serverID, "name": "disabled TLS", "protocol": "anytls", "port": 50443,
		"tlsName": "example.com", "certificateId": id, "enabled": false,
	}, nil); code != 201 {
		t.Fatal(code, node)
	}
	otherPEM, otherKey := makeTestCertificate(t, false, nil, 60, "other.example.net")
	code, out, _ := p.do("PATCH", "/api/certificates/"+id, map[string]any{
		"pem": otherPEM, "key": otherKey, "domain": "other.example.net",
	}, nil)
	if code != 409 || !strings.Contains(out["error"].(string), "已停用节点") {
		t.Fatalf("disabled node blocker was not identified: %d %v", code, out)
	}
	stored, err := p.store.Certificate(id)
	if err != nil || stored.PEM != oldPEM {
		t.Fatalf("rejected certificate replaced the old one: %v", err)
	}
}

func TestCertificateMigrationPreservesKeysAndNodeReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mui.db")
	const secret = "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	// Recreate the certificate schema immediately before the global-pool
	// migration, with an existing bound certificate and node reference.
	if _, err := store.DB.Exec(`ALTER TABLE mui_certificates ADD COLUMN server_id TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DROP TABLE IF EXISTS mui_offline_exports`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DROP TABLE IF EXISTS mui_entry_connection_ips`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`ALTER TABLE mui_audit DROP COLUMN ip`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DELETE FROM mui_schema_migrations WHERE version>=14`); err != nil {
		t.Fatal(err)
	}
	key, err := store.Encrypt("original-private-key")
	if err != nil {
		t.Fatal(err)
	}
	oldData := Marshal(map[string]any{"id": "cert", "serverId": "old-server", "domain": "example.com", "pem": "original-certificate", "expiresAt": time.Now().Add(time.Hour)})
	if _, err := store.DB.Exec(`INSERT INTO mui_certificates(id,server_id,data,secret) VALUES($1,$2,$3,$4)`, "cert", "old-server", oldData, key); err != nil {
		t.Fatal(err)
	}
	if err := store.PutNode(shared.Node{ID: "node", ServerID: "old-server", CertificateID: "cert"}, "node-password"); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	store = reopened
	cert, err := store.Certificate("cert")
	if err != nil || cert.ID != "cert" || cert.PEM != "original-certificate" {
		t.Fatalf("certificate changed during migration: %v", err)
	}
	if clear, err := store.CertificateKey("cert"); err != nil || clear != "original-private-key" {
		t.Fatalf("private key changed during migration: %v", err)
	}
	node, err := store.Node("node")
	if err != nil || node.CertificateID != cert.ID {
		t.Fatalf("node reference changed during migration: %v", err)
	}
	data, _ := json.Marshal(cert)
	if strings.Contains(string(data), "serverId") {
		t.Fatal("migrated certificate still exposes server ownership")
	}
	if _, err := store.DB.Exec(`SELECT server_id FROM mui_certificates`); err == nil {
		t.Fatal("certificate server ownership column was not removed")
	}
	if err := store.PutCertificate(shared.Certificate{ID: "global", Domain: "example.net", Key: "new-key"}); err != nil {
		t.Fatalf("cannot save a certificate after migration: %v", err)
	}
}
