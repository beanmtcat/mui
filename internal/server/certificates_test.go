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
