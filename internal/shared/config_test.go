package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestSingBoxConfigAllProtocolsAndStats(t *testing.T) {
	nodes := []ManagedNode{
		{Node: Node{ID: "a", Protocol: "ss", Port: 8388, Listen: "0.0.0.0", Method: "2022-blake3-aes-128-gcm", Enabled: true}, Password: "secret"},
		{Node: Node{ID: "b", Protocol: "snell", Port: 8389, Listen: "0.0.0.0", Obfs: "http", Enabled: true}, Password: "secret"},
		{Node: Node{ID: "c", Protocol: "anytls", Port: 8390, Listen: "0.0.0.0", TLSName: "example.com", Enabled: true}, Password: "secret"},
	}
	raw, err := SingBoxConfig(nodes, "/etc/mui-agent/certs")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds     []map[string]any `json:"inbounds"`
		Experimental map[string]any   `json:"experimental"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 3 {
		t.Fatalf("inbounds: %d", len(doc.Inbounds))
	}
	if doc.Inbounds[0]["type"] != "shadowsocks" || doc.Inbounds[1]["version"] != float64(5) || doc.Inbounds[2]["type"] != "anytls" {
		t.Fatalf("protocol config: %#v", doc.Inbounds)
	}
	api := doc.Experimental["v2ray_api"].(map[string]any)
	stats := api["stats"].(map[string]any)
	tags := stats["inbounds"].([]any)
	if len(tags) != 3 || tags[0] != "node-a" {
		t.Fatalf("stats tags: %#v", tags)
	}
}

func TestSingBoxConfigSubscriptionUsers(t *testing.T) {
	nodes := []ManagedNode{
		{Node: Node{ID: "ss", Name: "SS", Protocol: "ss", Port: 50001, Method: "2022-blake3-aes-128-gcm", Enabled: true}, Password: "server-key", Users: []NodeUser{{SubscriptionID: "a", Name: "mui-ss-a", Password: "user-key"}}},
		{Node: Node{ID: "snell", Name: "Snell", Protocol: "snell", Port: 50002, ShadowTLSHost: "example.com", Enabled: true}, Password: "psk", ShadowTLSPassword: "legacy-outer", Users: []NodeUser{{SubscriptionID: "b", Name: "mui-snell-b", Password: "userkey", ShadowTLSPassword: "user-outer"}}},
		{Node: Node{ID: "anytls", Name: "AnyTLS", Protocol: "anytls", Port: 50003, TLSName: "example.com", Enabled: true}, Password: "legacy", Users: []NodeUser{{SubscriptionID: "c", Name: "mui-anytls-c", Password: "user-password"}}},
	}
	raw, err := SingBoxConfig(nodes, "/tmp/certs")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds     []map[string]any `json:"inbounds"`
		Experimental map[string]any   `json:"experimental"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 4 {
		t.Fatalf("inbounds: %s", raw)
	}
	ssUsers := doc.Inbounds[0]["users"].([]any)
	if ssUsers[0].(map[string]any)["password"] != "user-key" {
		t.Fatalf("SS users: %s", raw)
	}
	outerUsers := doc.Inbounds[1]["users"].([]any)
	if outerUsers[1].(map[string]any)["name"] != "mui-snell-b" || outerUsers[1].(map[string]any)["password"] != "user-outer" {
		t.Fatalf("ShadowTLS users: %s", raw)
	}
	// Behind ShadowTLS, Snell is single-user: the outer password identifies the subscription.
	if _, multiUser := doc.Inbounds[2]["users"]; multiUser {
		t.Fatalf("Snell users: %s", raw)
	}
	anyUsers := doc.Inbounds[3]["users"].([]any)
	if anyUsers[1].(map[string]any)["password"] != "user-password" {
		t.Fatalf("AnyTLS users: %s", raw)
	}
	stats := doc.Experimental["v2ray_api"].(map[string]any)["stats"].(map[string]any)["users"].([]any)
	if len(stats) != 3 {
		t.Fatalf("stats user names: %s", raw)
	}
}

func TestNormalizeFirewallAccess(t *testing.T) {
	policy, sources, err := NormalizeFirewallAccess("restricted", "203.0.113.7, 203.0.113.7/32\n2001:db8::1; 198.51.100.99/24")
	if err != nil || policy != "restricted" || sources != "203.0.113.7/32,2001:db8::1/128,198.51.100.0/24" {
		t.Fatalf("normalized sources: %q %q %v", policy, sources, err)
	}
	if policy, sources, err = NormalizeFirewallAccess("", ""); err != nil || policy != "all" || sources != "" {
		t.Fatalf("legacy policy: %q %q %v", policy, sources, err)
	}
	for _, test := range []struct{ policy, sources string }{
		{"restricted", ""},
		{"restricted", "not-an-ip"},
		{"restricted", "fe80::1%eth0"},
		{"manual", "203.0.113.7"},
		{"invalid", ""},
	} {
		if _, _, err := NormalizeFirewallAccess(test.policy, test.sources); err == nil {
			t.Errorf("accepted invalid policy/sources: %q %q", test.policy, test.sources)
		}
	}
}

func TestSnellShadowTLSInboundAndStats(t *testing.T) {
	item := ManagedNode{Node: Node{ID: "snell1", Name: "Snell", Protocol: "snell", Port: 54321, Listen: "0.0.0.0", Obfs: "none", ShadowTLSHost: "www.example.com", Enabled: true}, Password: "snell-secret", ShadowTLSPassword: "outer-secret"}
	raw, err := SingBoxConfig([]ManagedNode{item}, "/etc/mui-agent/certs")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds     []map[string]any `json:"inbounds"`
		Experimental map[string]any   `json:"experimental"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 2 {
		t.Fatalf("expected outer and inner inbounds: %#v", doc.Inbounds)
	}
	outer, inner := doc.Inbounds[0], doc.Inbounds[1]
	if outer["type"] != "shadowtls" || outer["version"] != float64(3) || outer["listen_port"] != float64(54321) || outer["detour"] != "node-snell1" || outer["strict_mode"] != true {
		t.Fatalf("invalid outer inbound: %#v", outer)
	}
	users := outer["users"].([]any)
	if users[0].(map[string]any)["password"] != "outer-secret" || outer["handshake"].(map[string]any)["server"] != "www.example.com" {
		t.Fatalf("invalid ShadowTLS credentials or handshake: %#v", outer)
	}
	if inner["type"] != "snell" || inner["psk"] != "snell-secret" || inner["tag"] != "node-snell1" || inner["listen"] != "127.0.0.1" || inner["listen_port"] != float64(24321) {
		t.Fatalf("inner Snell must use a fixed loopback port: %#v", inner)
	}
	stats := doc.Experimental["v2ray_api"].(map[string]any)["stats"].(map[string]any)["inbounds"].([]any)
	if len(stats) != 1 || stats[0] != "node-snell1" {
		t.Fatalf("stats must use Snell tag: %#v", stats)
	}
	if got := doc.Experimental["clash_api"].(map[string]any)["external_controller"]; got != "127.0.0.1:10086" {
		t.Fatalf("connections API must listen on loopback: %v", got)
	}
	item.ShadowTLSPassword = ""
	if _, err := SingBoxConfig([]ManagedNode{item}, ""); err == nil {
		t.Fatal("missing ShadowTLS secret accepted")
	}
	item.Node.ShadowTLSHost = "bad_host"
	if err := ValidateNode(item.Node, nil, false); err == nil {
		t.Fatal("invalid ShadowTLS SNI accepted")
	}
}

func TestAnyTLSCertificateValidation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"*.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	expiry, _, err := ParseCertificate(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !CertificateCovers(certPEM, "node.example.com") || CertificateCovers(certPEM, "example.com") {
		t.Fatal("wildcard certificate coverage incorrect")
	}
	node := Node{Name: "AnyTLS", Protocol: "anytls", Port: 8443, Listen: "0.0.0.0", TLSName: "node.example.com"}
	cert := &Certificate{Domain: "another.example.com", PEM: certPEM, ExpiresAt: expiry}
	if err := ValidateNode(node, cert, false); err != nil {
		t.Fatal(err)
	}
	node.TLSName = "example.com"
	cert.Domain = node.TLSName
	if err := ValidateNode(node, cert, false); err == nil {
		t.Fatal("certificate label must not override actual wildcard coverage")
	}
}

func TestSnellFixedInnerPortAndConflicts(t *testing.T) {
	n := Node{ID: "snell", ServerID: "host", Name: "Snell", Protocol: "snell", Port: 54321, SnellPort: 23456, ShadowTLSHost: "example.com", Enabled: true}
	if err := ValidateNode(n, nil, false); err != nil {
		t.Fatal(err)
	}
	raw, err := SingBoxConfig([]ManagedNode{{Node: n, Password: "snell-secret", ShadowTLSPassword: "outer-secret"}}, "/tmp/certs")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if inner := config.Inbounds[1]; inner["listen"] != "127.0.0.1" || inner["listen_port"] != float64(23456) {
		t.Fatalf("wrong inner listener: %s", raw)
	}
	for _, port := range []int{-1, 65536, n.Port, StatsAPIPort, ConnectionsAPIPort} {
		invalid := n
		invalid.SnellPort = port
		if ValidateNode(invalid, nil, false) == nil {
			t.Errorf("accepted inner port %d", port)
		}
	}
	other := Node{ID: "ss", ServerID: n.ServerID, Protocol: "ss", Port: n.SnellPort, Listen: "0.0.0.0"}
	if !PortConflict(n, other) || !PortConflict(other, n) {
		t.Fatal("inner/external collision not detected")
	}
	other.Listen = "192.0.2.1"
	if PortConflict(n, other) {
		t.Fatal("nonoverlapping listen addresses conflict")
	}
	other = n
	other.ID = "second"
	other.Port++
	if !PortConflict(n, other) {
		t.Fatal("two Snell inner listeners accepted on same port")
	}
}
