package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"mui/internal/shared"
)

// Optional integration checks against the exact core shipped to operators.
func TestOutboundConfigsMatchCore(t *testing.T) {
	core := os.Getenv("MUI_TEST_SNELL_CORE")
	if core == "" {
		t.Skip("requires release sing-box")
	}
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(filepath.Join(dir, "anytls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anytls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, defaultIF := range []string{"", "lo"} {
		t.Run("default-"+defaultIF, func(t *testing.T) {
			nodes := []shared.ManagedNode{}
			for i, protocol := range []string{"ss", "anytls", "socks5", "snell", "snell"} {
				id := protocol
				if i == 4 {
					id = "shadow"
				}
				n := shared.Node{ID: id, Name: id, Protocol: protocol, SnellVersion: 6, SnellPort: 23456, Port: 53000 + i, Listen: "0.0.0.0", Enabled: true, Method: "aes-256-gcm", TLSName: "example.com", Username: "test-user"}
				switch i {
				case 1:
					n.OutboundMode = "system"
				case 2, 3, 4:
					n.OutboundMode = "interface"
					n.OutboundInterface = "lo"
				}
				if i == 4 {
					n.ShadowTLSHost = "example.com"
				}
				nodes = append(nodes, shared.ManagedNode{Node: n, Password: "valid-test-password", ShadowTLSPassword: "outer-test-password"})
			}
			raw, err := shared.SingBoxConfig(nodes, dir, defaultIF)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(core, "check", "-c", path).CombinedOutput(); err != nil {
				t.Fatalf("core config rejected: %v %s", err, out)
			}
		})
	}
}

func TestOutboundRuntimeBinding(t *testing.T) {
	core := os.Getenv("MUI_TEST_SNELL_CORE")
	if core == "" || runtime.GOOS != "linux" {
		t.Skip("requires Linux release core")
	}
	if _, err := net.InterfaceByName("eth0"); err != nil {
		t.Skip("requires isolated Linux container with eth0")
	}
	destinationURL := os.Getenv("MUI_TEST_BIND_TARGET")
	if destinationURL == "" {
		t.Skip("requires separate isolated target container")
	}
	ports := []int{}
	nodes := []shared.ManagedNode{}
	for i, mode := range []string{"inherit", "system", "interface"} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		ports = append(ports, port)
		n := shared.Node{ID: mode, Name: mode, Protocol: "socks5", Username: "user", Listen: "127.0.0.1", Port: port, Enabled: true, OutboundMode: mode}
		if i == 2 {
			n.OutboundInterface = "eth0"
		}
		nodes = append(nodes, shared.ManagedNode{Node: n, Password: "test-password"})
	}
	raw, err := shared.SingBoxConfig(nodes, t.TempDir(), "lo")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for _, port := range ports {
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				log, _ := os.ReadFile(logFile.Name())
				t.Fatalf("core did not listen: %s", log)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Binding lo must not fall back to eth0 to reach a separate container;
	// system routing and an explicit eth0 override must reach that target.
	// Loopback destinations themselves are exempt from binding in sing-box.
	for i, port := range ports {
		d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &proxy.Auth{User: "user", Password: "test-password"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
		client := &http.Client{Transport: tr, Timeout: 700 * time.Millisecond}
		resp, err := client.Get(destinationURL)
		if i == 0 {
			if err == nil {
				resp.Body.Close()
				t.Fatal("device binding silently used eth0")
			}
			tr.CloseIdleConnections()
			continue
		}
		if err != nil {
			t.Fatalf("node override %s: %v", nodes[i].Node.OutboundMode, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tr.CloseIdleConnections()
		if string(body) != "egress-ok" {
			t.Fatal(string(body))
		}
	}
}
