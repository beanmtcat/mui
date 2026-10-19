//go:build linux

package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"mui/internal/shared"
)

func TestAgentProxySwitch(t *testing.T) {
	if os.Getenv("MUI_TEST_PROXY_SWITCH") != "1" {
		t.Skip("requires a disposable container")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("test requires a disposable root Docker container")
	}
	if _, err := os.Stat(ConfigDir + "/config.json"); !os.IsNotExist(err) {
		t.Fatal("refusing to replace an existing Agent config")
	}
	os.MkdirAll(ConfigDir, 0750)
	exec.Command("addgroup", "-S", agentUser).Run()
	exec.Command("adduser", "-S", "-D", "-H", "-G", agentUser, agentUser).Run()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/report" || r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("X-Agent-Signature") == "" {
			http.Error(w, "bad authentication", 401)
			return
		}
		w.WriteHeader(200)
	}))
	defer panel.Close()
	old := Config{URL: panel.URL, ServerID: "fixture", Token: "fixture-token", AgentProxy: &shared.SOCKS5Proxy{Host: "127.0.0.1", Port: 1, Username: "entry", Password: "old-password"}}
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(ConfigDir+"/config.json", raw, 0640); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(PanelPublicKeyPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0644)
	state := shared.DesiredState{Revision: 1, ProtocolVersion: 1, AgentProxy: &shared.SOCKS5Proxy{}}
	if err := prepareAgentProxy(state, nil); err == nil {
		t.Fatal("unsigned proxy change accepted")
	}
	state.AgentProxy = &shared.SOCKS5Proxy{Host: "127.0.0.1", Port: 2, Username: "entry", Password: "unreachable-password"}
	state.Signature = shared.SignDesiredState(priv, state)
	if err := prepareAgentProxy(state, nil); err == nil {
		t.Fatal("unreachable proxy accepted")
	}
	unchanged, _ := os.ReadFile(ConfigDir + "/config.json")
	if !bytes.Equal(raw, unchanged) {
		t.Fatal("failed test changed installed settings")
	}
	state.AgentProxy = &shared.SOCKS5Proxy{}
	state.Signature = ""
	state.Signature = shared.SignDesiredState(priv, state)
	if err := prepareAgentProxy(state, nil); err != nil {
		t.Fatal(err)
	}
	if err := saveAgentProxy(state.AgentProxy); err != nil {
		t.Fatal(err)
	}
	c, err := ReadConfig()
	if err != nil || c.AgentProxy != nil {
		t.Fatal("did not persist direct connection", err)
	}
	info, _ := os.Stat(ConfigDir + "/config.json")
	if info.Mode().Perm() != 0640 {
		t.Fatal("unsafe proxy config permissions")
	}
	clean := sanitizeStateForStorage(state)
	if clean.AgentProxy != nil {
		t.Fatal("proxy secret retained in current state")
	}
	os.Remove(ConfigDir + "/config.json")
	os.Remove(PanelPublicKeyPath)
}
