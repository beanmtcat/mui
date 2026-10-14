package server

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPanelServesAgentInstallerAndArtifacts(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("MUI_AGENT_BIN_DIR", binDir)
	p := newTestMui(t)
	archDir := filepath.Join(binDir, "amd64")
	if err := os.Mkdir(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"mui-agent": "agent-binary", "sing-box": "core-binary", "SHA256SUMS": "test-checksums",
	} {
		if err := os.WriteFile(filepath.Join(archDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for path, want := range map[string]string{
		"/download/install.sh":       "sha256sum --check",
		"/download/amd64/mui-agent":  "agent-binary",
		"/download/amd64/sing-box":   "core-binary",
		"/download/amd64/SHA256SUMS": "test-checksums",
	} {
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
	}
	for _, path := range []string{"/download/arm64/mui-agent", "/download/amd64/secret", "/download/other/mui-agent"} {
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 {
			t.Fatalf("unexpected artifact access %s: %d", path, rec.Code)
		}
	}
	if err := os.Mkdir(filepath.Join(binDir, "arm64"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(archDir, "mui-agent"), filepath.Join(binDir, "arm64", "mui-agent")); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, httptest.NewRequest("GET", "/download/arm64/mui-agent", nil))
	if rec.Code != 404 {
		t.Fatalf("symlinked artifact was served: %d", rec.Code)
	}
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "test", "country": "SG", "ipv4": "203.0.113.10"}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	command := out["installCommand"].(string)
	if !strings.Contains(command, "https://mui.example.test/download/install.sh") || !strings.Contains(command, " | sudo sh -s -- ") || !strings.HasPrefix(command, "bash -o pipefail -c ") || strings.Contains(command, "MUI_ENROLL_TOKEN=") || strings.Contains(command, "./mui-agent install") {
		t.Fatalf("invalid install command: %q", command)
	}
	fakeTools := t.TempDir()
	for name, content := range map[string]string{
		"curl": "#!/bin/sh\nprintf '%s\\n' 'test \"$#\" -eq 4 && test \"$1\" = \"https://mui.example.test\" && test -n \"$2\" && test -n \"$3\" && test \"$4\" = node'\n",
		"sudo": "#!/bin/sh\nexec \"$@\"\n",
	} {
		if err := os.WriteFile(filepath.Join(fakeTools, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+fakeTools+":"+os.Getenv("PATH"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install command failed with stub downloader: %v %s", err, output)
	}
	code, renewed, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 || !strings.Contains(renewed["installCommand"].(string), "/download/install.sh") {
		t.Fatalf("renewed install command: %d %v", code, renewed)
	}
}

func TestInstallerChecksDownloadsBeforeExecutingAgent(t *testing.T) {
	toolsDir := t.TempDir()
	artifacts := t.TempDir()
	marker := filepath.Join(t.TempDir(), "installed")
	for name, content := range map[string]string{
		"uname":     "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\n",
		"curl":      "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in --output) output=$2; shift 2;; *) url=$1; shift;; esac\ndone\ncp \"$FIXTURE_DIR/${url##*/}\" \"$output\"\n",
		"sha256sum": "#!/bin/sh\nexit \"${CHECKSUM_EXIT:-0}\"\n",
	} {
		if err := os.WriteFile(filepath.Join(toolsDir, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"mui-agent":      "#!/bin/sh\ntest \"$1\" = install && test \"$2\" = \"https://mui.example.test\" && test \"$3\" = test-server && test \"$4\" = test-token && test \"$#\" -eq 6 && { test \"$5\" = - || test -f \"$5\"; } && test \"$6\" = \"${EXPECTED_RELEASE_KEY:-}\" && touch \"$INSTALL_MARKER\"\n",
		"sing-box":       "core-binary",
		"SHA256SUMS":     "aaaa  mui-agent\nbbbb  sing-box\n",
		"SHA256SUMS.sig": "test-signature",
	} {
		if err := os.WriteFile(filepath.Join(artifacts, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, run := range []struct {
		checksumExit string
		args         []string
		releaseKey   string
	}{
		{"1", []string{"https://mui.example.test", "test-server", "test-token", "node"}, ""},
		{"0", []string{"https://mui.example.test", "test-server", "test-token", "node"}, ""},
		{"0", []string{"https://mui.example.test", "test-server", "test-token", "node", "test-release-key"}, "test-release-key"},
	} {
		checksumExit := run.checksumExit
		_ = os.Remove(marker)
		cmd := exec.Command("sh", append([]string{"-s", "--"}, run.args...)...)
		cmd.Stdin = bytes.NewReader(installAgentScript)
		cmd.Env = append(os.Environ(),
			"PATH="+toolsDir+":"+os.Getenv("PATH"),
			"FIXTURE_DIR="+artifacts, "INSTALL_MARKER="+marker, "CHECKSUM_EXIT="+checksumExit, "EXPECTED_RELEASE_KEY="+run.releaseKey,
		)
		_, err := cmd.CombinedOutput()
		_, markerErr := os.Stat(marker)
		if checksumExit == "1" && (err == nil || !os.IsNotExist(markerErr)) {
			t.Fatal("installer ran the agent after a failed checksum")
		}
		if checksumExit == "0" && (err != nil || markerErr != nil) {
			t.Fatalf("installer did not run after successful checksum: %v %v", err, markerErr)
		}
	}
	if err := os.Remove(filepath.Join(artifacts, "sing-box")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(marker)
	cmd := exec.Command("sh", "-s", "--", "https://mui.example.test", "test-server", "test-token", "relay")
	cmd.Stdin = bytes.NewReader(installAgentScript)
	cmd.Env = append(os.Environ(), "PATH="+toolsDir+":"+os.Getenv("PATH"), "FIXTURE_DIR="+artifacts, "INSTALL_MARKER="+marker, "CHECKSUM_EXIT=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("relay installer required sing-box: %v %s", err, output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("relay installer did not run Agent: %v", err)
	}
}
