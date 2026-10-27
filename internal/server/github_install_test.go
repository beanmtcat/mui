package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestGitHubInstallScriptDownloadsArchiveDirectly(t *testing.T) {
	agent := []byte("#!/bin/sh\ntest \"$1\" = install || exit 3\nIFS= read -r token\ntest \"$token\" = expected-token || exit 4\nprintf '%s' installed > \"$MUI_TEST_INSTALL_LOG\"\n")
	core := []byte("#!/bin/sh\nexit 0\n")
	manifest := []byte(fmt.Sprintf("%x  mui-agent\n%x  sing-box\n", sha256.Sum256(agent), sha256.Sum256(core)))
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"amd64/mui-agent", agent}, {"amd64/sing-box", core}, {"amd64/SHA256SUMS", manifest}, {"amd64/SHA256SUMS.sig", []byte("signature")},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0755, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "release.tar.gz")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"uname": "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\n",
		"curl":  "#!/bin/sh\nset -eu\nout=\nurl=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in --output) out=$2; shift 2;; https://*) url=$1; shift;; *) shift;; esac\ndone\ntest \"$url\" = https://github.com/beanmtcat/mui/releases/download/v0.6.21/mui-agent-0.6.21-linux-amd64.tar.gz\ncp \"$MUI_TEST_ARCHIVE\" \"$out\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		shasum, err := exec.LookPath("shasum")
		if err != nil {
			t.Fatal(err)
		}
		wrapper := "#!/bin/sh\nexec " + shellQuote(shasum) + " -a 256 \"$@\"\n"
		if err := os.WriteFile(filepath.Join(dir, "sha256sum"), []byte(wrapper), 0755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "installed")
	cmd := exec.Command("sh", "install-agent.sh", "https://panel.example", "server-id", "-", "node", "public-key", "", "0.6.21")
	cmd.Stdin = strings.NewReader("expected-token\n")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "MUI_TEST_ARCHIVE="+archivePath, "MUI_TEST_INSTALL_LOG="+logPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install: %v %s", err, output)
	}
	if data, err := os.ReadFile(logPath); err != nil || string(data) != "installed" {
		t.Fatalf("Agent did not run: %q %v", data, err)
	}
}

func TestGitHubInstallGuidesUsePanelScriptAndGitHubArchive(t *testing.T) {
	app := &App{PublicURL: "https://panel.example", releaseVersion: "0.6.21", releaseKeyB64: "public-key"}
	server := shared.Server{Roles: []string{shared.RoleExit}}
	command := app.installCommand("server-id", "enroll-token", server)
	if !strings.Contains(command, "https://panel.example/download/install.sh") || strings.Contains(command, "raw.githubusercontent.com") || !strings.Contains(command, "0.6.21") {
		t.Fatalf("online command did not use the panel script: %s", command)
	}
	guide := app.offlineInstall("server-id", "enroll-token", server)
	if len(guide.Downloads) != 2 || len(guide.Downloads[0].Files) != 1 || !strings.Contains(guide.Downloads[0].Files[0].URL, "/releases/download/v0.6.21/") || !strings.Contains(guide.Command, "tar -xzf") {
		t.Fatalf("manual guide did not use GitHub archive: %+v", guide)
	}
}

func TestGitHubModeServesPanelScriptsButNotBinaries(t *testing.T) {
	p := newTestMui(t)
	p.app.releaseVersion = "0.6.21"
	for _, path := range []string{"/download/install.sh", "/download/uninstall.sh"} {
		if code, body := p.fetch(path); code != 200 || len(body) == 0 {
			t.Fatalf("GitHub mode script %s: %d", path, code)
		}
	}
	if code, _ := p.fetch("/download/amd64/mui-agent"); code != 404 {
		t.Fatalf("GitHub mode still serves binaries: %d", code)
	}
}
