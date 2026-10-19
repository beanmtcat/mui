package server

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mui/internal/shared"
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
		"mui-agent": "agent-binary", "sing-box": "core-binary", "SHA256SUMS": "test-checksums", "SHA256SUMS.sig": "test-signature",
	} {
		if err := os.WriteFile(filepath.Join(archDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for path, want := range map[string]string{
		"/download/install.sh":           "sha256sum --check",
		"/download/amd64/mui-agent":      "agent-binary",
		"/download/amd64/sing-box":       "core-binary",
		"/download/amd64/SHA256SUMS":     "test-checksums",
		"/download/amd64/SHA256SUMS.sig": "test-signature",
	} {
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Fatalf("%s: %d %q", path, rec.Code, rec.Body.String())
		}
		if path != "/download/install.sh" {
			filename := filepath.Base(path)
			if rec.Header().Get("Content-Disposition") != "attachment; filename=\""+filename+"\"" || rec.Header().Get("Content-Type") != "application/octet-stream" {
				t.Fatalf("release filename is not preserved: %s %v", path, rec.Header())
			}
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
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "test", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.10"}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	command := out["installCommand"].(string)
	if !strings.Contains(command, "https://mui.example.test/download/install.sh") || !strings.Contains(command, "\"$@\" \"$mui_installer\"") || !strings.HasPrefix(command, "(\n") || strings.Contains(command, "bash -o pipefail -c") || strings.Contains(command, "MUI_ENROLL_TOKEN=") || strings.Contains(command, "./mui-agent install") {
		t.Fatalf("invalid install command: %q", command)
	}
	fakeTools := t.TempDir()
	for name, content := range map[string]string{
		"id": "#!/bin/sh\nprintf '1000\\n'\n",
		"curl": `#!/bin/sh
set -eu
test "$1" = -fsSL
test "$2" = https://mui.example.test/download/install.sh
test "$3" = -o
printf '%s\n' "$4" > "$INSTALLER_PATH_LOG"
cat > "$4" <<'SCRIPT'
set -eu
test "$#" -eq 4
test "$1" = https://mui.example.test
test -n "$2"
test "$3" = -
test "$4" = node
IFS= read -r token
test "$token" = "$EXPECTED_ENROLL_TOKEN"
SCRIPT
`,
		"sudo": `#!/bin/sh
set -eu
for arg do
  case "$arg" in *"$EXPECTED_ENROLL_TOKEN"*) exit 77;; esac
done
exec "$@"
`,
	} {
		if err := os.WriteFile(filepath.Join(fakeTools, name), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	installerPathLog := filepath.Join(t.TempDir(), "installer-path")
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader(command)
	cmd.Env = append(os.Environ(), "PATH="+fakeTools+":"+os.Getenv("PATH"), "EXPECTED_ENROLL_TOKEN="+out["enrollToken"].(string), "INSTALLER_PATH_LOG="+installerPathLog)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install command failed with stub downloader: %v %s", err, output)
	}
	installerPath, err := os.ReadFile(installerPathLog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(strings.TrimSpace(string(installerPath))); !os.IsNotExist(err) {
		t.Fatalf("temporary installer was not removed: %v", err)
	}
	code, renewed, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
	if code != 200 || !strings.Contains(renewed["installCommand"].(string), "/download/install.sh") {
		t.Fatalf("renewed install command: %d %v", code, renewed)
	}
}

func TestInstallCommandRootAndSudoSelection(t *testing.T) {
	app := &App{PublicURL: "https://mui.example.test"}
	command := app.installCommand("test-server", "test-token", shared.Server{})
	for _, tc := range []struct {
		name     string
		uid      string
		sudo     bool
		wantOK   bool
		wantSudo bool
	}{
		{"root without sudo", "0", false, true, false},
		{"root skips sudo", "0", true, true, false},
		{"user with sudo", "1000", true, true, true},
		{"user without sudo", "1000", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools := t.TempDir()
			// An isolated PATH ensures a host-installed sudo cannot hide a bug.
			for _, name := range []string{"sh", "mktemp", "rm", "cat"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(tools, name)); err != nil {
					t.Fatal(err)
				}
			}
			scripts := map[string]string{
				"id": "#!/bin/sh\nprintf '%s\\n' \"$TEST_UID\"\n",
				"curl": `#!/bin/sh
set -eu
cat > "$4" <<'SCRIPT'
set -eu
test "$#" -eq 4
test "$1" = https://mui.example.test
test "$2" = test-server
test "$3" = -
test "$4" = relay
IFS= read -r token
test "$token" = test-token
printf done > "$INSTALL_MARKER"
SCRIPT
`,
			}
			if tc.sudo {
				scripts["sudo"] = "#!/bin/sh\nprintf used > \"$SUDO_MARKER\"\nexec \"$@\"\n"
			}
			for name, script := range scripts {
				if err := os.WriteFile(filepath.Join(tools, name), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
			}
			marker, sudoMarker := filepath.Join(t.TempDir(), "installed"), filepath.Join(t.TempDir(), "sudo")
			cmd := exec.Command("sh")
			cmd.Stdin = strings.NewReader(command)
			cmd.Env = append(os.Environ(), "PATH="+tools, "TEST_UID="+tc.uid, "INSTALL_MARKER="+marker, "SUDO_MARKER="+sudoMarker)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("unexpected command result: %v %s", err, output)
			}
			if !tc.wantOK && !strings.Contains(string(output), "请切换到 root") {
				t.Fatalf("missing actionable error: %s", output)
			}
			_, installErr := os.Stat(marker)
			_, sudoErr := os.Stat(sudoMarker)
			if (installErr == nil) != tc.wantOK || (sudoErr == nil) != tc.wantSudo {
				t.Fatalf("wrong installation or elevation path: installed=%v sudo=%v", installErr, sudoErr)
			}
		})
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
		"mui-agent":      "#!/bin/sh\ntest \"$1\" = install && test \"$2\" = \"https://mui.example.test\" && test \"$3\" = test-server && test \"$4\" = - && test \"$#\" -eq 7 && { test \"$5\" = - || test -f \"$5\"; } && test \"$6\" = \"${EXPECTED_RELEASE_KEY:-}\" && test \"$7\" = --token-stdin && IFS= read -r token && test \"$token\" = test-token && touch \"$INSTALL_MARKER\"\n",
		"sing-box":       "core-binary",
		"SHA256SUMS":     "aaaa  mui-agent\nbbbb  sing-box\n",
		"SHA256SUMS.sig": "test-signature",
	} {
		if err := os.WriteFile(filepath.Join(artifacts, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	installer := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(installer, installAgentScript, 0644); err != nil {
		t.Fatal(err)
	}
	for _, run := range []struct {
		checksumExit string
		args         []string
		releaseKey   string
	}{
		{"1", []string{"https://mui.example.test", "test-server", "test-token", "node"}, ""},
		{"0", []string{"https://mui.example.test", "test-server", "test-token", "node"}, ""},
		{"0", []string{"https://mui.example.test", "test-server", "test-token", "node", "test-release-key"}, "test-release-key"},
		{"0", []string{"https://mui.example.test", "test-server", "-", "node"}, ""},
		{"0", []string{"https://mui.example.test", "test-server", "-", "node", "test-release-key"}, "test-release-key"},
	} {
		checksumExit := run.checksumExit
		_ = os.Remove(marker)
		cmd := exec.Command("sh", append([]string{installer}, run.args...)...)
		if run.args[2] == "-" {
			cmd.Stdin = strings.NewReader("test-token\n")
		}
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
	cmd := exec.Command("sh", installer, "https://mui.example.test", "test-server", "-", "relay")
	cmd.Stdin = strings.NewReader("test-token\n")
	cmd.Env = append(os.Environ(), "PATH="+toolsDir+":"+os.Getenv("PATH"), "FIXTURE_DIR="+artifacts, "INSTALL_MARKER="+marker, "CHECKSUM_EXIT=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("relay installer required sing-box: %v %s", err, output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("relay installer did not run Agent: %v", err)
	}
}
