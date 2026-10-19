package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestOfflineInstallFilesAndAPI(t *testing.T) {
	for _, exit := range []bool{false, true} {
		for _, signed := range []bool{false, true} {
			app := &App{PublicURL: "https://mui.example.test"}
			if signed {
				app.releaseKeyB64 = "public-key"
			}
			s := shared.Server{Roles: []string{shared.RoleTransit}}
			if exit {
				s.Roles = append(s.Roles, shared.RoleExit)
			}
			guide := app.offlineInstall("server-id", "token", s)
			for _, download := range guide.Downloads {
				names := []string{}
				for _, file := range download.Files {
					names = append(names, file.Name)
					if file.URL != app.PublicURL+"/download/"+download.Arch+"/"+file.Name || !strings.Contains(download.Command, file.URL) {
						t.Fatalf("invalid download: %+v", download)
					}
				}
				all := strings.Join(names, ",")
				if strings.Contains(all, "sing-box") != exit || strings.Contains(all, "SHA256SUMS.sig") != signed || guide.Signed != signed {
					t.Fatalf("wrong role or signature files: %+v", guide)
				}
				if strings.Contains(download.Command, "token") {
					t.Fatal("public download command contains enrollment token")
				}
			}
			if len(guide.Downloads) != 2 || strings.Contains(guide.Command, "curl ") || strings.Contains(guide.Command, "--ignore-missing") || !strings.Contains(guide.Command, "--token-stdin") {
				t.Fatalf("invalid manual guide: %+v", guide)
			}
		}
	}
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "manual install", "roles": []string{"transit"}, "country": "SG", "ipv4": "192.0.2.10"}, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	for _, response := range []map[string]any{out, func() map[string]any {
		code, renewed, _ := p.do("POST", "/api/servers/"+id+"/enrollment", nil, nil)
		if code != 200 {
			t.Fatalf("renew: %d %v", code, renewed)
		}
		return renewed
	}()} {
		raw, _ := json.Marshal(response["offlineInstall"])
		var guide offlineInstallGuide
		if err := json.Unmarshal(raw, &guide); err != nil || len(guide.Downloads) != 2 || !strings.Contains(guide.Command, response["enrollToken"].(string)) || !strings.Contains(guide.Command, id) {
			t.Fatalf("API did not return a matching manual guide: %s %v", raw, err)
		}
	}
}

// Execute the exact generated shell command against local fixture files. A
// stub agent checks its arguments/stdin; real sha256sum gates its execution.
func TestOfflineInstallCommand(t *testing.T) {
	for _, tc := range []struct {
		name       string
		exit, sudo bool
		standalone bool
		proxy      bool
		online     bool
		textSuffix bool
		breakFile  string
	}{
		{name: "relay root without sudo"},
		{name: "proxy manual root", proxy: true},
		{name: "proxy manual sudo", proxy: true, sudo: true},
		{name: "proxy online root", proxy: true, online: true},
		{name: "proxy online sudo", proxy: true, online: true, sudo: true},
		{name: "exit with sudo", exit: true, sudo: true},
		{name: "standalone root", standalone: true},
		{name: "standalone sudo", standalone: true, sudo: true},
		{name: "browser txt suffix root", standalone: true, textSuffix: true},
		{name: "browser txt suffix sudo", sudo: true, textSuffix: true},
		{name: "browser txt suffix corrupt agent", textSuffix: true, breakFile: "corrupt-agent"},
		{name: "corrupt agent", breakFile: "corrupt-agent"},
		{name: "corrupt core", exit: true, breakFile: "corrupt-core"},
		{name: "missing agent", breakFile: "missing-agent"},
		{name: "missing manifest entry", breakFile: "missing-entry"},
		{name: "duplicate manifest entry", breakFile: "duplicate-entry"},
		{name: "missing signature", breakFile: "missing-signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, tools := t.TempDir(), t.TempDir()
			dir := filepath.Join(home, "mui-install")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"grep", "chmod", "mv", "mktemp", "rm", "sh", "wc", "cp"} {
				path, err := exec.LookPath(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(tools, name)); err != nil {
					t.Fatal(err)
				}
			}
			if runtime.GOOS == "darwin" {
				// macOS's sha256sum lacks GNU's long flags; shasum implements
				// the same manifest checks used by GNU sha256sum on Linux.
				path, err := exec.LookPath("shasum")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(tools, "sha256sum"), []byte("#!/bin/sh\nexec "+shellQuote(path)+" -a 256 \"$@\"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				path, err := exec.LookPath("sha256sum")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path, filepath.Join(tools, "sha256sum")); err != nil {
					t.Fatal(err)
				}
			}
			uid, core := "0", "-"
			roles := []string{shared.RoleTransit}
			if tc.exit {
				core, roles = "./sing-box", []string{shared.RoleExit}
			}
			if tc.sudo {
				uid = "1000"
				if err := os.WriteFile(filepath.Join(tools, "sudo"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(tools, "id"), []byte("#!/bin/sh\nprintf '%s\\n' "+uid+"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			app := &App{PublicURL: "https://mui.example.test", releaseKeyB64: "release-key"}
			srv := shared.Server{Roles: roles}
			if tc.proxy {
				fixture := newTestMui(t)
				hostID, _ := fixture.enroll("proxy-host")
				host, _ := fixture.store.Server(hostID)
				host.UFWStatus = "active"
				fixture.store.PutServer(host)
				n := shared.Node{ID: ID(), ServerID: hostID, Name: "proxy", Protocol: "socks5", Username: "entry", Port: 1080, Direct: true, Enabled: true, Status: "active"}
				if err := fixture.store.PutNode(n, "proxy-password"); err != nil {
					t.Fatal(err)
				}
				app.Store = fixture.store
				srv.AgentProxyNodeID = n.ID
			}
			guide := app.offlineInstall("server-id", "test-enroll-token", srv)
			if tc.online {
				guide.Command = app.installCommand("server-id", "test-enroll-token", srv)
			}
			stub := "#!/bin/sh\nset -eu\ntest \"$#\" -eq 7\ntest \"$1\" = install\ntest \"$2\" = https://mui.example.test\ntest \"$3\" = server-id\ntest \"$4\" = -\ntest \"$5\" = " + shellQuote(core) + "\ntest \"$6\" = release-key\ntest \"$7\" = --token-stdin\nIFS= read -r token\ntest \"$token\" = test-enroll-token\nprintf ran > \"$INSTALL_LOG\"\n"
			if tc.proxy {
				stub = strings.Replace(stub, `test "$#" -eq 7`, `test "$#" -eq 9`, 1)
				stub = strings.Replace(stub, "test \"$7\" = --token-stdin\n", `shift 6
proxy_file=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --token-stdin) ;;
  --proxy-file) shift; proxy_file=$1 ;;
  *) exit 1 ;;
 esac
 shift
done
test -f "$proxy_file"
grep -q '"password":"proxy-password"' "$proxy_file"
`, 1)
			}
			if tc.standalone {
				guide = app.standaloneInstallAt(app.PublicURL)
				if strings.Contains(guide.Command, "test-enroll-token") || strings.Contains(guide.Command, "--token") || strings.Contains(guide.Command, "curl ") {
					t.Fatal("standalone install requires network or enrollment")
				}
				stub = "#!/bin/sh\nset -eu\ntest \"$#\" -eq 6\ntest \"$1\" = offline\ntest \"$2\" = install\ntest \"$3\" = --config\ntest \"$4\" = ./forwards.json\ntest \"$5\" = --release-key\ntest \"$6\" = release-key\nprintf ran > \"$INSTALL_LOG\"\n"
			}
			manifest := ""
			for name, data := range map[string]string{"mui-agent": stub, "sing-box": "core-binary"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				entry := fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(data)), name)
				if name == "mui-agent" && tc.breakFile == "missing-entry" {
					continue
				}
				manifest += entry
				if name == "mui-agent" && tc.breakFile == "duplicate-entry" {
					manifest += entry
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte("signature"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.textSuffix {
				for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
					if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, name+".txt")); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch tc.breakFile {
			case "corrupt-agent":
				_ = os.WriteFile(filepath.Join(dir, "mui-agent"), []byte(stub+"# corrupt\n"), 0600)
			case "corrupt-core":
				_ = os.WriteFile(filepath.Join(dir, "sing-box"), []byte("corrupt"), 0600)
			case "missing-agent":
				_ = os.Remove(filepath.Join(dir, "mui-agent"))
			case "missing-signature":
				_ = os.Remove(filepath.Join(dir, "SHA256SUMS.sig"))
			}
			if tc.online {
				os.WriteFile(filepath.Join(dir, "install.sh"), installAgentScript, 0600)
				os.WriteFile(filepath.Join(tools, "uname"), []byte("#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\n"), 0755)
				curl := `#!/bin/sh
set -eu
config=
output=
url=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --config) shift; config=$1 ;;
  --output|-o) shift; output=$1 ;;
  https://*) url=$1 ;;
 esac
 shift
done
test -f "$config"
grep -q 'proxy-user = "entry:proxy-password"' "$config"
name=${url##*/}
cp "$INSTALL_FILES/$name" "$output"
`
				os.WriteFile(filepath.Join(tools, "curl"), []byte(curl), 0755)
			}
			log := filepath.Join(home, "installed")
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = strings.NewReader(guide.Command)
			cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+tools, "INSTALL_LOG="+log, "INSTALL_FILES="+dir)
			output, err := cmd.CombinedOutput()
			_, logErr := os.Stat(log)
			if tc.breakFile != "" {
				if err == nil || !os.IsNotExist(logErr) {
					t.Fatalf("bad files executed the agent: %v %s", err, output)
				}
			} else if err != nil || logErr != nil {
				t.Fatalf("valid offline install failed: %v %s; agent: %v", err, output, logErr)
			}
		})
	}
}
