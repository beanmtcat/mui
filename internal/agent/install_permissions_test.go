//go:build linux

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Install is invoked by an enrollment shell using umask 077. Check actual
// service-account readability, as root readability alone hid the regression.
func TestInstallPermissionsWithRestrictiveUmask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in an isolated Linux test container")
	}
	if os.Getenv("MUI_TEST_RESTRICTIVE_UMASK") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestInstallPermissionsWithRestrictiveUmask$", "-test.v")
		cmd.Env = append(os.Environ(), "MUI_TEST_RESTRICTIVE_UMASK=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	syscall.Umask(0077)
	dir, err := os.MkdirTemp("", "mui-permission-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := makeDirectory(configDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(configDir, 0, 65534); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDir, "config.json")
	if err := writeFileAtomic(path, []byte(`{"token":"fixture-only"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 65534); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `test -r "$1"`, "sh", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("worker cannot read config: %v %s", err, out)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{configDir, 0750}, {path, 0640}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("mode for %s: %v %v", item.path, info, err)
		}
	}
}
