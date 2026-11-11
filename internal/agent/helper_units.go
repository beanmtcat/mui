//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func coreActive() bool {
	_, err := serviceCommand("is-active", "--quiet", "mui-sing-box.service")
	return err == nil
}

func coreEnabled() bool {
	_, err := serviceCommand("is-enabled", "--quiet", "mui-sing-box.service")
	return err == nil
}

func coreInstalled() bool {
	info, err := os.Stat(CoreBinaryPath)
	return err == nil && info.Mode().IsRegular()
}

func needsCore(state shared.DesiredState) bool {
	for _, item := range state.Nodes {
		if item.Node.Enabled && !item.Node.Deleting {
			return true
		}
	}
	return false
}

func forwardActive() bool {
	_, err := serviceCommand("is-active", "--quiet", "mui-forward.service")
	return err == nil
}

func forwardEnabled() bool {
	_, err := serviceCommand("is-enabled", "--quiet", "mui-forward.service")
	return err == nil
}

func coreUnitForState(state shared.DesiredState) string {
	unit := coreUnit
	if len(shared.OutboundInterfaces(state.Nodes, state.OutboundInterface)) > 0 {
		// Older Linux kernels require NET_RAW for SO_BINDTODEVICE. Keep the
		// core unprivileged and grant it only while device binding is in use.
		unit = strings.ReplaceAll(unit, "=CAP_NET_BIND_SERVICE\n", "=CAP_NET_BIND_SERVICE CAP_NET_RAW\n")
	}
	return unit
}

func ensureCoreUnit(states ...shared.DesiredState) error {
	state, err := readCurrentChecked()
	if err != nil {
		return err
	}
	if len(states) > 0 {
		state = states[0]
	}
	if err := ensureServiceUser(coreUser, CoreDir); err != nil {
		return err
	}
	for _, dir := range []string{CoreDir, CertDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		if err := chownRootGroup(dir, coreUser); err != nil {
			return err
		}
	}
	path, unit, mode := serviceFile("mui-sing-box.service", coreUnitForState(state))
	content, err := os.ReadFile(path)
	if err == nil && string(content) == unit {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeFileAtomic(path, []byte(unit), mode); err != nil {
		return err
	}
	if _, err := serviceCommand("daemon-reload"); err != nil {
		return err
	}
	_, err = serviceCommand("enable", "mui-sing-box.service")
	return err
}

// ensureForwardUnit reports whether it had to (re)write the unit file.
func ensureForwardUnit() (bool, error) {
	if err := ensureServiceUser(forwardUser, ForwardDir); err != nil {
		return false, err
	}
	if err := makeDirectory(ForwardDir, 0750); err != nil {
		return false, err
	}
	if err := chownRootGroup(ForwardDir, forwardUser); err != nil {
		return false, err
	}
	if _, err := os.Stat(ForwardConfig); os.IsNotExist(err) {
		if err := writeOwned(ForwardConfig, []byte("[]"), 0640, forwardUser); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	}
	path, unit, mode := serviceFile("mui-forward.service", forwardUnit)
	content, err := os.ReadFile(path)
	if err == nil && string(content) == unit {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := writeFileAtomic(path, []byte(unit), mode); err != nil {
		return false, err
	}
	if _, err := serviceCommand("daemon-reload"); err != nil {
		return false, err
	}
	return true, nil
}

func waitForwardReady(config []byte) error {
	digest := sha256.Sum256(config)
	want := hex.EncodeToString(digest[:])
	for i := 0; i < 20; i++ {
		if got, err := os.ReadFile(ForwardReady); err == nil && string(got) == want && forwardActive() {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("转发进程未能启动并监听端口，请查看 mui-forward.service 日志")
}

func rollbackCore(previous []byte, wasActive, wasEnabled bool) {
	if len(previous) > 0 {
		_ = writeOwned(CoreConfig, previous, 0640, coreUser)
	} else {
		_ = os.Remove(CoreConfig)
	}
	if wasEnabled {
		_, _ = serviceCommand("enable", "mui-sing-box.service")
	} else {
		_, _ = serviceCommand("disable", "mui-sing-box.service")
	}
	if wasActive {
		_, _ = serviceCommand("restart", "mui-sing-box.service")
	} else {
		_, _ = serviceCommand("stop", "mui-sing-box.service")
	}
}

func CoreVersion() string {
	out, err := command(CoreBinaryPath, "version")
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}

func CheckCoreBuild() error { return checkCoreBuildAt(CoreBinaryPath) }

func checkCoreBuildAt(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOut, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box version check: %w: %s", err, strings.TrimSpace(string(versionOut)))
	}
	out := string(versionOut)
	if !strings.Contains(out, "with_v2ray_api") {
		return errors.New("sing-box must include with_v2ray_api build tag")
	}
	if !strings.Contains(out, "with_clash_api") {
		return errors.New("sing-box must include with_clash_api build tag")
	}
	version := regexp.MustCompile(`sing-box version (\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(out)
	if len(version) != 4 {
		return errors.New("cannot determine sing-box version")
	}
	major, _ := strconv.Atoi(version[1])
	minor, _ := strconv.Atoi(version[2])
	if major < 1 || (major == 1 && minor < 14) {
		return errors.New("Snell requires sing-box 1.14 or newer")
	}
	return nil
}
