//go:build linux

package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"mui/internal/shared"
)

func lockOffline() (func(), error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("请以 root 执行离线安装或应用命令")
	}
	// Online jobs own the same forward service. Refuse competing writers,
	// including an offline agent whose service is merely stopped temporarily.
	if _, err := os.Stat(ConfigDir + "/config.json"); err == nil {
		return nil, errors.New("此机已有面板接入配置；不能同时由面板和本地管理转发，请在独立的离线主机使用此命令")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile("/run/mui-offline.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("另一个离线安装或应用命令正在执行")
	}
	return func() { _ = f.Close() }, nil
}

func verifyOfflineRelease(self, offered string) (ed25519.PublicKey, error) {
	var key ed25519.PublicKey
	for _, path := range []string{ReleaseKeyPath, OfflineReleaseKeyPath} {
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		pinned, err := shared.ParseReleaseKey(string(raw))
		if err != nil {
			return nil, err
		}
		if key != nil && !key.Equal(pinned) {
			return nil, errors.New("本机固定的发布公钥冲突")
		}
		key = pinned
	}
	if strings.TrimSpace(offered) != "" {
		offeredKey, err := shared.ParseReleaseKey(offered)
		if err != nil {
			return nil, err
		}
		if key != nil && !key.Equal(offeredKey) {
			return nil, errors.New("不能替换本机已固定的发布公钥")
		}
		key = offeredKey
	}
	manifestPath := filepath.Join(filepath.Dir(self), "SHA256SUMS")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("请将同版本 SHA256SUMS 放在待安装的 mui-agent 旁: %w", err)
	}
	count := 0
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == "mui-agent" {
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("SHA256SUMS 必须且只能包含一个 mui-agent 条目")
	}
	if key != nil {
		sig, err := os.ReadFile(manifestPath + ".sig")
		if err != nil {
			return nil, err
		}
		if err := shared.VerifyManifest(key, manifest, sig); err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintln(os.Stderr, "未配置发布公钥：本次仅校验 SHA256SUMS；可使用 --release-key 或 --release-key-file 校验并固定发布公钥。")
	}
	if err := verifyChecksums(manifestPath, map[string]string{"mui-agent": self}); err != nil {
		return nil, err
	}
	return key, nil
}

// InstallOffline installs only the standalone forward service. It neither
// enrolls, launches a panel worker/helper, installs a core nor touches UFW.
func InstallOffline(config, releaseKey string) error {
	unlock, err := lockOffline()
	if err != nil {
		return err
	}
	defer unlock()
	_, raw, bundle, err := readOfflineDocument(config)
	if err != nil {
		return err
	}
	if err := checkOfflineIdentity(bundle); err != nil {
		return err
	}
	if err := checkServiceTools(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	key, err := verifyOfflineRelease(self, releaseKey)
	if err != nil {
		return err
	}
	if err := makeDirectory(ForwardDir, 0750); err != nil {
		return err
	}
	rb := &installRollback{}
	wasActive, wasEnabled := forwardActive(), forwardEnabled()
	unitPath, _, unitMode := serviceFile("mui-forward.service", forwardUnit)
	for path, mode := range map[string]os.FileMode{"/usr/local/bin/mui-agent": 0755, ForwardConfig: 0640, unitPath: unitMode, OfflineModePath: 0640, OfflineReleaseKeyPath: 0644, OfflineBundlePath: 0600} {
		if err := rb.backup(path, mode); err != nil {
			rb.rollback()
			_ = chownRootGroup(ForwardConfig, forwardUser)
			return err
		}
	}
	fail := func(cause error) error {
		var restoreErr error
		// Remove any newly created enable symlink before restoring/removing
		// the unit file; systemctl cannot disable a unit after it disappears.
		if !wasEnabled && fileExists(unitPath) {
			_, restoreErr = serviceCommand("disable", "mui-forward.service")
		}
		if !wasActive && forwardActive() {
			_, err := serviceCommand("stop", "mui-forward.service")
			restoreErr = errors.Join(restoreErr, err)
		}
		rb.rollback()
		_ = chownRootGroup(ForwardConfig, forwardUser)
		_, _ = serviceCommand("daemon-reload")
		if wasEnabled {
			_, err := serviceCommand("enable", "mui-forward.service")
			restoreErr = errors.Join(restoreErr, err)
		}
		if wasActive {
			_, err := serviceCommand("restart", "mui-forward.service")
			restoreErr = errors.Join(restoreErr, err)
			if err == nil {
				previous, readErr := os.ReadFile(ForwardConfig)
				if readErr == nil {
					readErr = waitForwardReady(previous)
				}
				restoreErr = errors.Join(restoreErr, readErr)
			}
		}
		if restoreErr != nil {
			return fmt.Errorf("%w; 恢复原服务状态失败: %v", cause, restoreErr)
		}
		return cause
	}
	if err := copyFile(self, "/usr/local/bin/mui-agent", 0755); err != nil {
		return fail(err)
	}
	if _, err := ensureForwardUnit(); err != nil {
		return fail(err)
	}
	if err := writeOwned(ForwardConfig, raw, 0640, forwardUser); err != nil {
		return fail(err)
	}
	if key != nil {
		if err := writeFileAtomic(OfflineReleaseKeyPath, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0644); err != nil {
			return fail(err)
		}
	}
	if err := writeFileAtomic(OfflineModePath, []byte(`{"version":1,"mode":"offline-forward"}`+"\n"), 0640); err != nil {
		return fail(err)
	}
	_ = os.Remove(ForwardReady)
	if _, err := serviceCommand("enable", "mui-forward.service"); err != nil {
		return fail(err)
	}
	if _, err := serviceCommand("restart", "mui-forward.service"); err != nil {
		return fail(err)
	}
	if err := waitForwardReady(raw); err != nil {
		return fail(err)
	}
	if err := commitOfflineBundle(bundle); err != nil {
		return fail(err)
	}
	rb.commit()
	return nil
}

// ApplyOfflineForwards replaces the config only after validation. It waits for
// the forwarder's digest acknowledgement; systemctl reload alone can succeed
// even when the asynchronous reload is subsequently rejected.
func ApplyOfflineForwards(config string) error {
	unlock, err := lockOffline()
	if err != nil {
		return err
	}
	defer unlock()
	if !fileExists(OfflineModePath) {
		return errors.New("请先使用 mui-agent offline install 安装离线转发服务")
	}
	_, raw, bundle, err := readOfflineDocument(config)
	if err != nil {
		return err
	}
	if err := checkOfflineIdentity(bundle); err != nil {
		return err
	}
	rb := &installRollback{}
	for _, path := range []string{OfflineBundlePath} {
		if err := rb.backup(path, 0600); err != nil {
			rb.rollback()
			return err
		}
	}
	defer func() {
		if rb != nil {
			rb.rollback()
		}
	}()
	old, err := os.ReadFile(ForwardConfig)
	if err != nil {
		return err
	}
	wasActive, wasEnabled := forwardActive(), forwardEnabled()
	if err := writeOwned(ForwardConfig, raw, 0640, forwardUser); err != nil {
		return err
	}
	activate := func(data []byte, reload bool) error {
		_ = os.Remove(ForwardReady)
		if _, err := serviceCommand("enable", "mui-forward.service"); err != nil {
			return err
		}
		verb := "restart"
		if reload {
			verb = "reload"
		}
		if _, err := serviceCommand(verb, "mui-forward.service"); err != nil {
			return err
		}
		return waitForwardReady(data)
	}
	applyErr := activate(raw, wasActive)
	if applyErr == nil {
		applyErr = commitOfflineBundle(bundle)
	}
	if err := applyErr; err != nil {
		restoreErr := writeOwned(ForwardConfig, old, 0640, forwardUser)
		if restoreErr == nil {
			if wasActive {
				restoreErr = activate(old, forwardActive())
			} else {
				_, restoreErr = serviceCommand("stop", "mui-forward.service")
			}
		}
		if !wasEnabled {
			_, enableErr := serviceCommand("disable", "mui-forward.service")
			restoreErr = errors.Join(restoreErr, enableErr)
		}
		if restoreErr != nil {
			return fmt.Errorf("%w; 恢复原配置失败: %v", err, restoreErr)
		}
		return fmt.Errorf("应用失败，已恢复原配置: %w", err)
	}
	rb.commit()
	rb = nil
	return nil
}

// UpgradeOffline is run by the installed, trusted agent. It copies the
// candidate binary and its manifest into a directory only root can write,
// checks them there against the release key pinned on this machine, refuses
// a downgrade, and only then runs the verified copy to install it and apply
// config. Running an uploaded binary first and letting it check itself would
// prove nothing: a modified binary would skip the check.
func UpgradeOffline(candidate, config string) error {
	unlock, err := lockOffline()
	if err != nil {
		return err
	}
	if !fileExists(OfflineModePath) {
		unlock()
		return errors.New("本机尚未安装离线转发服务；首次安装请使用 mui-agent offline install")
	}
	if config == "" {
		config = OfflineBundlePath
		if !fileExists(config) {
			config = ForwardConfig
		}
	}
	if filepath.Base(candidate) != "mui-agent" {
		unlock()
		return errors.New("待升级的程序文件名必须是 mui-agent，并与 SHA256SUMS 放在同一目录")
	}
	// Use the installed executable's filesystem: /run is often mounted noexec.
	// MkdirTemp creates a private 0700 directory in this root-managed location.
	stage, err := os.MkdirTemp("/usr/local/bin", ".mui-offline-upgrade-")
	if err != nil {
		unlock()
		return err
	}
	defer os.RemoveAll(stage)
	source := filepath.Dir(candidate)
	copies := map[string]os.FileMode{filepath.Base(candidate): 0700, "SHA256SUMS": 0600, "SHA256SUMS.sig": 0600}
	for name, mode := range copies {
		from := filepath.Join(source, name)
		if name == "SHA256SUMS.sig" && !fileExists(from) {
			continue // Only an unsigned release; verifyOfflineRelease decides.
		}
		if err := copyFile(from, filepath.Join(stage, name), mode); err != nil {
			unlock()
			return fmt.Errorf("复制待升级文件 %s: %w", name, err)
		}
	}
	verified := filepath.Join(stage, "mui-agent")
	// The pinned key only: an upgrade cannot bring its own key.
	key, err := verifyOfflineRelease(verified, "")
	if err != nil {
		unlock()
		return fmt.Errorf("新版本校验失败，未做任何改动: %w", err)
	}
	if key == nil {
		unlock()
		return errors.New("本机未固定发布公钥，拒绝执行待升级程序；请先通过可信渠道核实并配置发布公钥")
	}
	out, err := exec.Command(verified, "version").Output()
	if err != nil {
		unlock()
		return fmt.Errorf("新版本无法运行: %w", err)
	}
	next, err := parseSemver(string(out))
	if err != nil {
		unlock()
		return err
	}
	if current, err := parseSemver(Version); err == nil && next.compare(current) < 0 {
		unlock()
		return fmt.Errorf("不能降级：本机 %s，待安装 %s", Version, strings.TrimSpace(string(out)))
	}
	// The verified copy takes the lock itself.
	unlock()
	cmd := exec.Command(verified, "offline", "install", "--config", config)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
