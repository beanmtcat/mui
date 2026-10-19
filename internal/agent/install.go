//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"mui/internal/shared"
)

const forwardUnit = "[Unit]\nDescription=MUI TCP and UDP forwarder\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=mui-forward\nGroup=mui-forward\nExecStart=/usr/local/bin/mui-agent forward\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=3\nMemoryMax=384M\nRuntimeDirectory=mui-forward\nRuntimeDirectoryMode=0700\nNoNewPrivileges=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=/run/mui-forward\nCapabilityBoundingSet=\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n"
const coreUnit = "[Unit]\nDescription=Managed sing-box\nAfter=network-online.target\nWants=network-online.target\n[Service]\nUser=mui-core\nGroup=mui-core\nExecStart=/usr/local/bin/sing-box run -c " + CoreConfig + "\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nLimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n"

// The helper is root and runs ufw, useradd, systemctl and systemd-run; its
// protection is the narrow request whitelist. The agent itself runs
// unprivileged.
const helperUnit = "[Unit]\nDescription=MUI privileged helper\nAfter=network.target\n[Service]\nExecStart=/usr/local/bin/mui-agent helper\nRestart=always\nRuntimeDirectory=mui-agent\nRuntimeDirectoryMode=0755\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n"
const agentUnit = "[Unit]\nDescription=MUI agent\nAfter=network-online.target mui-agent-helper.service\nWants=network-online.target\nRequires=mui-agent-helper.service\n[Service]\nUser=mui-agent\nGroup=mui-agent\nExecStart=/usr/local/bin/mui-agent run\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n"

// installRollback tracks files replaced or created during install so a
// failure after the first mutation can restore the previous state: replaced
// files are restored from their .install-bak backup, newly created files are
// removed, and backups are deleted on success.
type installRollback struct {
	replaced []string // destinations with a .install-bak backup
	created  []string // destinations that did not exist before
}

func backupSuffix(dst string) string { return dst + ".install-bak" }

// backup records dst for rollback: an existing file is copied to
// dst.install-bak, a missing file is recorded as created.
func (r *installRollback) backup(dst string, mode os.FileMode) error {
	if _, err := os.Stat(dst); err == nil {
		if err := copyFile(dst, backupSuffix(dst), mode); err != nil {
			return fmt.Errorf("backup %s: %w", dst, err)
		}
		r.replaced = append(r.replaced, dst)
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	r.created = append(r.created, dst)
	return nil
}

func (r *installRollback) rollback() {
	for _, dst := range r.replaced {
		// Restore atomically; a failed restore is the best effort we have.
		_ = os.Rename(backupSuffix(dst), dst)
	}
	for _, dst := range r.created {
		_ = os.Remove(dst)
	}
}

func (r *installRollback) commit() {
	for _, dst := range r.replaced {
		_ = os.Remove(backupSuffix(dst))
	}
}

// Install installs the agent and, when core is non-empty, sing-box.
// Order: validate input -> read the pinned key and check compatibility
// (read-only) -> verify manifest + checksums (read-only) -> pre-check the
// core binary (read-only) -> enroll -> then mutate: users, directories,
// pinned key, binaries, config and units. Any failure after mutation starts
// rolls the replaced/created files back. The enrollment token must already
// be the final value: cmd/agent resolves --token-stdin / --token-file.
func Install(url, serverID, enrollToken, core, releaseKey string, proxies ...*shared.SOCKS5Proxy) error {
	var proxyConfig *shared.SOCKS5Proxy
	if len(proxies) > 0 {
		proxyConfig = proxies[0]
	}
	if err := shared.ValidateAgentProxy(proxyConfig); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("install must run as root on Linux")
	}
	if fileExists(OfflineModePath) {
		return errors.New("此机已安装离线转发服务，不能同时接入在线 Agent")
	}
	// 1. Validate input.
	if url == "" || serverID == "" || enrollToken == "" {
		return errors.New("panel URL, server ID and enrollment token are required")
	}
	parsedURL, err := validatePanelURL(url)
	if err != nil {
		return err
	}
	url = strings.TrimRight(parsedURL.String(), "/")
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	release := map[string]string{}
	for _, line := range strings.Split(string(osRelease), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			release[pair[0]] = strings.Trim(pair[1], "\"")
		}
	}
	if !supportedDistribution(release["ID"], release["VERSION_ID"]) {
		return fmt.Errorf("unsupported distribution %s %s", release["ID"], release["VERSION_ID"])
	}
	if err := checkServiceTools(); err != nil {
		return err
	}
	for _, tool := range []string{"sshd", "ss"} {
		if _, err = exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is required: %w", tool, err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// 2. Read the pinned key and check compatibility (read-only). A key
	// pinned by an earlier install stays authoritative: re-running the
	// installer must not be a way to replace it.
	key, err := pinnedReleaseKey()
	if err != nil {
		return fmt.Errorf("read pinned release key: %w", err)
	}
	releaseKey = strings.TrimSpace(releaseKey)
	pinNew := false
	if releaseKey != "" {
		offered, err := shared.ParseReleaseKey(releaseKey)
		if err != nil {
			return err
		}
		if key == nil {
			key, pinNew = offered, true
		} else if !key.Equal(offered) {
			return fmt.Errorf("this server pinned a different release key; remove %s first if the key really changed", ReleaseKeyPath)
		}
	}
	// 3. Verify manifest + checksums (read-only). The manifest is always
	// required. Its signature is checked whenever a release key is in play
	// (supplied now or pinned earlier); a panel without a key installs on its
	// own authority, as it then also does for upgrades.
	sumsPath := filepath.Join(filepath.Dir(self), "SHA256SUMS")
	if _, err := os.Stat(sumsPath); err != nil {
		return fmt.Errorf("install needs SHA256SUMS next to the installer: %w", err)
	}
	if key != nil {
		manifest, err := os.ReadFile(sumsPath)
		if err != nil {
			return err
		}
		signature, err := os.ReadFile(sumsPath + ".sig")
		if err != nil {
			return fmt.Errorf("signed install needs SHA256SUMS.sig next to the installer: %w", err)
		}
		if err = shared.VerifyManifest(key, manifest, signature); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stderr, "warning: no release public key; the binaries are checked against SHA256SUMS only. Set MUI_RELEASE_PUBLIC_KEY on the panel to require signed releases.")
	}
	// Verify before anything is installed, so a corrupted or swapped binary leaves no trace.
	if err = verifyChecksums(sumsPath, map[string]string{"mui-agent": self, "sing-box": core}); err != nil {
		return err
	}
	// 4. Pre-check the core binary before enrolling or mutating anything.
	if core != "" {
		if err = checkCoreBuildAt(core); err != nil {
			return fmt.Errorf("sing-box build: %w", err)
		}
	}
	// 5. Enroll.
	agentToken, panelPublicKey, err := Enroll(url, serverID, enrollToken, proxyConfig)
	if err != nil {
		return err
	}
	// 6. Mutate, with rollback on failure.
	rb := &installRollback{}
	fail := func(err error) error {
		rb.rollback()
		return err
	}
	users := map[string]string{agentUser: DataDir}
	if core != "" {
		users[coreUser] = CoreDir
	}
	for name, home := range users {
		if err = ensureServiceUser(name, home); err != nil {
			return fail(err)
		}
	}
	if err = makeDirectory(ConfigDir, 0750); err != nil {
		return fail(err)
	}
	if core != "" {
		for _, dir := range []string{CoreDir, CertDir} {
			if err = makeDirectory(dir, 0750); err != nil {
				return fail(err)
			}
			if err = chownRootGroup(dir, coreUser); err != nil {
				return fail(err)
			}
		}
	}
	if err = makeDirectory(DataDir, 0750); err != nil {
		return fail(err)
	}
	if err = makeDirectory("/run/mui-agent", 0755); err != nil {
		return fail(err)
	}
	if err = chownRootGroup(ConfigDir, agentUser); err != nil {
		return fail(err)
	}
	if pinNew {
		if err = rb.backup(ReleaseKeyPath, 0644); err != nil {
			return fail(err)
		}
		if err = writeFileAtomic(ReleaseKeyPath, []byte(releaseKey+"\n"), 0644); err != nil {
			return fail(err)
		}
	}
	if err = chownMui(DataDir); err != nil {
		return fail(err)
	}
	if err = rb.backup("/usr/local/bin/mui-agent", 0755); err != nil {
		return fail(err)
	}
	if err = copyFile(self, "/usr/local/bin/mui-agent", 0755); err != nil {
		return fail(err)
	}
	if core != "" {
		if err = rb.backup("/usr/local/bin/sing-box", 0755); err != nil {
			return fail(err)
		}
		if err = copyFile(core, "/usr/local/bin/sing-box", 0755); err != nil {
			return fail(err)
		}
	}
	if panelPublicKey != "" {
		if err = rb.backup(PanelPublicKeyPath, 0600); err != nil {
			return fail(err)
		}
		if err = writeFileAtomic(PanelPublicKeyPath, []byte(strings.TrimSpace(panelPublicKey)+"\n"), 0600); err != nil {
			return fail(fmt.Errorf("write panel public key: %w", err))
		}
	}
	if err := stopLegacyServices(); err != nil {
		return fail(err)
	}
	if err := migrateLegacyTraffic(); err != nil {
		return fail(err)
	}
	config, _ := json.Marshal(Config{URL: url, ServerID: serverID, Token: agentToken, AgentProxy: proxyConfig})
	if err = rb.backup(ConfigDir+"/config.json", 0640); err != nil {
		return fail(err)
	}
	if err = writeOwned(ConfigDir+"/config.json", config, 0640, agentUser); err != nil {
		return fail(err)
	}
	units := map[string]string{
		"mui-agent-helper.service": helperUnit,
		"mui-agent.service":        agentUnit,
	}
	if core != "" {
		units["mui-sing-box.service"] = coreUnit
	}
	for name, content := range units {
		path, content, mode := serviceFile(name, content)
		if err = rb.backup(path, mode); err != nil {
			return fail(err)
		}
		if err = writeFileAtomic(path, []byte(content), mode); err != nil {
			return fail(err)
		}
	}
	// Check using the actual service account before reporting installation success.
	// Root can read a config even when restrictive inherited umasks made its
	// parent directory inaccessible to the worker.
	if err = verifyInstalledConfig(); err != nil {
		return fail(err)
	}
	if _, err = serviceCommand("daemon-reload"); err != nil {
		return fail(err)
	}
	// restart rather than start: a re-install must pick up the new binary and units.
	for _, unit := range []string{"mui-agent-helper.service", "mui-agent.service"} {
		if _, err = serviceCommand("enable", unit); err != nil {
			return fail(err)
		}
		if _, err = serviceCommand("restart", unit); err != nil {
			return fail(err)
		}
	}
	// A reinstall updates the shared executable used by an existing forwarder.
	// Older installs started an empty forwarder; retire that service here too.
	if forwardActive() || forwardEnabled() {
		config, readErr := os.ReadFile(ForwardConfig)
		if readErr != nil && !os.IsNotExist(readErr) {
			return fail(readErr)
		}
		if len(config) == 0 || bytes.Equal(bytes.TrimSpace(config), []byte("[]")) {
			if _, err = serviceCommand("disable", "--now", "mui-forward.service"); err != nil {
				return fail(err)
			}
		} else if forwardActive() {
			if _, err = serviceCommand("try-restart", "mui-forward.service"); err != nil {
				return fail(err)
			}
		}
	}
	if core != "" {
		_, _ = serviceCommand("try-restart", "mui-sing-box.service")
	}
	rb.commit()
	return nil
}

// An older installation used panel-* unit names. Stop it before starting the
// renamed units so two sing-box instances cannot claim the same node ports.
func stopLegacyServices() error {
	_, _ = serviceCommand("stop", "panel-ufw-rollback.timer")
	for _, unit := range []string{"panel-agent.service", "panel-agent-helper.service", "panel-sing-box.service"} {
		path := filepath.Join("/etc/systemd/system", unit)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := serviceCommand("disable", "--now", unit); err != nil {
			return fmt.Errorf("stop legacy service %s: %w", unit, err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove legacy service %s: %w", unit, err)
		}
	}
	return nil
}

func migrateLegacyTraffic() error {
	destination := DataDir + "/traffic.json"
	if _, err := os.Stat(destination); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	legacy := "/var/lib/panel-agent/traffic.json"
	if _, err := os.Stat(legacy); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := copyFile(legacy, destination, 0600); err != nil {
		return fmt.Errorf("preserve legacy traffic: %w", err)
	}
	return chownMui(destination)
}

// verifyChecksums checks the binaries against the SHA256SUMS file that
// deploy/build-agent.sh writes next to them. A missing file is an error: an
// unverified install must not proceed.
func verifyChecksums(sumsPath string, files map[string]string) error {
	f, err := os.Open(sumsPath)
	if err != nil {
		return fmt.Errorf("open SHA256SUMS: %w", err)
	}
	defer f.Close()
	expected := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			expected[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	for name, path := range files {
		if path == "" {
			continue
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("SHA256SUMS has no entry for %s", name)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, in)
		in.Close()
		if err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("checksum mismatch for %s: got %s, SHA256SUMS says %s", name, got, want)
		}
	}
	return nil
}

// copyFile copies src to dst atomically: a temp file in the same directory,
// fsync, chmod, rename, then fsync the directory. A failure leaves no
// partial destination behind.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".mui-copy-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	if _, err = io.Copy(tmpFile, in); err != nil {
		tmpFile.Close()
		return err
	}
	if err = tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err = tmpFile.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err = os.Rename(tmp, dst); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(dst))
}

// makeDirectory also repairs an existing directory created under umask 077.
func makeDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func verifyInstalledConfig() error {
	uid, err := userID(agentUser)
	if err != nil {
		return err
	}
	gid, err := groupID(agentUser)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/local/bin/mui-agent", "check-config")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Agent 配置读取检查失败（以 mui-agent 账户执行）: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
