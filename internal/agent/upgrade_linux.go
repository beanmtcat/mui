//go:build linux

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

const (
	maxAgentBinarySize = 128 << 20
	maxCoreBinarySize  = 256 << 20
)

// validatePanelURL is the strict panel URL check shared by Install,
// downloadUpgradeArtifact and (in spirit) the worker: no userinfo, query or
// fragment; only https, or http on loopback.
func validatePanelURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		return nil, errors.New("panel URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("panel URL must not contain a query")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("panel URL must not contain a fragment")
	}
	if u.Scheme == "https" {
		// ok
	} else if u.Scheme == "http" && u.Hostname() == "127.0.0.1" {
		// ok
	} else {
		return nil, errors.New("upgrade requires a trusted HTTPS panel URL")
	}
	if u.Host == "" {
		return nil, errors.New("panel URL must contain a host")
	}
	return u, nil
}

// semver is a parsed X.Y.Z version. Pre-release/build suffixes are ignored:
// "1.14.0-rc1" compares equal to "1.14.0".
type semver struct {
	Major, Minor, Patch int
}

func (v semver) compare(o semver) int {
	if v.Major != o.Major {
		return compareInt(v.Major, o.Major)
	}
	if v.Minor != o.Minor {
		return compareInt(v.Minor, o.Minor)
	}
	return compareInt(v.Patch, o.Patch)
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

var semverPattern = regexp.MustCompile(`\bv?(\d+)\.(\d+)\.(\d+)\b`)

// parseSemver finds the first X.Y.Z version in s. It accepts a bare version
// ("0.6.0"), a probe line ("mui-agent 0.6.0") and a sing-box version line
// ("sing-box version 1.14.0 (...)").
func parseSemver(s string) (semver, error) {
	m := semverPattern.FindStringSubmatch(s)
	if m == nil {
		return semver{}, fmt.Errorf("no semantic version in %q", strings.TrimSpace(s))
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return semver{}, err
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return semver{}, err
	}
	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return semver{}, err
	}
	return semver{Major: major, Minor: minor, Patch: patch}, nil
}

// manifestMinVersion returns the "# min-version: X.Y.Z" annotation from a
// SHA256SUMS manifest, if present.
func manifestMinVersion(manifest []byte) (semver, bool, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if !strings.HasPrefix(rest, "min-version:") {
			continue
		}
		ver, err := parseSemver(strings.TrimSpace(strings.TrimPrefix(rest, "min-version:")))
		if err != nil {
			return semver{}, true, fmt.Errorf("invalid min-version in release manifest: %w", err)
		}
		return ver, true, nil
	}
	return semver{}, false, nil
}

// The root helper takes the download URL from its root-owned config, never
// from the unprivileged worker's request. The task pins the file's SHA-256.
func downloadUpgradeArtifact(name, expected string, maxSize int64) (string, error) {
	if name != "mui-agent" && name != "sing-box" {
		return "", errors.New("unsupported upgrade artifact")
	}
	if len(expected) != 64 {
		return "", errors.New("invalid upgrade SHA-256")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return "", errors.New("invalid upgrade SHA-256")
	}
	// Without a pinned release key the SHA-256 comes from the panel alone; the
	// upgrade then trusts the panel, as the installation did. Once a key is
	// pinned, a signed manifest is required (checked after the download).
	key, err := pinnedReleaseKey()
	if err != nil {
		return "", fmt.Errorf("read pinned release key: %w", err)
	}
	c, err := ReadConfig()
	if err != nil {
		return "", err
	}
	base, err := validatePanelURL(c.URL)
	if err != nil {
		return "", err
	}
	endpoint := strings.TrimRight(base.String(), "/") + "/download/" + runtime.GOARCH + "/" + name
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s download HTTP %d", name, resp.StatusCode)
	}
	tmp, err := os.CreateTemp("/usr/local/bin", "."+name+"-upgrade-*")
	if err != nil {
		return "", err
	}
	valid := false
	defer func() {
		_ = tmp.Close()
		if !valid {
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return "", err
	}
	if n == 0 || n > maxSize || hex.EncodeToString(h.Sum(nil)) != expected {
		return "", fmt.Errorf("downloaded %s failed size or SHA-256 verification", name)
	}
	// The hash above came from the panel together with the file. With a pinned
	// release key it must also be listed in a manifest signed off the panel.
	prefix := strings.TrimRight(base.String(), "/") + "/download/" + runtime.GOARCH + "/"
	manifest, err := fetchSmall(ctx, client, prefix+"SHA256SUMS")
	if err != nil {
		return "", err
	}
	signature, err := fetchSmall(ctx, client, prefix+"SHA256SUMS.sig")
	if err != nil {
		return "", err
	}
	if err = shared.VerifyManifest(key, manifest, signature); err != nil {
		return "", err
	}
	if listed, ok := shared.ManifestHash(manifest, name); !ok || listed != expected {
		return "", fmt.Errorf("%s is not listed in the signed release manifest", name)
	}
	// A release may require a minimum agent version (e.g. for a new helper
	// protocol). Refuse to upgrade into a release this agent cannot serve.
	if minVer, ok, err := manifestMinVersion(manifest); err != nil {
		return "", err
	} else if ok {
		current, err := parseSemver(Version)
		if err != nil {
			return "", fmt.Errorf("current agent version: %w", err)
		}
		if current.compare(minVer) < 0 {
			return "", fmt.Errorf("release requires agent >= %d.%d.%d (current %s)", minVer.Major, minVer.Minor, minVer.Patch, Version)
		}
	}
	if err = tmp.Chmod(0755); err != nil {
		return "", err
	}
	if err = tmp.Sync(); err != nil {
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	valid = true
	return tmp.Name(), nil
}

func fetchSmall(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", endpoint, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// randomUnitSuffix returns an unpredictable suffix for transient systemd-run
// unit names, so a concurrent or repeated upgrade cannot collide with or
// predict another unit's name.
func randomUnitSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// rotateBackup rolls the existing .previous backup to .previous2 (dropping
// the old .previous2), so two generations of backups are kept.
func rotateBackup(backup string) {
	_ = os.Remove(backup + "2")
	_ = os.Rename(backup, backup+"2")
}

// writeWatchdogTimer installs a persistent timer + service that runs
// execStart once after the given delay. Persistent=true makes the timer fire
// after a reboot if the machine was down when it was due.
func writeWatchdogTimer(name, execStart, delay string) error {
	servicePath := "/etc/systemd/system/" + name + ".service"
	timerPath := "/etc/systemd/system/" + name + ".timer"
	service := "[Unit]\nDescription=MUI upgrade watchdog\n[Service]\nType=oneshot\nExecStart=" + execStart + "\n"
	timer := "[Unit]\nDescription=MUI upgrade watchdog timer\n[Timer]\nOnActiveSec=" + delay + "\nPersistent=true\nUnit=" + name + ".service\n[Install]\nWantedBy=timers.target\n"
	if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(timerPath, []byte(timer), 0644); err != nil {
		return err
	}
	if _, err := command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command("systemctl", "enable", "--now", name+".timer"); err != nil {
		return err
	}
	return nil
}

// clearWatchdogTimer stops and removes a persistent watchdog timer + service.
// Best effort: a stale watchdog that still fires is harmless (it checks the
// confirmation file and the running binary's hash before acting), but a
// leftover timer must not roll back a later, healthy upgrade.
func clearWatchdogTimer(name string) {
	_, _ = command("systemctl", "disable", "--now", name+".timer")
	_ = os.Remove("/etc/systemd/system/" + name + ".service")
	_ = os.Remove("/etc/systemd/system/" + name + ".timer")
	_, _ = command("systemctl", "daemon-reload")
}

func upgradeAgent(expected string) error {
	candidate, err := downloadUpgradeArtifact("mui-agent", expected, maxAgentBinarySize)
	if err != nil {
		return err
	}
	defer os.Remove(candidate)
	info, err := buildinfo.ReadFile(candidate)
	if err != nil || info.Path != "mui/cmd/agent" {
		return errors.New("downloaded file is not a MUI Agent build")
	}
	probeCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	output, err := exec.CommandContext(probeCtx, candidate, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(output), "mui-agent ") {
		return errors.New("downloaded Agent binary cannot start or does not support self-update")
	}
	// Refuse a candidate older than the running agent: a downgrade must be an
	// explicit, manual operation. The same version is allowed, because a
	// rebuild of it (a fix, a different sing-box) is a normal release.
	candidateVer, err := parseSemver(string(output))
	if err != nil {
		return fmt.Errorf("candidate agent version: %w", err)
	}
	currentVer, err := parseSemver(Version)
	if err != nil {
		return fmt.Errorf("current agent version: %w", err)
	}
	if candidateVer.compare(currentVer) < 0 {
		return fmt.Errorf("candidate agent version %d.%d.%d is older than current %s", candidateVer.Major, candidateVer.Minor, candidateVer.Patch, Version)
	}
	dst := "/usr/local/bin/mui-agent"
	backup := dst + ".previous"
	rotateBackup(backup)
	if err = copyFile(dst, backup, 0700); err != nil {
		return fmt.Errorf("backup current Agent: %w", err)
	}
	restore := func(cause error) error {
		if restoreErr := copyFile(backup, dst, 0755); restoreErr != nil {
			return fmt.Errorf("%w; restore old Agent: %v", cause, restoreErr)
		}
		clearWatchdogTimer("mui-agent-upgrade-watchdog")
		return cause
	}
	if err = os.Rename(candidate, dst); err != nil {
		return restore(err)
	}
	// Clear any stale confirmation so the new build must prove itself.
	if err = os.Remove(UpgradeConfirmedPath); err != nil && !os.IsNotExist(err) {
		return restore(fmt.Errorf("clear previous upgrade confirmation: %w", err))
	}
	if err = os.Remove(DataDir + "/upgrade-confirmed"); err != nil && !os.IsNotExist(err) {
		return restore(fmt.Errorf("clear previous upgrade confirmation: %w", err))
	}
	// Persistent watchdog: if the new agent never confirms a successful
	// report, roll back. It runs the old, known-good binary: the new binary
	// itself may be too broken to execute the rollback.
	if err = writeWatchdogTimer("mui-agent-upgrade-watchdog", backup+" rollback-if-unconfirmed "+expected, "4min"); err != nil {
		return restore(fmt.Errorf("install upgrade watchdog: %w", err))
	}
	// systemd owns the delayed restart, so it survives the helper replacing its
	// own executable. The running sing-box service is left untouched.
	suffix := randomUnitSuffix()
	_, err = command("systemd-run", "--quiet", "--unit", "mui-agent-upgrade-"+suffix+"-restart", "--on-active=10s", "/bin/systemctl", "restart", "mui-agent-helper.service", "mui-agent.service")
	if err == nil && forwardActive() {
		_, err = command("systemd-run", "--quiet", "--unit", "mui-agent-upgrade-"+suffix+"-forward", "--on-active=12s", "/bin/systemctl", "try-restart", "mui-forward.service")
	}
	if err != nil {
		return restore(fmt.Errorf("schedule restart: %w", err))
	}
	return nil
}

// upgradeCore validates the candidate against the live configuration before
// replacing the binary. A failed restart restores the previous executable.
func upgradeCore(expected string) error {
	candidate, err := downloadUpgradeArtifact("sing-box", expected, maxCoreBinarySize)
	if err != nil {
		return err
	}
	defer os.Remove(candidate)
	build, err := buildinfo.ReadFile(candidate)
	if err != nil || build.Path != "github.com/sagernet/sing-box/cmd/sing-box" {
		return errors.New("downloaded file is not a sing-box build")
	}
	if err = checkCoreBuildAt(candidate); err != nil {
		return fmt.Errorf("new sing-box build: %w", err)
	}
	dst := CoreBinaryPath
	_, statErr := os.Stat(dst)
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	hadBinary := statErr == nil
	// Refuse a candidate that is not newer than the running core.
	if hadBinary {
		probeCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		candidateOut, probeErr := exec.CommandContext(probeCtx, candidate, "version").CombinedOutput()
		stop()
		if probeErr != nil {
			return fmt.Errorf("new sing-box version probe: %w: %s", probeErr, strings.TrimSpace(string(candidateOut)))
		}
		candidateVer, err := parseSemver(string(candidateOut))
		if err != nil {
			return fmt.Errorf("candidate sing-box version: %w", err)
		}
		if currentVer, err := parseSemver(CoreVersion()); err == nil {
			if candidateVer.compare(currentVer) <= 0 {
				return fmt.Errorf("candidate sing-box version %d.%d.%d is not newer than current %s", candidateVer.Major, candidateVer.Minor, candidateVer.Patch, strings.TrimSpace(CoreVersion()))
			}
		}
		// An unparseable current version (e.g. "unavailable") does not block
		// the upgrade: the candidate has already passed its own checks.
	}
	if _, err = os.Stat(CoreConfig); err == nil {
		checkCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		output, checkErr := exec.CommandContext(checkCtx, candidate, "check", "-c", CoreConfig).CombinedOutput()
		stop()
		if checkErr != nil {
			return fmt.Errorf("new sing-box rejects current config: %w: %s", checkErr, strings.TrimSpace(string(output)))
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	previouslyActive := coreActive()
	state := ReadCurrent()
	if !previouslyActive {
		for _, item := range state.Nodes {
			if item.Node.Enabled {
				return errors.New("sing-box service is not active while nodes are enabled; repair the service before upgrading")
			}
		}
	}
	backup := dst + ".previous"
	if hadBinary {
		rotateBackup(backup)
		if err = copyFile(dst, backup, 0700); err != nil {
			return fmt.Errorf("backup current sing-box: %w", err)
		}
	}
	// A stale confirmation from an earlier upgrade must not satisfy this one.
	_ = os.Remove(CoreUpgradeConfirmedPath)
	if err = os.Rename(candidate, dst); err != nil {
		return err
	}
	rollback := func(cause error) error {
		if hadBinary {
			if restoreErr := copyFile(backup, dst, 0755); restoreErr != nil {
				return fmt.Errorf("%w; restore old sing-box: %v", cause, restoreErr)
			}
		} else {
			_ = os.Remove(dst)
		}
		_ = os.Remove(DataDir + "/core-upgrade-pending")
		clearWatchdogTimer("mui-core-upgrade-watchdog")
		if previouslyActive {
			if _, restoreErr := command("systemctl", "restart", "mui-sing-box.service"); restoreErr != nil {
				return fmt.Errorf("%w; restart old sing-box: %v", cause, restoreErr)
			}
		} else {
			_, _ = command("systemctl", "stop", "mui-sing-box.service")
		}
		return cause
	}
	if err = ensureCoreUnit(); err != nil {
		return rollback(err)
	}
	if previouslyActive {
		if _, err = command("systemctl", "restart", "mui-sing-box.service"); err != nil {
			return rollback(err)
		}
		if !coreActive() {
			return rollback(errors.New("new sing-box did not stay running"))
		}
		if err = verifyNodeListeners(state); err != nil {
			return rollback(err)
		}
	}
	// The upgrade succeeded. Arm the persistent watchdog and record the
	// pending upgrade: if the worker never confirms the new core healthy,
	// the watchdog restores the previous binary. The worker confirms via
	// CallHelper("core.confirm") after the panel acknowledges the result.
	if err = writeWatchdogTimer("mui-core-upgrade-watchdog", "/usr/local/bin/mui-agent rollback-core-if-unconfirmed "+expected, "5min"); err != nil {
		return rollback(fmt.Errorf("install core upgrade watchdog: %w", err))
	}
	if err = writeFileAtomic(DataDir+"/core-upgrade-pending", []byte(expected), 0600); err != nil {
		return rollback(fmt.Errorf("record pending core upgrade: %w", err))
	}
	return nil
}

// The scheduled watchdog uses the old, known-good binary. If the new Agent
// cannot make a successful report, restore it and reconnect automatically.
func RollbackIfUnconfirmed(expected string) error {
	if os.Geteuid() != 0 {
		return errors.New("upgrade rollback must run as root")
	}
	if len(expected) != 64 {
		return errors.New("invalid upgrade SHA-256")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("invalid upgrade SHA-256")
	}
	if confirmed, err := os.ReadFile(UpgradeConfirmedPath); err == nil && string(confirmed) == expected {
		// Confirmed: drop the superseded backup and the watchdog.
		_ = os.Remove("/usr/local/bin/mui-agent.previous")
		clearWatchdogTimer("mui-agent-upgrade-watchdog")
		return nil
	}
	if confirmed, err := os.ReadFile(DataDir + "/upgrade-confirmed"); err == nil && string(confirmed) == expected {
		// Legacy confirmation path, kept for one transition: installations
		// whose confirmation was written before the path moved.
		_ = os.Remove("/usr/local/bin/mui-agent.previous")
		_ = os.Remove(DataDir + "/upgrade-confirmed")
		clearWatchdogTimer("mui-agent-upgrade-watchdog")
		return nil
	}
	dst := "/usr/local/bin/mui-agent"
	sum, err := fileSHA256(dst)
	if err != nil || sum != expected {
		return nil // A newer/manual install replaced this build; leave it alone.
	}
	if err := copyFile(dst+".previous", dst, 0755); err != nil {
		return fmt.Errorf("restore previous Agent: %w", err)
	}
	clearWatchdogTimer("mui-agent-upgrade-watchdog")
	_, err = command("systemctl", "restart", "mui-agent-helper.service", "mui-agent.service")
	if err != nil {
		return err
	}
	if forwardActive() {
		_, err = command("systemctl", "try-restart", "mui-forward.service")
	}
	return err
}

// RollbackCoreIfUnconfirmed is the core-upgrade watchdog's entry point. If the
// new core was confirmed healthy, it cleans the watchdog and the pending
// marker. If the running sing-box is not the unconfirmed new build, it does
// nothing. Otherwise the new build never proved itself healthy: restore the
// previous binary and restart the service.
func RollbackCoreIfUnconfirmed(expected string) error {
	if os.Geteuid() != 0 {
		return errors.New("core upgrade rollback must run as root")
	}
	if len(expected) != 64 {
		return errors.New("invalid upgrade SHA-256")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("invalid upgrade SHA-256")
	}
	if confirmed, err := os.ReadFile(CoreUpgradeConfirmedPath); err == nil && string(confirmed) == expected {
		_ = os.Remove(DataDir + "/core-upgrade-pending")
		clearWatchdogTimer("mui-core-upgrade-watchdog")
		return nil
	}
	sum, err := fileSHA256(CoreBinaryPath)
	if err != nil || sum != expected {
		return nil // A newer/manual install replaced this build; leave it alone.
	}
	if err := copyFile(CoreBinaryPath+".previous", CoreBinaryPath, 0755); err != nil {
		return fmt.Errorf("restore previous sing-box: %w", err)
	}
	_ = os.Remove(DataDir + "/core-upgrade-pending")
	clearWatchdogTimer("mui-core-upgrade-watchdog")
	_, err = command("systemctl", "restart", "mui-sing-box.service")
	return err
}
