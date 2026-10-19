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
	client, err := panelHTTPClient(c.AgentProxy, 3*time.Minute)
	if err != nil {
		return "", err
	}
	defer client.CloseIdleConnections()
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
	manifest, err := fetchUpgradeManifest(ctx, client, prefix, key, name, expected)
	if err != nil {
		return "", err
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
	if err = copyFile(dst, backup, 0755); err != nil {
		return fmt.Errorf("backup current Agent: %w", err)
	}
	restore := func(cause error) error {
		if restoreErr := copyFile(backup, dst, 0755); restoreErr != nil {
			return fmt.Errorf("%w; restore old Agent: %v", cause, restoreErr)
		}
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
	// Watchdog: if the new agent has not confirmed a successful report within
	// four minutes, roll back. It runs the old, known-good binary, because the
	// new one may be too broken to do it, and systemd owns it, so it outlives
	// the helper replacing its own executable.
	suffix := randomUnitSuffix()
	if err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-watchdog", 4*time.Minute, backup, "rollback-if-unconfirmed", expected); err != nil {
		return restore(fmt.Errorf("schedule upgrade watchdog: %w", err))
	}
	if openRC() {
		err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-restart", 10*time.Second, "/sbin/rc-service", "mui-agent-helper", "restart")
		if err == nil {
			err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-worker", 11*time.Second, "/sbin/rc-service", "mui-agent", "restart")
		}
	} else {
		err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-restart", 10*time.Second, "/bin/systemctl", "restart", "mui-agent-helper.service", "mui-agent.service")
	}
	if err == nil && forwardActive() {
		if openRC() {
			err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-forward", 12*time.Second, "/sbin/rc-service", "mui-forward", "restart")
		} else {
			err = scheduleServiceJob("mui-agent-upgrade-"+suffix+"-forward", 12*time.Second, "/bin/systemctl", "try-restart", "mui-forward.service")
		}
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
	// Refuse a candidate older than the running core; a rebuild of the same
	// version (other build options) is allowed.
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
			if candidateVer.compare(currentVer) < 0 {
				return fmt.Errorf("candidate sing-box version %d.%d.%d is older than current %s", candidateVer.Major, candidateVer.Minor, candidateVer.Patch, strings.TrimSpace(CoreVersion()))
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
		if err = copyFile(dst, backup, 0755); err != nil {
			return fmt.Errorf("backup current sing-box: %w", err)
		}
	}
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
		if previouslyActive {
			if _, restoreErr := serviceCommand("restart", "mui-sing-box.service"); restoreErr != nil {
				return fmt.Errorf("%w; restart old sing-box: %v", cause, restoreErr)
			}
		} else {
			_, _ = serviceCommand("stop", "mui-sing-box.service")
		}
		return cause
	}
	if err = ensureCoreUnit(); err != nil {
		return rollback(err)
	}
	if previouslyActive {
		if _, err = serviceCommand("restart", "mui-sing-box.service"); err != nil {
			return rollback(err)
		}
		if !coreActive() {
			return rollback(errors.New("new sing-box did not stay running"))
		}
		if err = verifyNodeListeners(state); err != nil {
			return rollback(err)
		}
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
	for _, path := range []string{UpgradeConfirmedPath, DataDir + "/upgrade-confirmed"} {
		if confirmed, err := os.ReadFile(path); err == nil && string(confirmed) == expected {
			return nil
		}
	}
	dst := "/usr/local/bin/mui-agent"
	sum, err := fileSHA256(dst)
	if err != nil || sum != expected {
		return nil // A newer/manual install replaced this build; leave it alone.
	}
	if err := copyFile(dst+".previous", dst, 0755); err != nil {
		return fmt.Errorf("restore previous Agent: %w", err)
	}
	_, err = serviceCommand("restart", "mui-agent-helper.service", "mui-agent.service")
	if err != nil {
		return err
	}
	if forwardActive() {
		_, err = serviceCommand("try-restart", "mui-forward.service")
	}
	return err
}
