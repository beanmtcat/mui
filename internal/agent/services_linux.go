//go:build linux

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Keep service operations behind one adapter. Alpine uses OpenRC; installing a
// systemctl shim would hide failures in restarts, timers and upgrade rollback.
func openRC() bool {
	return fileExists("/sbin/openrc-run") && !fileExists("/run/systemd/system")
}

func checkServiceTools() error {
	tools := []string{"systemctl", "systemd-run", "useradd"}
	if openRC() {
		tools = []string{"rc-service", "rc-update", "supervise-daemon", "adduser", "addgroup"}
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is required: %w", tool, err)
		}
	}
	return nil
}

func ensureServiceUser(name, home string) error {
	if _, err := command("id", "-u", name); err == nil {
		return nil
	}
	if openRC() {
		group, err := os.ReadFile("/etc/group")
		if err != nil {
			return err
		}
		found := false
		for _, line := range strings.Split(string(group), "\n") {
			if strings.HasPrefix(line, name+":") {
				found = true
				break
			}
		}
		if !found {
			if _, err := command("addgroup", "-S", name); err != nil {
				return err
			}
		}
		_, err = command("adduser", "-S", "-D", "-H", "-G", name, "-h", home, "-s", "/sbin/nologin", name)
		return err
	}
	_, err := command("useradd", "--system", "--home", home, "--shell", "/usr/sbin/nologin", name)
	return err
}

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

func serviceCommand(args ...string) (string, error) {
	if !openRC() {
		return command("systemctl", args...)
	}
	if len(args) == 0 {
		return "", errors.New("missing service operation")
	}
	verb := args[0]
	if verb == "daemon-reload" || verb == "reset-failed" {
		return "", nil
	}
	now := false
	var services []string
	for _, arg := range args[1:] {
		if arg == "--quiet" {
			continue
		}
		if arg == "--now" {
			now = true
			continue
		}
		name := strings.TrimSuffix(arg, ".service")
		if !serviceNamePattern.MatchString(name) {
			return "", fmt.Errorf("invalid service name %q", arg)
		}
		services = append(services, name)
	}
	if len(services) == 0 {
		return "", errors.New("missing service name")
	}
	var out string
	for _, name := range services {
		var err error
		switch verb {
		case "is-active":
			out, err = command("rc-service", name, "status")
		case "is-enabled":
			_, err = os.Stat(filepath.Join("/etc/runlevels/default", name))
		case "enable":
			out, err = command("rc-update", "add", name, "default")
			if err == nil && now {
				out, err = command("rc-service", name, "start")
			}
		case "disable":
			if fileExists(filepath.Join("/etc/runlevels/default", name)) {
				out, err = command("rc-update", "del", name, "default")
			}
			if err == nil && now {
				if fileExists(filepath.Join("/etc/init.d", name)) {
					out, err = command("rc-service", name, "stop")
				}
			}
		case "try-restart":
			if _, activeErr := command("rc-service", name, "status"); activeErr == nil {
				out, err = command("rc-service", name, "restart")
			}
		case "start", "stop", "restart", "reload":
			out, err = command("rc-service", name, verb)
		default:
			return "", fmt.Errorf("unsupported OpenRC operation %q", verb)
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func serviceFile(unit, systemd string) (string, string, os.FileMode) {
	if !openRC() {
		if unit == "mui-sing-box.service" {
			systemd = strings.Replace(systemd, "[Service]\n", "[Service]\nEnvironment=GOMEMLIMIT="+strconv.FormatInt(memoryBudget("core", availableMemory()), 10)+"\n", 1)
		}
		return filepath.Join("/etc/systemd/system", unit), systemd, 0644
	}
	name := strings.TrimSuffix(unit, ".service")
	user, binary, args := "root", "/usr/local/bin/mui-agent", "helper"
	startPre, depend, extra := `checkpath -d -m 0755 -o root:root /run/mui-agent`, "after net", ""
	switch name {
	case "mui-agent":
		user, args, startPre, depend = agentUser, "run", ":", "need mui-agent-helper\n    after net"
	case "mui-forward":
		user, args = forwardUser, "forward"
		startPre = `checkpath -d -m 0700 -o mui-forward:mui-forward /run/mui-forward`
		extra = `extra_started_commands="reload"
reload() {
    supervise-daemon "${RC_SVCNAME}" --signal HUP
}
`
	case "mui-sing-box":
		user, binary, args, startPre = coreUser, CoreBinaryPath, "run -c "+CoreConfig, ":"
		extra = "export GOMEMLIMIT=" + strconv.FormatInt(memoryBudget("core", availableMemory()), 10) + "\n"
	}
	script := fmt.Sprintf(`#!/sbin/openrc-run
description="MUI %s"
command="%s"
command_args="%s"
command_user="%s:%s"
supervisor="supervise-daemon"
pidfile="/run/${RC_SVCNAME}.pid"
respawn_delay=5
respawn_max=0
no_new_privs=yes
output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.log"
%s
depend() {
    %s
}
start_pre() {
    %s || return 1
    checkpath -f -m 0640 -o %s:%s "/var/log/${RC_SVCNAME}.log"
}
`, name, binary, args, user, user, extra, depend, startPre, user, user)
	return filepath.Join("/etc/init.d", name), script, 0755
}

// Jobs are detached from the helper so an upgrade or crash cannot disarm its
// watchdog. OpenRC jobs use root-owned files, positional shell arguments and a
// separate session; cancellation removes the token before the deadline.
const serviceJobDir = "/run/mui-service-jobs"

func scheduleServiceJob(name string, delay time.Duration, executable string, args ...string) error {
	if !openRC() {
		call := []string{"--quiet", "--unit", name, "--on-active=" + strconv.FormatInt(int64(delay/time.Second), 10) + "s", executable}
		_, err := command("systemd-run", append(call, args...)...)
		return err
	}
	if !serviceNamePattern.MatchString(name) || !filepath.IsAbs(executable) {
		return errors.New("invalid scheduled service job")
	}
	if err := makeDirectory(serviceJobDir, 0700); err != nil {
		return err
	}
	// Each generation has its own token: a cancelled older job cannot remove
	// the token belonging to a newer UFW rollback timer with the same name.
	token := filepath.Join(serviceJobDir, name+"."+randomUnitSuffix())
	if err := writeFileAtomic(token, nil, 0600); err != nil {
		return err
	}
	script := `sleep "$1"; token=$2; shift 2; [ -f "$token" ] || exit 0; rm -f "$token"; exec "$@"`
	call := []string{"-c", script, "mui-service-job", strconv.FormatInt(int64(delay/time.Second), 10), token, executable}
	cmd := exec.Command("/bin/sh", append(call, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(token)
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func cancelServiceJob(name string) {
	if openRC() {
		if serviceNamePattern.MatchString(name) {
			paths, _ := filepath.Glob(filepath.Join(serviceJobDir, name+".*"))
			for _, path := range paths {
				_ = os.Remove(path)
			}
		}
		return
	}
	_, _ = serviceCommand("stop", name+".timer")
	_, _ = serviceCommand("reset-failed", name+".service")
}

func coreMainPID() string {
	if openRC() {
		// OpenRC keeps the supervised child's PID separately from its supervisor.
		raw, err := os.ReadFile("/run/openrc/options/mui-sing-box/child_pid")
		if err != nil {
			return ""
		}
		pid := strings.TrimSpace(string(raw))
		if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
			return ""
		}
		return pid
	}
	out, err := command("systemctl", "show", "-p", "MainPID", "--value", "mui-sing-box.service")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
