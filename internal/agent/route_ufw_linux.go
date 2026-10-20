//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

const routeUFWProfilePath = "/etc/ufw/applications.d/mui-chain"

func routeUFWIPv6() bool {
	data, err := os.ReadFile("/etc/default/ufw")
	if err != nil {
		return true // Verify both families if the UFW setting cannot be read.
	}
	for _, raw := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if ok && strings.TrimSpace(key) == "IPV6" {
			return strings.Trim(strings.TrimSpace(strings.Split(value, "#")[0]), "\"'") != "no"
		}
	}
	return true
}

func checkRouteUFWSSH(state shared.DesiredState) error {
	ports := routeUFWPorts(state)
	if len(ports) == 0 {
		return nil
	}
	ssh, err := sshPorts()
	if err != nil {
		return err
	}
	for port := range ssh {
		if ports[portProto{port, "tcp"}] {
			return fmt.Errorf("链路端口 %d 与本机 SSH 端口冲突，不能覆盖 SSH 防火墙规则", port)
		}
	}
	return nil
}

func routeUFWDrift(status string, state shared.DesiredState) bool {
	rules := routeUFWRules(state)
	if !routeUFWAtHead(status, rules, routeUFWIPv6()) {
		return true
	}
	if len(rules) > 0 {
		data, err := os.ReadFile(routeUFWProfilePath)
		return err != nil || !bytes.Equal(data, routeUFWProfiles("", rules))
	}
	return false
}

func syncRouteUFW(state shared.DesiredState, status string) error {
	rules := routeUFWRules(state)
	var present []ufwLine
	for _, line := range parseMuiLines(status) {
		if strings.HasPrefix(line.ID, routeUFWPrefix) {
			present = append(present, line)
		}
	}
	if len(rules) == 0 && len(present) == 0 {
		return nil
	}
	if err := checkRouteUFWSSH(state); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(routeUFWProfilePath), 0755); err != nil {
		return err
	}
	if err := writeOwned(routeUFWProfilePath, routeUFWProfiles(status, rules), 0644, "root"); err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, r := range rules {
		wanted[r.ID] = true
	}
	ready := routeUFWAtHead(status, rules, routeUFWIPv6())
	for _, line := range present {
		if !wanted[line.ID] {
			ready = false
		}
	}
	if !ready {
		// Application profile rules cannot be moved by UFW. Rebuild only the
		// MUI chain prefix; external rules and SSH remain in their original order.
		sort.Slice(present, func(i, j int) bool { return present[i].Index > present[j].Index })
		for _, line := range present {
			if _, err := commandTimeout("ufw", 60*time.Second, "--force", "delete", strconv.Itoa(line.Index)); err != nil {
				return err
			}
		}
		for i := len(rules) - 1; i >= 0; i-- {
			if err := addUFWRuleAt(rules[i], 60*time.Second, true); err != nil {
				return err
			}
		}
		out, err := command("ufw", "status", "numbered")
		if err != nil {
			return err
		}
		if !routeUFWAtHead(out, rules, routeUFWIPv6()) {
			return fmt.Errorf("UFW 链路优先规则未生效；请检查同名应用规则或并发修改")
		}
	}
	// Old profile definitions are no longer referenced after a successful sync.
	return writeOwned(routeUFWProfilePath, routeUFWProfiles("", rules), 0644, "root")
}
