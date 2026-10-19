package shared

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// UFWLine is one rule line of `ufw status numbered`, for example
// "[ 2] 8000:8010/tcp ALLOW IN 203.0.113.0/24 # mui-abc".
type UFWLine struct {
	Index int
	// Rule is the line without its number: what identifies it across
	// renumbering.
	Rule string
	// Tag is the comment of a rule the panel wrote ("mui-..." or the legacy
	// "panel-..."); empty for rules added on the host by other means.
	Tag    string
	Action string // ALLOW, DENY, REJECT or LIMIT
	// AllPorts is a rule without a port ("Anywhere ALLOW IN 10.0.0.0/8").
	AllPorts         bool
	PortFrom, PortTo int
	// Protos is tcp and/or udp; a port without "/proto" covers both.
	Protos []string
	// App is set for application profiles ("OpenSSH"), whose ports UFW
	// resolves itself.
	App string
	// Source is "Anywhere" or what follows the direction, such as a CIDR.
	Source string
	// V6 marks the IPv6 line UFW lists separately for the same rule.
	V6 bool
}

// ParseUFWLine parses one numbered rule line. It reports false for anything
// else, including headers.
func ParseUFWLine(line string) (UFWLine, bool) {
	line = strings.TrimSpace(line)
	closing := strings.Index(line, "]")
	if !strings.HasPrefix(line, "[") || closing < 0 {
		return UFWLine{}, false
	}
	index, err := strconv.Atoi(strings.TrimSpace(line[1:closing]))
	if err != nil {
		return UFWLine{}, false
	}
	out := UFWLine{Index: index, Rule: strings.TrimSpace(line[closing+1:])}
	out.V6 = strings.Contains(out.Rule, "(v6)")
	body := out.Rule
	if i := strings.Index(body, "#"); i >= 0 {
		comment := strings.TrimSpace(body[i+1:])
		if strings.HasPrefix(comment, "mui-") || strings.HasPrefix(comment, "panel-") {
			out.Tag = comment
		}
		body = body[:i]
	}
	fields := strings.Fields(body)
	actionAt := -1
	for i, f := range fields {
		if f == "ALLOW" || f == "DENY" || f == "REJECT" || f == "LIMIT" {
			out.Action, actionAt = f, i
			break
		}
	}
	if actionAt < 1 {
		return UFWLine{}, false
	}
	rest := fields[actionAt+1:]
	if len(rest) > 0 && (rest[0] == "IN" || rest[0] == "OUT" || rest[0] == "FWD") {
		rest = rest[1:]
	}
	out.Source = strings.TrimSpace(strings.ReplaceAll(strings.Join(rest, " "), "(v6)", ""))
	spec := fields[0]
	switch {
	case spec == "Anywhere":
		out.AllPorts = true
		return out, true
	case spec[0] < '0' || spec[0] > '9':
		out.App = strings.Join(fields[:actionAt], " ")
		return out, true
	}
	out.Protos = []string{"tcp", "udp"}
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		switch proto := strings.ToLower(spec[i+1:]); proto {
		case "tcp", "udp":
			out.Protos = []string{proto}
		default:
			return UFWLine{}, false
		}
		spec = spec[:i]
	}
	from, to, found := strings.Cut(spec, ":")
	if !found {
		to = from
	}
	if out.PortFrom, err = strconv.Atoi(from); err != nil {
		return UFWLine{}, false
	}
	if out.PortTo, err = strconv.Atoi(to); err != nil {
		return UFWLine{}, false
	}
	if out.PortFrom < 1 || out.PortTo < out.PortFrom || out.PortTo > 65535 {
		return UFWLine{}, false
	}
	return out, true
}

// UFWRuleKey identifies one listed rule regardless of column padding. UFW
// lists a rule added for both families as two lines; the IPv6 one carries
// "(v6)" and has its own key, so it is removed on its own.
func UFWRuleKey(rule string) string {
	return strings.Join(strings.Fields(rule), " ")
}

// AdmitsSSH reports whether an allowing rule lets traffic reach one of the
// given SSH ports. Application profiles are assumed to, since their ports
// are not visible here.
func (l UFWLine) AdmitsSSH(sshPorts []int) bool {
	if l.Action != "ALLOW" && l.Action != "LIMIT" {
		return false
	}
	if l.AllPorts || l.App != "" {
		return true
	}
	if !slices.Contains(l.Protos, "tcp") {
		return false
	}
	for _, port := range sshPorts {
		if port >= l.PortFrom && port <= l.PortTo {
			return true
		}
	}
	return false
}

// CustomRule turns a host rule into the custom rule the panel would write for
// it, or reports false when a custom rule cannot express it: no port, both
// protocols, an application profile, REJECT/LIMIT, or an unusual source.
func (l UFWLine) CustomRule() (FirewallRule, bool) {
	if l.AllPorts || l.App != "" || len(l.Protos) != 1 || (l.Action != "ALLOW" && l.Action != "DENY") || strings.ContainsAny(l.Source, " \t") {
		return FirewallRule{}, false
	}
	rule := FirewallRule{PortFrom: l.PortFrom, PortTo: l.PortTo, Network: l.Protos[0], Action: strings.ToLower(l.Action), Family: "ipv4"}
	if l.V6 {
		rule.Family = "ipv6"
	}
	if l.Source != "Anywhere" {
		rule.Source = l.Source
	}
	return rule, true
}

// RuleFamilyError checks a custom rule's address family against its source.
func RuleFamilyError(r FirewallRule) error {
	switch r.Family {
	case "", "ipv4", "ipv6":
	default:
		return fmt.Errorf("地址族只能是 IPv4、IPv6 或两者")
	}
	if r.Source == "" || r.Family == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(r.Source)
	if err != nil {
		return nil // The source check reports it.
	}
	if prefix.Addr().Is4() != (r.Family == "ipv4") {
		return fmt.Errorf("来源 %s 与所选地址族不一致", r.Source)
	}
	return nil
}

// HostRuleError says why the panel must not remove a host rule, or "".
func HostRuleError(l UFWLine, sshPorts []int) string {
	switch {
	case l.Tag != "":
		return "该规则由面板生成，请在对应的节点、转发或自定义规则中修改"
	case l.AdmitsSSH(sshPorts):
		return "该规则可能放行 SSH 端口，为防止失联不能在面板删除或修改；请登录服务器手动调整"
	}
	return ""
}

// UncoveredSSHPorts lists the SSH ports no allowing rule in `ufw status
// numbered` output lets in over TCP, from any source. A rule restricted to
// some sources counts as covering: the administrator chose who may connect,
// and opening the port wider would undo that. An application profile counts
// only for port 22 and only when it is an SSH profile, since its real ports
// are not visible here.
func UncoveredSSHPorts(status string, sshPorts []int) []int {
	var out []int
	for _, port := range sshPorts {
		covered := false
		for _, raw := range strings.Split(status, "\n") {
			l, ok := ParseUFWLine(raw)
			if !ok || (l.Action != "ALLOW" && l.Action != "LIMIT") {
				continue
			}
			switch {
			case l.AllPorts:
				covered = true
			case l.App != "":
				covered = port == 22 && strings.Contains(strings.ToUpper(l.App), "SSH")
			default:
				covered = slices.Contains(l.Protos, "tcp") && port >= l.PortFrom && port <= l.PortTo
			}
			if covered {
				break
			}
		}
		if !covered {
			out = append(out, port)
		}
	}
	slices.Sort(out)
	return out
}
