package agent

import (
	"net/netip"
	"strconv"
	"strings"
)

type ufwStatusRule struct {
	action   string
	allowAll bool
	ports    []portProto
	// source is ufw's From column ("Anywhere", "10.0.0.0/8", "1.2.3.4"),
	// empty when the line does not show one.
	source string
}

// parseUFWStatusRule parses one `ufw status numbered` rule line, e.g.
// "[ 2] 8000:8010/tcp ALLOW IN Anywhere". An "Anywhere" port spec means
// the rule opens every port; a spec without "/proto" is treated as both
// TCP and UDP, matching ufw's own display.
func parseUFWStatusRule(line string) (ufwStatusRule, bool) {
	close := strings.Index(line, "]")
	if close < 0 {
		return ufwStatusRule{}, false
	}
	fields := strings.Fields(line[close+1:])
	if len(fields) < 2 {
		return ufwStatusRule{}, false
	}
	rule := ufwStatusRule{}
	for i, field := range fields[1:] {
		if field == "ALLOW" || field == "DENY" {
			rule.action = field
			rest := fields[i+2:]
			if len(rest) > 0 && (rest[0] == "IN" || rest[0] == "OUT" || rest[0] == "FWD") {
				rest = rest[1:]
			}
			if len(rest) > 0 && !strings.HasPrefix(rest[0], "#") {
				rule.source = rest[0]
			}
			break
		}
	}
	if rule.action == "" {
		return ufwStatusRule{}, false
	}
	spec := fields[0]
	if spec == "Anywhere" {
		rule.allowAll = true
		return rule, true
	}
	proto := ""
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}
	protos := []string{"tcp", "udp"}
	if proto == "tcp" || proto == "udp" {
		protos = []string{proto}
	}
	from, to := 0, 0
	if i := strings.Index(spec, ":"); i >= 0 {
		var err error
		from, err = strconv.Atoi(spec[:i])
		if err != nil {
			return ufwStatusRule{}, false
		}
		to, err = strconv.Atoi(spec[i+1:])
		if err != nil {
			return ufwStatusRule{}, false
		}
	} else {
		port, err := strconv.Atoi(spec)
		if err != nil {
			return ufwStatusRule{}, false
		}
		from, to = port, port
	}
	if from < 1 || to < from || to > 65535 {
		return ufwStatusRule{}, false
	}
	for port := from; port <= to; port++ {
		for _, p := range protos {
			rule.ports = append(rule.ports, portProto{port, p})
		}
	}
	return rule, true
}

// localUFWSource reports whether a ufw From value only covers loopback,
// link-local or private (RFC 1918 / ULA) addresses, such as a Docker bridge
// subnet. Traffic from those ranges cannot arrive from the public internet,
// so an allow limited to them does not bypass the panel's public-facing
// deny or restricted-source rules.
func localUFWSource(source string) bool {
	prefix, err := netip.ParsePrefix(source)
	if err != nil {
		addr, addrErr := netip.ParseAddr(source)
		if addrErr != nil {
			return false
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr := prefix.Masked().Addr()
	if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsPrivate() {
		return false
	}
	// The prefix must not be broader than the local range its first address
	// sits in, e.g. 10.0.0.0/7 also covers public 11.0.0.0/8.
	for _, local := range localUFWRanges {
		if local.Contains(addr) {
			return prefix.Bits() >= local.Bits()
		}
	}
	return false
}

var localUFWRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}
