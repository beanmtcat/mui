package shared

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Linux interface names are at most IFNAMSIZ-1 bytes. Reject shell/path syntax
// as these names are administrative settings, never commands or addresses.
func ValidateOutboundInterface(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 15 || name == "." || name == ".." {
		return fmt.Errorf("出口网卡名称无效：最多 15 字节，例如 ppp0、eth0")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
			return fmt.Errorf("出口网卡名称只能包含字母、数字、下划线、点和短横线")
		}
	}
	return nil
}

func ValidateNodeOutbound(n Node) error {
	switch n.OutboundMode {
	case "", "inherit", "system":
		if n.OutboundInterface != "" {
			return fmt.Errorf("仅指定网卡模式可以填写出口网卡")
		}
	case "interface":
		if n.OutboundInterface == "" {
			return fmt.Errorf("请填写节点出口网卡，例如 ppp0")
		}
		return ValidateOutboundInterface(n.OutboundInterface)
	default:
		return fmt.Errorf("节点出口模式无效")
	}
	return nil
}

const MaxBlockedDomains = 512

var blockedDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// The tokens of a pasted sing-box rule that are not part of its domain list.
var blockedDomainRuleWords = []string{":", "action", "sniff", "domain_suffix", "reject", "method", "drop"}

// NormalizeBlockedDomains accepts pasted lists, including whole sing-box rules,
// and returns lowercase unique suffixes in their original order.
func NormalizeBlockedDomains(items []string) ([]string, error) {
	var out []string
	for _, item := range items {
		for _, raw := range strings.FieldsFunc(item, func(r rune) bool { return strings.ContainsRune(" \t\r\n,;\"'[]{}", r) }) {
			if slices.Contains(blockedDomainRuleWords, strings.ToLower(raw)) {
				continue
			}
			domain := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(raw), "*"), ".")
			labels := strings.Split(domain, ".")
			if net.ParseIP(domain) != nil {
				return nil, fmt.Errorf("拦截域名 %q 是 IP，这里只支持域名", raw)
			}
			if len(domain) > 253 {
				return nil, fmt.Errorf("拦截域名 %q 无效", raw)
			}
			for _, label := range labels {
				if !blockedDomainLabel.MatchString(label) {
					return nil, fmt.Errorf("拦截域名 %q 无效；中文域名请填写 xn-- 形式", raw)
				}
			}
			if !slices.Contains(out, domain) {
				out = append(out, domain)
			}
		}
	}
	if len(out) > MaxBlockedDomains {
		return nil, fmt.Errorf("拦截域名最多 %d 个", MaxBlockedDomains)
	}
	return out, nil
}

// DomainBlocked reports whether host matches a suffix in a normalized list.
func DomainBlocked(blocked []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return slices.ContainsFunc(blocked, func(domain string) bool {
		return host == domain || strings.HasSuffix(host, "."+domain)
	})
}

func EffectiveOutboundInterface(n Node, serverDefault string) string {
	switch n.OutboundMode {
	case "system":
		return ""
	case "interface":
		return n.OutboundInterface
	default:
		return serverDefault
	}
}

// Include the default even when all nodes override it: the generated default
// outbound must also refer to an existing device. Disabled overrides are inert.
func OutboundInterfaces(nodes []ManagedNode, serverDefault string) []string {
	seen := map[string]bool{}
	if serverDefault != "" {
		seen[serverDefault] = true
	}
	for _, item := range nodes {
		if item.Node.Enabled {
			if name := EffectiveOutboundInterface(item.Node, serverDefault); name != "" {
				seen[name] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
