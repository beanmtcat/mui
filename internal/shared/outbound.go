package shared

import (
	"fmt"
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
