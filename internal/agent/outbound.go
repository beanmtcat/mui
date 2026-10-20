package agent

import (
	"fmt"
	"net"

	"mui/internal/shared"
)

// Run before changing any services, certificates, firewall rules or proxy.
// Device binding stays in sing-box: Agent traffic and forwards are untouched.
func checkOutboundInterfaces(state shared.DesiredState) error {
	for _, name := range shared.OutboundInterfaces(state.Nodes, state.OutboundInterface) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("出口网卡 %q 不存在或不可读取：%w；未应用配置", name, err)
		}
		if iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("出口网卡 %q 未启用；未应用配置", name)
		}
	}
	return nil
}
