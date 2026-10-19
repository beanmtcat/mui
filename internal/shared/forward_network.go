package shared

const ForwardTCPUDP = "tcp+udp"

// ForwardNetworks lists the sockets owned by one logical forwarding rule.
// FirewallRule still accepts only a single concrete protocol.
func ForwardNetworks(network string) []string {
	switch network {
	case "tcp", "udp":
		return []string{network}
	case ForwardTCPUDP:
		return []string{"tcp", "udp"}
	default:
		return nil
	}
}

func ForwardNetworkIncludes(network, protocol string) bool {
	return (protocol == "tcp" || protocol == "udp") && (network == protocol || network == ForwardTCPUDP)
}

func ForwardNetworksOverlap(a, b string) bool {
	return ForwardNetworkIncludes(a, "tcp") && ForwardNetworkIncludes(b, "tcp") || ForwardNetworkIncludes(a, "udp") && ForwardNetworkIncludes(b, "udp")
}
