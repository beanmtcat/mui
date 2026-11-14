package shared

import "net/netip"

var pingCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// AllowedPingPublicIP reports whether ip is a routable public unicast address
// permitted as a latency-probe target (excluding loopback, RFC1918/ULA private,
// link-local, unspecified, multicast, zoned, and RFC6598 CGNAT addresses).
func AllowedPingPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !pingCGNAT.Contains(ip)
}
