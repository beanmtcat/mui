package shared

import (
	"net/netip"
	"testing"
)

func TestAllowedPingPublicIP(t *testing.T) {
	if AllowedPingPublicIP(netip.Addr{}) {
		t.Fatal("zero netip.Addr must be rejected")
	}

	cases := []struct {
		addr string
		want bool
	}{
		// Public IPv4 & IPv6 (merged from server & agent monitor tests)
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"93.184.216.34", true},
		{"2606:4700:4700::1111", true},
		{"::ffff:1.1.1.1", true},
		{"100.63.255.255", true},
		{"100.128.0.0", true},

		// Loopback, unspecified, broadcast, multicast
		{"127.0.0.1", false},
		{"::1", false},
		{"::ffff:127.0.0.1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"255.255.255.255", false},
		{"224.0.0.1", false},
		{"ff02::1", false},

		// Private RFC1918 & IPv6 ULA
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.254", false},
		{"192.168.1.1", false},
		{"192.168.1.10", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"::ffff:10.0.0.1", false},

		// Link-local & cloud metadata
		{"169.254.169.254", false},
		{"fe80::1", false},

		// RFC6598 CGNAT (100.64.0.0/10)
		{"100.64.0.0", false},
		{"100.64.0.1", false},
		{"100.127.255.255", false},
		{"::ffff:100.64.0.1", false},

		// Zoned address
		{"2606:4700:4700::1111%eth0", false},
	}

	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.addr)
		if got := AllowedPingPublicIP(ip); got != tc.want {
			t.Fatalf("AllowedPingPublicIP(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
