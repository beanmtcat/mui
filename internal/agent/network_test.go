package agent

import "testing"

func TestNetworkProcParsing(t *testing.T) {
	route := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 01010101 0003 0 0 0 00000000 0 0 0\n"
	if got := defaultInterface(route); got != "eth0" {
		t.Fatalf("interface: %q", got)
	}
	v6route := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 eth1\n"
	if got := defaultIPv6Interface(v6route); got != "eth1" {
		t.Fatalf("IPv6 interface: %q", got)
	}
	dev := "Inter-| Receive | Transmit\n eth0: 123 0 0 0 0 0 0 0 456 0 0 0 0 0 0 0\n"
	rx, tx, err := parseInterfaceBytes(dev, "eth0")
	if err != nil || rx != 123 || tx != 456 {
		t.Fatalf("counters: %d %d %v", rx, tx, err)
	}
}
