package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- destination

// target is where a rule sends traffic. A literal address never changes. A host
// name is resolved in the background, so that neither a new connection nor a
// datagram ever waits for DNS, and a changed record is picked up within
// resolveInterval.
type target struct {
	host   string
	port   int
	static bool
	// illegal marks a literal target that rejectPrivateAddr refused.
	// startRule rejects the rule instead of letting it start.
	illegal bool

	// Health, used only when a rule has several targets. A target starts up.
	healthMu sync.Mutex
	down     bool
	streak   int       // consecutive probe results contradicting the current state
	retryAt  time.Time // passive checks retry after a bounded cooldown

	mu sync.RWMutex
	// latest is the most recent answer, in resolver order. previous is the one
	// before: an address counts as current while it is in either, which keeps
	// names that rotate between several records from looking like a move.
	latest, previous []netip.Addr
}

func (t *target) up() bool {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	if t.down && !t.retryAt.IsZero() && !time.Now().Before(t.retryAt) {
		t.down, t.streak, t.retryAt = false, 0, time.Time{}
	}
	return !t.down
}

// observe records one probe result and reports whether the state changed.
func (t *target) observe(ok bool) bool {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	if ok != t.down {
		t.streak = 0 // The probe agrees with the current state.
		return false
	}
	if t.streak++; t.streak < healthStreak {
		return false
	}
	t.down, t.streak = !ok, 0
	return true
}

// markDown takes a target out of use after a failed client connection and
// reports whether it was up.
func (t *target) markDown() bool { return t.markDownFor(0) }

func (t *target) markDownFor(cooldown time.Duration) bool {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	was := !t.down
	t.down, t.streak = true, 0
	if cooldown > 0 {
		t.retryAt = time.Now().Add(cooldown)
	} else {
		t.retryAt = time.Time{}
	}
	return was
}

func newTarget(host string, port int) *target {
	t := &target{host: host, port: port}
	var addr netip.Addr
	var ok bool
	if parsed, err := netip.ParseAddr(host); err == nil {
		addr, ok = parsed.Unmap(), true
	} else if parsed, ok2 := parseNumericIP(host); ok2 {
		// A numeric shorthand such as 127.1 or 2130706433 is a literal
		// address too, not a host name to look up.
		addr, ok = parsed, true
	}
	if ok {
		t.static = true
		t.latest = []netip.Addr{addr}
		if rejectPrivateAddr(addr) {
			t.illegal = true
		}
	}
	return t
}

// rejectPrivateAddr reports whether addr is an address a forward must never
// send traffic to: loopback, unspecified, link-local, multicast, or a cloud
// metadata service. Those reach this host itself or its instance credentials,
// which a public port must not expose. Private (RFC 1918, ULA) and CGNAT
// ranges are allowed: relaying into a private network is a normal use.
func rejectPrivateAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	// Unmap first: an IPv4-mapped IPv6 address such as ::ffff:127.0.0.1
	// must be judged as the IPv4 address it really is.
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, metadata := range metadataAddrs {
		if addr == metadata {
			return true
		}
	}
	return false
}

// ForbiddenTarget is rejectPrivateAddr for the panel, so that it refuses the
// same destinations up front instead of letting the agent's apply fail.
func ForbiddenTarget(addr netip.Addr) bool { return rejectPrivateAddr(addr) }

// Instance metadata services outside the link-local range: Alibaba Cloud and
// the AWS IPv6 endpoint. 169.254.169.254 is link-local and already refused.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("fd00:ec2::254"),
}

// parseNumericIP parses an IPv4 address written the way inet_aton does: one
// to four numeric parts, each decimal unless it starts with 0x (hexadecimal)
// or a leading 0 (octal). Missing parts are filled from the right: "127.1"
// is 127.0.0.1 and "2130706433" is 127.0.0.1. It returns false for anything
// that is not such a numeric form, including ordinary host names.
func parseNumericIP(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := parseNumericPart(part)
		if !ok {
			return netip.Addr{}, false
		}
		nums[i] = n
	}
	var ip uint32
	switch len(nums) {
	case 1:
		if nums[0] > 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(nums[0])
	case 2:
		if nums[0] > 0xFF || nums[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])
	case 3:
		if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])<<16 | uint32(nums[2])
	case 4:
		for _, n := range nums {
			if n > 0xFF {
				return netip.Addr{}, false
			}
		}
		ip = uint32(nums[0])<<24 | uint32(nums[1])<<16 | uint32(nums[2])<<8 | uint32(nums[3])
	}
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

// parseNumericPart parses one inet_aton part: a 0x/0X prefix is hexadecimal,
// a leading 0 with more digits is octal, otherwise decimal.
func parseNumericPart(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	switch {
	case len(part) > 2 && (part[:2] == "0x" || part[:2] == "0X"):
		for _, c := range part[2:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return 0, false
			}
		}
		n, err := strconv.ParseUint(part[2:], 16, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	case len(part) > 1 && part[0] == '0':
		for _, c := range part {
			if c < '0' || c > '7' {
				return 0, false
			}
		}
		n, err := strconv.ParseUint(part, 8, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, false
			}
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
}

// isLocalAddr reports whether addr is assigned to one of this host's own
// network interfaces. If the interface list cannot be read, it reports
// false; the private-address rejection in startRule still covers the
// loopback and private cases.
func isLocalAddr(addr netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	want := addr.Unmap()
	for _, ifaceAddr := range addrs {
		var ip net.IP
		switch v := ifaceAddr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if parsed, ok := netip.AddrFromSlice(ip); ok && parsed.Unmap() == want {
			return true
		}
	}
	return false
}

// refresh looks the name up again. It reports false, and changes nothing, when
// the lookup fails, returns no address, or returns only addresses that
// rejectPrivateAddr refuses (a DNS answer that would turn the forward into
// an SSRF relay keeps the previous addresses instead).
func (t *target) refresh(ctx context.Context) bool {
	addrs, err := lookupNetIP(ctx, "ip", t.host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	kept := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		// TestAllowLoopbackTarget (set only by tests) lets a test DNS
		// answer point at loopback backends; production still drops it.
		if rejectPrivateAddr(addr) && !TestAllowLoopbackTarget {
			continue
		}
		kept = append(kept, addr)
	}
	if len(kept) == 0 {
		return false
	}
	t.mu.Lock()
	t.previous, t.latest = t.latest, kept
	t.mu.Unlock()
	return true
}

// snapshot returns a copy of the target's latest resolved addresses.
func (t *target) snapshot() []netip.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]netip.Addr(nil), t.latest...)
}

func (t *target) first() (netip.Addr, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.latest) == 0 {
		return netip.Addr{}, false
	}
	return t.latest[0], true
}

func (t *target) current(addr netip.Addr) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, list := range [][]netip.Addr{t.latest, t.previous} {
		for _, known := range list {
			if known == addr {
				return true
			}
		}
	}
	return false
}

// dialTCP connects to the first address that answers.
func (t *target) dialTCP(ctx context.Context) (*net.TCPConn, error) {
	t.mu.RLock()
	addrs := append([]netip.Addr(nil), t.latest...)
	t.mu.RUnlock()
	if len(addrs) == 0 {
		return nil, fmt.Errorf("destination %s has not resolved yet", t.host)
	}
	var lastErr error
	dialer := net.Dialer{}
	for i, addr := range addrs {
		attempt := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok && i < len(addrs)-1 {
			// Leave time for the remaining addresses.
			attempt, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addrs)-i))
		}
		conn, err := dialer.DialContext(attempt, "tcp", netip.AddrPortFrom(addr, uint16(t.port)).String())
		cancel()
		if err == nil {
			return conn.(*net.TCPConn), nil
		}
		lastErr = err
	}
	return nil, lastErr
}
