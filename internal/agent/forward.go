package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"mui/internal/forward"
	"mui/internal/shared"
)

// forwardStatsFailures counts failed stats writes (marshal, write or rename)
// since the process started.
var forwardStatsFailures atomic.Uint64

// ForwardStatsFailures reports how many forward stats writes have failed.
func ForwardStatsFailures() uint64 { return forwardStatsFailures.Load() }

// readForwardRules loads the rule file and returns it with the digest the
// helper waits to see in the ready file. The file is capped at 1 MiB and
// every rule is validated before the forwarder starts: a bad rule file must
// fail fast here, not after listeners are bound.
func readForwardRules() ([]shared.ForwardRule, string, error) {
	f, err := os.Open(ForwardConfig)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > 1<<20 {
		return nil, "", fmt.Errorf("forward rules file exceeds 1 MiB")
	}
	var rules []shared.ForwardRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, "", err
	}
	for i := range rules {
		if err := validateForwardRule(rules[i]); err != nil {
			return nil, "", fmt.Errorf("forward rule %d (%q): %w", i, rules[i].ID, err)
		}
	}
	digest := sha256.Sum256(raw)
	return rules, hex.EncodeToString(digest[:]), nil
}

var blockedTargetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.100.0.0/8"),
}

// validateForwardRule checks one rule the way the panel is supposed to: ports
// in range, network tcp/udp only, a non-empty target, and a literal target
// that is not loopback, private, link-local, multicast, unspecified or in a
// blocked range. A domain target passes here; the forwarding process checks
// it again when it resolves.
func validateForwardRule(rule shared.ForwardRule) error {
	if rule.Port < 1 || rule.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", rule.Port)
	}
	if rule.TargetPort < 1 || rule.TargetPort > 65535 {
		return fmt.Errorf("target port %d out of range 1-65535", rule.TargetPort)
	}
	if rule.Network != "tcp" && rule.Network != "udp" {
		return fmt.Errorf("network %q must be tcp or udp", rule.Network)
	}
	if strings.TrimSpace(rule.TargetHost) == "" {
		return errors.New("target host must not be empty")
	}
	if addr, err := netip.ParseAddr(rule.TargetHost); err == nil {
		// Unmap first: an IPv4-mapped IPv6 address such as ::ffff:127.0.0.1
		// must be judged as the IPv4 address it really is.
		addr = addr.Unmap()
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("target address %s is private, loopback, link-local, multicast or unspecified", rule.TargetHost)
		}
		for _, prefix := range blockedTargetPrefixes {
			if prefix.Contains(addr) {
				return fmt.Errorf("target address %s is in blocked range %s", rule.TargetHost, prefix)
			}
		}
		return nil
	}
	// Not a literal address: it must be a host name, not a numeric shorthand
	// such as "127.1" or "2130706433" (which the resolver would treat as a
	// literal address) and not contain characters a host name cannot have.
	if isNumericShorthand(rule.TargetHost) {
		return fmt.Errorf("target host %q looks like a numeric IP address; use dotted-quad notation", rule.TargetHost)
	}
	if strings.ContainsAny(rule.TargetHost, " /\\:[]@") {
		return fmt.Errorf("target host %q is not a valid host name", rule.TargetHost)
	}
	return nil
}

// isNumericShorthand reports whether s is all digits (optionally dotted),
// which parsers treat as a numeric address rather than a host name.
func isNumericShorthand(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func RunForward(ctx context.Context) error {
	rules, digest, err := readForwardRules()
	if err != nil {
		return err
	}
	service, err := forward.Start(rules)
	if err != nil {
		return err
	}
	defer service.Close()
	// Begin receiving reload signals before publishing readiness; the helper may
	// send SIGHUP as soon as it sees the ready file.
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)
	defer signal.Stop(hangup)
	if err := writeForwardReady(digest); err != nil {
		return err
	}
	defer os.Remove(ForwardReady)
	// SIGHUP applies a changed rule file in place: rules that did not change keep
	// their listeners and connections. The ready file is only rewritten after a
	// reload that fully succeeded, which is how the helper learns the outcome.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hangup:
			}
			rules, digest, err := readForwardRules()
			if err == nil {
				err = service.Reload(rules)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "reload:", err)
				continue
			}
			if err := writeForwardReady(digest); err != nil {
				fmt.Fprintln(os.Stderr, "ready:", err)
			}
		}
	}()
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return err
	}
	instanceID := hex.EncodeToString(instance[:])
	var lastSnapshot map[string]forward.Counter
	firstStats := true
	writeStats := func() {
		snapshot := service.Snapshot()
		if !firstStats && snapshotsEqual(lastSnapshot, snapshot) {
			return
		}
		points := make([]shared.ForwardTrafficPoint, 0, len(snapshot))
		now := time.Now()
		for id, count := range snapshot {
			points = append(points, shared.ForwardTrafficPoint{ForwardID: id, InstanceID: instanceID, Uplink: count.Uplink, Downlink: count.Downlink, UpdatedAt: now})
		}
		sort.Slice(points, func(i, j int) bool { return points[i].ForwardID < points[j].ForwardID })
		raw, err := json.Marshal(points)
		if err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
		if err = os.WriteFile(ForwardStats+".tmp", raw, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
		if err = os.Rename(ForwardStats+".tmp", ForwardStats); err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
		lastSnapshot = snapshot
		firstStats = false
	}
	writeStats()
	statsCtx, stopStats := context.WithCancel(ctx)
	statsDone := make(chan struct{})
	defer func() { stopStats(); <-statsDone; _ = os.Remove(ForwardStats) }()
	go func() {
		defer close(statsDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-statsCtx.Done():
				writeStats()
				return
			case <-ticker.C:
				writeStats()
			}
		}
	}()
	return service.Run(ctx)
}

// writeForwardReady publishes the rules digest atomically (tmp + rename) so
// the helper never observes a half-written ready file.
func writeForwardReady(digest string) error {
	tmp := ForwardReady + ".tmp"
	if err := os.WriteFile(tmp, []byte(digest), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ForwardReady)
}

func snapshotsEqual(a, b map[string]forward.Counter) bool {
	if len(a) != len(b) {
		return false
	}
	for id, av := range a {
		bv, ok := b[id]
		if !ok || av != bv {
			return false
		}
	}
	return true
}
