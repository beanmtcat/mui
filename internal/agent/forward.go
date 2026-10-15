package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sort"
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

// validateForwardRule shares the panel's structural validation and the
// forwarder's target policy. Private destinations are valid; loopback,
// link-local, multicast, unspecified and metadata addresses are refused.
func validateForwardRule(rule shared.ForwardRule) error {
	if err := shared.ValidateForward(rule); err != nil {
		return err
	}
	if addr, err := netip.ParseAddr(rule.TargetHost); err == nil {
		if forward.ForbiddenTarget(addr) {
			return fmt.Errorf("target address %s is loopback, link-local, multicast, unspecified or metadata", rule.TargetHost)
		}
		return nil
	}
	// Not a literal address: it must be a host name, not a numeric shorthand
	// such as "127.1" or "2130706433" (which the resolver would treat as a
	// literal address) and not contain characters a host name cannot have.
	if isNumericShorthand(rule.TargetHost) {
		return fmt.Errorf("target host %q looks like a numeric IP address; use dotted-quad notation", rule.TargetHost)
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
	statsCtx, stopStats := context.WithCancel(ctx)
	statsDone := make(chan struct{})
	defer func() { stopStats(); <-statsDone; _ = os.Remove(ForwardStats) }()
	go func() {
		defer close(statsDone)
		runForwardStats(statsCtx, ForwardStats, instanceID, service.Snapshot, 5*time.Second)
	}()
	return service.Run(ctx)
}

// Publish even unchanged counters: UpdatedAt is the forwarder's heartbeat,
// not the time of its last byte. The helper must still report idle counters
// after the panel reconnects, until the process stops.
func runForwardStats(ctx context.Context, path, instanceID string, snapshot func() map[string]forward.Counter, interval time.Duration) {
	writeStats := func() {
		counts := snapshot()
		points := make([]shared.ForwardTrafficPoint, 0, len(counts))
		now := time.Now()
		for id, count := range counts {
			points = append(points, shared.ForwardTrafficPoint{ForwardID: id, InstanceID: instanceID, Uplink: count.Uplink, Downlink: count.Downlink, UpdatedAt: now})
		}
		sort.Slice(points, func(i, j int) bool { return points[i].ForwardID < points[j].ForwardID })
		raw, err := json.Marshal(points)
		if err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
		if err = os.WriteFile(path+".tmp", raw, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
		if err = os.Rename(path+".tmp", path); err != nil {
			fmt.Fprintln(os.Stderr, "forward stats:", err)
			forwardStatsFailures.Add(1)
			return
		}
	}
	writeStats()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			writeStats()
			return
		case <-ticker.C:
			writeStats()
		}
	}
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
