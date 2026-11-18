package forward

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mui/internal/shared"
)

// rule is one running forward: a listener, its destinations and whatever is
// currently connected through it.
type rule struct {
	relayMu      sync.RWMutex // Serialises a rule-wide override change with candidate reads.
	svc          *Service
	spec         shared.ForwardRule
	stats        *counter
	targets      []*target
	next         atomic.Uint32 // round-robin position
	nextTrial    atomic.Uint32
	quality      *relayQualityGroup
	listener     io.Closer
	done         chan struct{}
	stopOnce     sync.Once
	cancelLookup context.CancelFunc

	mu        sync.Mutex
	pairs     map[*tcpPair]struct{}
	sessions  map[netip.AddrPort]*udpSession
	perSource map[netip.Addr]int
	count     int
}

// stop closes the listener and everything connected through the rule. It does
// not wait: the port is free as soon as the listener is closed.
func (r *rule) stop() {
	r.stopOnce.Do(func() {
		close(r.done)
		if r.cancelLookup != nil {
			r.cancelLookup()
		}
		_ = r.listener.Close()
		r.mu.Lock()
		for pair := range r.pairs {
			pair.close()
		}
		for _, session := range r.sessions {
			_ = session.conn.Close()
		}
		r.mu.Unlock()
	})
}

func (r *rule) stopped() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// admit reserves a slot for a new connection or session from src, or refuses.
func (r *rule) admit(src netip.Addr, total *atomic.Int64, maxTotal int64, maxRule, maxSource int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count >= maxRule || r.perSource[src] >= maxSource {
		return false
	}
	if total.Add(1) > maxTotal {
		total.Add(-1)
		return false
	}
	r.count++
	r.perSource[src]++
	return true
}

func (r *rule) release(src netip.Addr, total *atomic.Int64) {
	r.mu.Lock()
	r.count--
	if r.perSource[src]--; r.perSource[src] <= 0 {
		delete(r.perSource, src)
	}
	r.mu.Unlock()
	total.Add(-1)
}

// allowedSource is the second line of defence for a rule's source check: the
// host firewall is the first. FirewallSources is one string holding IP
// addresses and CIDRs separated by commas, semicolons or whitespace, the
// same format shared.NormalizeFirewallAccess accepts.
func (r *rule) allowedSource(src netip.Addr) bool {
	switch r.spec.FirewallPolicy {
	case "all", "":
		return true
	case "manual":
		// The administrator's manually configured host firewall is
		// responsible for source filtering; this process admits all.
		return true
	case "restricted":
		// Fail closed: an empty source list admits nobody.
		for _, entry := range strings.FieldsFunc(r.spec.FirewallSources, func(c rune) bool {
			return c == ',' || c == ';' || c == '\n' || c == '\r' || c == ' ' || c == '\t'
		}) {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			if strings.Contains(entry, "/") {
				prefix, err := netip.ParsePrefix(entry)
				if err != nil {
					continue
				}
				if prefix.Contains(src) || prefix.Contains(src.Unmap()) {
					return true
				}
				continue
			}
			if addr, err := netip.ParseAddr(entry); err == nil {
				if addr.Unmap() == src.Unmap() {
					return true
				}
			}
		}
		return false
	default:
		// Unknown policy: fail closed rather than admitting by accident.
		return false
	}
}

// followTargets keeps host-name destinations current and moves UDP sessions
// off addresses a name no longer resolves to.
func (r *rule) followTargets(parent context.Context) {
	defer r.svc.wg.Done()
	ticker := time.NewTicker(resolveInterval)
	defer ticker.Stop()
	for {
		changed := false
		for _, t := range r.targets {
			if t.static {
				continue
			}
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			changed = t.refresh(ctx) || changed
			cancel()
		}
		if changed {
			r.dropSessions(func(session *udpSession) bool { return !session.target.current(session.remote) })
		}
		select {
		case <-r.done:
			return
		case <-ticker.C:
		}
	}
}

// checkHealth probes rules that explicitly support a TCP health endpoint.
// Plain UDP destinations use passive socket errors instead of TCP probes. A destination goes down after healthStreak failed probes in a row
// (or at once, when a client connection to it fails) and comes back after
// healthStreak successful ones. UDP sessions then follow: off a destination
// that went down and, in failover mode, back to a recovered preferred one.
// retryPreferred is the passive failover's way back: once a preferred
// destination's cooldown ends, sessions on a backup move back to it. It runs on
// a timer, not per datagram, because rebalancing walks every session.
func (r *rule) retryPreferred() {
	defer r.svc.wg.Done()
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.rebalanceSessions()
		}
	}
}

func (r *rule) checkHealth(parent context.Context) {
	defer r.svc.wg.Done()
	interval := healthInterval
	if len(r.targets) == 1 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
		}
		if r.quality != nil && !r.quality.beginProbe(time.Now()) {
			r.rebalanceSessions()
			continue
		}
		results := make([]probeResult, len(r.targets))
		var wg sync.WaitGroup
		for i, t := range r.targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(parent, healthTimeout)
				defer cancel()
				results[i] = r.svc.probe(ctx, t)
			}()
		}
		wg.Wait()
		if parent.Err() != nil {
			return
		}
		if r.quality != nil {
			r.quality.observeProbes(results, time.Now())
			r.rebalanceSessions()
			continue
		}
		var changed bool
		for i, result := range results {
			if r.targets[i].observe(result.ok) {
				_, manual := r.targets[i].relayStatus(time.Now())
				changed = changed || !manual
			}
		}
		if changed {
			r.rebalanceSessions()
		}
	}
}

// rebalanceSessions closes UDP sessions that should no longer use their
// destination; the client's next datagram opens one on the right destination.
func (r *rule) rebalanceSessions() {
	if r.spec.Network != "udp" {
		return
	}
	candidates := r.relayCandidates(false)
	var preferred *target
	if len(candidates) > 0 {
		preferred = candidates[0]
	}
	r.dropSessions(func(session *udpSession) bool {
		state, manual := session.target.relayStatus(time.Now())
		if state == shared.RelayDown {
			return manual || preferred != nil && preferred.effectiveUsable()
		}
		return r.quality == nil && !manual && state == shared.RelayNormal && preferred != nil && r.spec.Balance != "round-robin" && session.target != preferred && preferred.effectiveUsable()
	})
}

func (r *rule) dropSessions(stale func(*udpSession) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, session := range r.sessions {
		if stale(session) {
			// Drop the mapping as well as the connection: the client's next
			// datagram must open a fresh session instead of reusing this
			// one. The session's reply loop releases its admit slot when the
			// close ends its read.
			delete(r.sessions, key)
			_ = session.conn.Close()
		}
	}
}

func (r *rule) failedTarget(t *target) {
	if len(r.targets) < 2 && r.spec.RouteID == "" || r.stopped() {
		return
	}
	cooldown := time.Duration(0)
	if !tcpHealth(r.spec) {
		cooldown = 2 * healthInterval
	}
	if t.markDownFor(cooldown) {
		state, manual := t.relayStatus(time.Now())
		if state != shared.RelayDown || manual {
			return
		}
		r.rebalanceSessions()
	}
}
