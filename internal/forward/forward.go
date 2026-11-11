// Package forward relays TCP connections and UDP datagrams from a local port to
// one of a rule's destinations. One Service runs every rule of a server and can
// be reloaded in place: rules that did not change keep their listeners and
// connections. A rule with several destinations checks their health and sends
// new connections only to healthy ones.
package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"mui/internal/shared"
)

// Every limit is a hard bound on memory and file descriptors. A rule has its
// own budget so that one flooded port cannot starve the others; the totals
// bound the process as a whole.
const (
	maxTCPPerRule   = 4096
	maxTCPTotal     = 8192
	maxTCPPerSource = 2048
	maxUDPPerRule   = 2048
	maxUDPTotal     = 4096
	maxUDPPerSource = 1024

	// copyChunk is the most one relay step moves before the byte counters and the
	// activity time are updated.
	copyChunk = 1 << 20
	// A UDP session starts with a buffer that fits any ordinary datagram and only
	// grows to the protocol maximum once a larger one is actually seen.
	smallDatagram = 2048
	maxDatagram   = 65535
)

// Variables rather than constants so that tests can shorten them.
var (
	// A TCP connection that moved no data in either direction for this long is
	// closed; without it, connections that are opened and left alone would hold
	// their slots forever.
	tcpIdleTimeout = time.Hour
	udpIdleTimeout = 2 * time.Minute
	sweepInterval  = 30 * time.Second
	// How often a quiet TCP relay stops waiting to publish what it has moved.
	relayTick = 10 * time.Second
	// How often a destination given as a host name is looked up again.
	resolveInterval = 30 * time.Second
	lookupNetIP     = net.DefaultResolver.LookupNetIP
	// How often each destination of a multi-destination rule is probed, and
	// how many probes in a row it takes to mark it down or up again.
	healthInterval = 5 * time.Second
	healthTimeout  = 3 * time.Second
	healthStreak   = 2
)

// TestAllowLoopbackTarget is a test-only escape hatch for the SSRF guards
// in startRule and refresh: the forward tests run their backends on
// loopback, which production must refuse. It is false by default and is
// set only by _test.go files; production code never enables it.
var TestAllowLoopbackTarget = false

type Counter struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

type counter struct{ up, down atomic.Int64 }

type Service struct {
	clients clientObservations
	mu      sync.Mutex
	rules   map[string]*rule
	// Counters outlive their rule: a rule that is disabled and enabled again
	// within one process must continue counting, not restart from zero.
	counts             map[string]*counter
	tcpTotal, udpTotal atomic.Int64
	wg                 sync.WaitGroup
	errors             chan error
	closed             chan struct{}
	once               sync.Once

	// Rules that share a destination (a route's TCP and UDP forwards) share
	// its health probe instead of each connecting on its own.
	probeMu sync.Mutex
	probes  map[string]*probe
}

type probe struct {
	at   time.Time
	done chan struct{}
	ok   bool
}

// probe connects to a destination once per half health interval, whichever
// rule asks; concurrent askers wait for the same attempt.
func (s *Service) probe(ctx context.Context, t *target) bool {
	key := t.host + "\x00" + strconv.Itoa(t.port)
	s.probeMu.Lock()
	if p := s.probes[key]; p != nil && time.Since(p.at) < healthInterval/2 {
		s.probeMu.Unlock()
		<-p.done
		return p.ok
	}
	if s.probes == nil || len(s.probes) > 1024 {
		s.probes = map[string]*probe{} // Forget destinations no rule uses any more.
	}
	p := &probe{at: time.Now(), done: make(chan struct{})}
	s.probes[key] = p
	s.probeMu.Unlock()
	conn, err := t.dialTCP(ctx)
	if err == nil {
		_ = conn.Close()
	}
	p.ok = err == nil
	close(p.done)
	return p.ok
}

// Start binds every enabled rule before returning.
func Start(rules []shared.ForwardRule) (*Service, error) {
	s := &Service{rules: map[string]*rule{}, counts: map[string]*counter{}, errors: make(chan error, 1), closed: make(chan struct{})}
	if err := s.Reload(rules); err != nil {
		s.Close()
		return nil, err
	}
	s.wg.Add(1)
	go s.sweep()
	return s, nil
}

// Reload makes the running rules match the given list. A rule whose listening
// address, destination and firewall policy are unchanged is left alone,
// connections included; a changed or removed rule is stopped together with
// its connections. Reload is atomic as far as it can be: duplicate IDs are an
// error, every new or changed rule is pre-validated (including a trial bind)
// before anything is stopped, and if starting a new rule fails partway, the
// previous rule set is restored on a best-effort basis.
func (s *Service) Reload(rules []shared.ForwardRule) error {
	wanted := map[string]shared.ForwardRule{}
	order := []string{}
	logicalIDs := map[string]bool{}
	for _, spec := range rules {
		if !spec.Enabled || spec.Deleting {
			continue
		}
		if err := shared.ValidateForward(spec); err != nil {
			return fmt.Errorf("转发 %q: %w", spec.Name, err)
		}
		if spec.Listen == "" {
			spec.Listen = "0.0.0.0"
		}
		if logicalIDs[spec.ID] {
			return fmt.Errorf("转发 %q: 重复的规则 ID %q", spec.Name, spec.ID)
		}
		logicalIDs[spec.ID] = true
		// Listener identities include the protocol; traffic counters retain
		// the logical ID so TCP and UDP share one public statistics record.
		for _, network := range shared.ForwardNetworks(spec.Network) {
			socket := spec
			socket.Network = network
			key := spec.ID + "\x00" + network
			order = append(order, key)
			wanted[key] = socket
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return errors.New("forward service is closed")
	default:
	}
	// Snapshot the running rules so a failed start can roll back to them.
	oldSpecs := make(map[string]shared.ForwardRule, len(s.rules))
	for id, running := range s.rules {
		oldSpecs[id] = running.spec
	}
	// Pre-validation, before anything is stopped: two wanted rules must not
	// share one listen address.
	seenListen := map[string]string{}
	for _, id := range order {
		key := listenKey(wanted[id])
		if prev, dup := seenListen[key]; dup {
			return fmt.Errorf("转发 %q 与 %q 监听地址冲突: %s", wanted[id].Name, wanted[prev].Name, key)
		}
		seenListen[key] = id
	}
	// Listen addresses that a rule about to be stopped is freeing need no
	// trial bind: the old listener still holds them, so a trial bind would
	// fail spuriously (this also covers two rules swapping ports).
	freed := map[string]bool{}
	for id, running := range s.rules {
		if spec, keep := wanted[id]; !keep || !sameEndpoints(running.spec, spec) {
			freed[listenKey(running.spec)] = true
		}
	}
	for _, id := range order {
		spec := wanted[id]
		if running, ok := s.rules[id]; ok && sameEndpoints(running.spec, spec) {
			continue // Unchanged: keep its listener and connections.
		}
		if freed[listenKey(spec)] {
			continue
		}
		// Trial bind, closed immediately. A failure here aborts the reload
		// before any running rule has been touched.
		// NOTE: 预 bind 与正式 bind 之间仍有 TOCTOU 窗口——另一个进程可能在
		// 预检通过后、正式 bind 之前抢占端口；正式 bind 失败时仍会走下面
		// 的回滚路径，只是窗口内的抢占无法被预检发现。
		if err := tryBind(spec); err != nil {
			return fmt.Errorf("转发 %q 预绑定 %s 失败: %w", spec.Name, forwardAddress(spec), err)
		}
	}
	// Stop first: a changed rule may want the port its old self still holds.
	for id, running := range s.rules {
		if spec, keep := wanted[id]; !keep || !sameEndpoints(running.spec, spec) {
			running.stop()
			delete(s.rules, id)
		}
	}
	started := []string{}
	for _, id := range order {
		if _, running := s.rules[id]; running {
			continue
		}
		stats := s.counts[wanted[id].ID]
		if stats == nil {
			stats = &counter{}
			s.counts[wanted[id].ID] = stats
		}
		startedRule, err := s.startRule(wanted[id], stats)
		if err != nil {
			// Best-effort rollback to the previous rule set: stop the new
			// rules already started, then restart the old rules that were
			// stopped. Rules that were never stopped keep running untouched.
			for _, sid := range started {
				if r, ok := s.rules[sid]; ok {
					r.stop()
					delete(s.rules, sid)
				}
			}
			var rollbackErrs []error
			for oid, ospec := range oldSpecs {
				if _, running := s.rules[oid]; running {
					continue
				}
				ostats := s.counts[ospec.ID]
				if ostats == nil {
					ostats = &counter{}
					s.counts[ospec.ID] = ostats
				}
				oldRule, rerr := s.startRule(ospec, ostats)
				if rerr != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("回滚转发 %q 失败: %w", ospec.Name, rerr))
					continue
				}
				s.rules[oid] = oldRule
			}
			if len(rollbackErrs) > 0 {
				return errors.Join(append([]error{err}, rollbackErrs...)...)
			}
			return err
		}
		s.rules[id] = startedRule
		started = append(started, id)
	}
	return nil
}

// listenKey identifies a rule's listen socket: TCP and UDP may share a port.
func listenKey(spec shared.ForwardRule) string {
	return spec.Network + "\x00" + spec.Listen + "\x00" + strconv.Itoa(spec.Port)
}

// An IPv6 wildcard means dual stack, with Go selecting IPv4 on hosts where
// IPv6 is unavailable. An explicit address keeps its original address family.
func forwardAddress(spec shared.ForwardRule) string {
	host := spec.Listen
	if host == "::" {
		host = ""
	}
	return net.JoinHostPort(host, strconv.Itoa(spec.Port))
}

// tryBind binds a rule's listen address once and closes it immediately, to
// find out before anything is stopped whether the address is usable.
func tryBind(spec shared.ForwardRule) error {
	address := forwardAddress(spec)
	if spec.Network == "tcp" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		return listener.Close()
	}
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

func sameEndpoints(a, b shared.ForwardRule) bool {
	// The firewall policy is part of a rule's identity: changing only the
	// policy must restart the rule so the new source check takes effect.
	if a.ObserveClients != b.ObserveClients || a.ClientNodeID != b.ClientNodeID || a.RouteID != b.RouteID || a.Network != b.Network || a.Listen != b.Listen || a.Port != b.Port || a.Balance != b.Balance || a.HealthCheck != b.HealthCheck || a.FirewallPolicy != b.FirewallPolicy || a.FirewallSources != b.FirewallSources || len(a.Targets) != len(b.Targets) {
		return false
	}
	for i := range a.Targets {
		if a.Targets[i] != b.Targets[i] {
			return false
		}
	}
	return true
}

// Run blocks until the context ends or a listener fails for good.
func (s *Service) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		s.Close()
		return nil
	case err := <-s.errors:
		s.Close()
		return err
	}
}

func (s *Service) Close() {
	s.once.Do(func() {
		close(s.closed)
		s.mu.Lock()
		for id, running := range s.rules {
			running.stop()
			delete(s.rules, id)
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
}

func (s *Service) Snapshot() map[string]Counter {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Counter, len(s.counts))
	for id, c := range s.counts {
		out[id] = Counter{Uplink: c.up.Load(), Downlink: c.down.Load()}
	}
	return out
}

func (s *Service) fail(err error) {
	select {
	case s.errors <- err:
	default:
	}
}

// sweep closes TCP connections that have been idle for too long.
func (s *Service) sweep() {
	defer s.wg.Done()
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		running := make([]*rule, 0, len(s.rules))
		for _, r := range s.rules {
			running = append(running, r)
		}
		s.mu.Unlock()
		oldest := time.Now().Add(-tcpIdleTimeout).UnixNano()
		for _, r := range running {
			r.mu.Lock()
			for pair := range r.pairs {
				if pair.last.Load() < oldest {
					pair.close()
				}
			}
			r.mu.Unlock()
		}
	}
}

func (s *Service) startRule(spec shared.ForwardRule, stats *counter) (*rule, error) {
	r := &rule{svc: s, spec: spec, stats: stats, done: make(chan struct{}), pairs: map[*tcpPair]struct{}{}, sessions: map[netip.AddrPort]*udpSession{}, perSource: map[netip.Addr]int{}}
	dynamic := false
	for _, t := range spec.Targets {
		target := newTarget(t.Host, t.Port)
		// A literal target that rejectPrivateAddr refused must never start:
		// the administrator configured it, but forwarding to it would turn
		// this host into an SSRF relay. TestAllowLoopbackTarget (set only by
		// tests) lifts both this and the self-loop check below.
		if !TestAllowLoopbackTarget {
			if target.illegal {
				return nil, fmt.Errorf("转发 %q 目标地址 %s 被拒绝: 目标不得为回环/链路本地/组播/未指定或云元数据地址", spec.Name, t.Host)
			}
			// Self-loop check: a target that is one of this host's own
			// interface addresses would forward traffic back into this host.
			// Any port on a local address is a loop.
			for _, addr := range target.snapshot() {
				if isLocalAddr(addr) {
					return nil, fmt.Errorf("转发 %q 目标地址 %s 属于本机网卡地址, 拒绝自环转发", spec.Name, addr)
				}
			}
		}
		dynamic = dynamic || !target.static
		r.targets = append(r.targets, target)
	}
	if len(r.targets) == 0 {
		return nil, fmt.Errorf("转发 %q 没有目标", spec.Name)
	}
	address := forwardAddress(spec)
	if spec.Network == "tcp" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("转发 %q 无法监听 %s: %w", spec.Name, address, err)
		}
		r.listener = listener
		s.wg.Add(1)
		go r.serveTCP(listener)
	} else {
		listener, err := net.ListenPacket("udp", address)
		if err != nil {
			return nil, fmt.Errorf("转发 %q 无法监听 %s: %w", spec.Name, address, err)
		}
		r.listener = listener
		s.wg.Add(1)
		go r.serveUDP(listener.(*net.UDPConn))
	}
	if dynamic || len(r.targets) > 1 {
		ctx, cancel := context.WithCancel(context.Background())
		r.cancelLookup = cancel
		if dynamic {
			s.wg.Add(1)
			go r.followTargets(ctx)
		}
		if len(r.targets) > 1 && tcpHealth(spec) {
			s.wg.Add(1)
			go r.checkHealth(ctx)
		} else if len(r.targets) > 1 && spec.Balance != "round-robin" {
			s.wg.Add(1)
			go r.retryPreferred()
		}
	}
	return r, nil
}
