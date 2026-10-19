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
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	mu    sync.Mutex
	rules map[string]*rule
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

func tcpHealth(spec shared.ForwardRule) bool {
	return spec.HealthCheck == "tcp" || spec.HealthCheck == "" && spec.Network == "tcp"
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
	if a.Network != b.Network || a.Listen != b.Listen || a.Port != b.Port || a.Balance != b.Balance || a.HealthCheck != b.HealthCheck || a.FirewallPolicy != b.FirewallPolicy || a.FirewallSources != b.FirewallSources || len(a.Targets) != len(b.Targets) {
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

// rule is one running forward: a listener, its destinations and whatever is
// currently connected through it.
type rule struct {
	svc          *Service
	spec         shared.ForwardRule
	stats        *counter
	targets      []*target
	next         atomic.Uint32 // round-robin position
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
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
		}
		var wg sync.WaitGroup
		changed := make([]bool, len(r.targets))
		for i, t := range r.targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(parent, healthTimeout)
				ok := r.svc.probe(ctx, t)
				cancel()
				changed[i] = t.observe(ok)
			}()
		}
		wg.Wait()
		for _, c := range changed {
			if c {
				r.rebalanceSessions()
				break
			}
		}
	}
}

// rebalanceSessions closes UDP sessions that should no longer use their
// destination; the client's next datagram opens one on the right destination.
func (r *rule) rebalanceSessions() {
	preferred := r.candidates()[0]
	r.dropSessions(func(session *udpSession) bool {
		if !session.target.up() {
			return preferred.up()
		}
		return r.spec.Balance != "round-robin" && session.target != preferred
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

// candidates lists the destinations in the order a new connection tries them:
// healthy ones first (in configuration order for failover, rotated for
// round-robin), then the rest as a last resort.
func (r *rule) candidates() []*target {
	if len(r.targets) == 1 {
		return r.targets
	}
	healthy := make([]*target, 0, len(r.targets))
	var down []*target
	for _, t := range r.targets {
		if t.up() {
			healthy = append(healthy, t)
		} else {
			down = append(down, t)
		}
	}
	ordered := append(healthy, down...)
	count := len(healthy)
	if count == 0 {
		count = len(ordered)
	}
	if r.spec.Balance == "round-robin" && count > 1 {
		start := int(r.next.Add(1)-1) % count
		rotated := append([]*target{}, ordered[start:count]...)
		rotated = append(rotated, ordered[:start]...)
		return append(rotated, ordered[count:]...)
	}
	return ordered
}

func (r *rule) failedTarget(t *target) {
	if len(r.targets) < 2 || r.stopped() {
		return
	}
	cooldown := time.Duration(0)
	if !tcpHealth(r.spec) {
		cooldown = 2 * healthInterval
	}
	if t.markDownFor(cooldown) {
		r.rebalanceSessions()
	}
}

// ---- TCP

type tcpPair struct {
	client, upstream *net.TCPConn
	last             atomic.Int64
}

func (p *tcpPair) close() {
	_ = p.client.Close()
	if p.upstream != nil {
		_ = p.upstream.Close()
	}
}

func (r *rule) serveTCP(listener net.Listener) {
	defer r.svc.wg.Done()
	failures := 0
	backoff := 50 * time.Millisecond
	for {
		conn, err := listener.Accept()
		if err != nil {
			if r.stopped() {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient error (running out of file descriptors is the
			// usual cause) passes once connections close; only a listener
			// that stays broken is fatal, so back off exponentially instead
			// of killing the process on a burst of momentary failures.
			failures++
			if failures > 1000 {
				r.svc.fail(fmt.Errorf("转发 %q 接受连接失败: %w", r.spec.Name, err))
				return
			}
			time.Sleep(backoff)
			if backoff < 2*time.Second {
				backoff *= 2
				if backoff > 2*time.Second {
					backoff = 2 * time.Second
				}
			}
			continue
		}
		failures = 0
		backoff = 50 * time.Millisecond
		client := conn.(*net.TCPConn)
		src := sourceOf(client.RemoteAddr())
		if !r.allowedSource(src) {
			_ = client.Close()
			continue
		}
		if !r.admit(src, &r.svc.tcpTotal, maxTCPTotal, maxTCPPerRule, maxTCPPerSource) {
			_ = client.Close()
			continue
		}
		r.svc.wg.Add(1)
		go func() {
			defer r.svc.wg.Done()
			defer r.release(src, &r.svc.tcpTotal)
			r.proxyTCP(client)
		}()
	}
}

func (r *rule) proxyTCP(client *net.TCPConn) {
	pair := &tcpPair{client: client}
	pair.last.Store(time.Now().UnixNano())
	r.mu.Lock()
	r.pairs[pair] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pairs, pair)
		r.mu.Unlock()
		pair.close()
	}()
	upstream := r.dialUpstream()
	if upstream == nil {
		return
	}
	r.mu.Lock()
	pair.upstream = upstream
	r.mu.Unlock()
	if r.stopped() {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay(upstream, client, &r.stats.up, &pair.last)
	}()
	relay(client, upstream, &r.stats.down, &pair.last)
	<-done
}

// dialUpstream connects to the first destination that answers, in candidate
// order, within ten seconds overall. A destination that refuses is marked down
// at once when there are others to use.
func (r *rule) dialUpstream() *net.TCPConn {
	deadline := time.Now().Add(10 * time.Second)
	candidates := r.candidates()
	for i, t := range candidates {
		budget := time.Until(deadline)
		if budget <= 0 {
			return nil
		}
		if left := len(candidates) - i; left > 1 {
			// Leave time for the remaining destinations.
			budget = min(budget, max(budget/time.Duration(left), 3*time.Second))
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		conn, err := t.dialTCP(ctx)
		cancel()
		if err == nil {
			return conn
		}
		r.failedTarget(t)
	}
	return nil
}

// relay moves one direction of a connection. Both ends are plain TCP sockets
// and the copy goes through (*net.TCPConn).ReadFrom, which on Linux splices
// inside the kernel: the data never enters this process and no buffer is held
// while the connection is idle.
//
// The copy is interrupted every relayTick by a read deadline so that the byte
// counters and the activity time follow a connection while it is open, however
// little it sends. Only the read side has a deadline: it can expire only while
// waiting for input, when nothing is in flight, so an interruption never loses
// data.
func relay(dst, src *net.TCPConn, count, last *atomic.Int64) {
	for {
		_ = src.SetReadDeadline(time.Now().Add(relayTick))
		n, err := io.CopyN(dst, src, copyChunk)
		if n > 0 {
			count.Add(n)
			last.Store(time.Now().UnixNano())
		}
		if err == nil {
			continue
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		break
	}
	// Pass the end of stream on; the other direction may still have data to send.
	_ = dst.CloseWrite()
}

// ---- UDP

type udpSession struct {
	conn   *net.UDPConn
	target *target
	remote netip.Addr
	last   atomic.Int64
	// Per-session byte counters for the reply/request ratio alert in
	// udpReplies: serveUDP counts uplink, udpReplies counts downlink.
	up, down atomic.Int64
	warned   atomic.Bool
}

func (r *rule) serveUDP(listener *net.UDPConn) {
	defer r.svc.wg.Done()
	buffer := make([]byte, maxDatagram)
	failures := 0
	backoff := 50 * time.Millisecond
	for {
		n, client, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if r.stopped() {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient read errors get exponential back-off, as in
			// serveTCP; only a socket that stays broken is fatal.
			failures++
			if failures > 1000 {
				r.svc.fail(fmt.Errorf("转发 %q 读取 UDP 失败: %w", r.spec.Name, err))
				return
			}
			time.Sleep(backoff)
			if backoff < 2*time.Second {
				backoff *= 2
				if backoff > 2*time.Second {
					backoff = 2 * time.Second
				}
			}
			continue
		}
		failures = 0
		backoff = 50 * time.Millisecond
		r.mu.Lock()
		session := r.sessions[client]
		r.mu.Unlock()
		if session == nil {
			if session = r.openSession(listener, client); session == nil {
				continue
			}
		}
		session.last.Store(time.Now().UnixNano())
		if sent, err := session.conn.Write(buffer[:n]); err == nil {
			r.stats.up.Add(int64(sent))
			session.up.Add(int64(sent))
		} else if !errors.Is(err, net.ErrClosed) {
			r.failedTarget(session.target)
		}
	}
}

// openSession never waits on the network: the destination address comes from
// the resolver's last answer and connecting a UDP socket sends nothing, so one
// new client cannot hold up the datagrams of all the others.
func (r *rule) openSession(listener *net.UDPConn, client netip.AddrPort) *udpSession {
	var target *target
	var remote netip.Addr
	for _, t := range r.candidates() {
		if addr, ok := t.first(); ok {
			target, remote = t, addr
			break
		}
	}
	if target == nil {
		return nil // No name has resolved yet; the client will retry.
	}
	src := client.Addr().Unmap()
	if !r.allowedSource(src) {
		return nil
	}
	if !r.admit(src, &r.svc.udpTotal, maxUDPTotal, maxUDPPerRule, maxUDPPerSource) {
		return nil
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, uint16(target.port))))
	if err != nil {
		r.release(src, &r.svc.udpTotal)
		return nil
	}
	session := &udpSession{conn: conn, target: target, remote: remote}
	session.last.Store(time.Now().UnixNano())
	r.mu.Lock()
	r.sessions[client] = session
	r.mu.Unlock()
	if r.stopped() {
		_ = conn.Close()
	}
	r.svc.wg.Add(1)
	go func() {
		defer r.svc.wg.Done()
		r.udpReplies(listener, client, session)
		r.mu.Lock()
		if r.sessions[client] == session {
			delete(r.sessions, client)
		}
		r.mu.Unlock()
		_ = conn.Close()
		r.release(src, &r.svc.udpTotal)
	}()
	return session
}

func (r *rule) udpReplies(listener *net.UDPConn, client netip.AddrPort, session *udpSession) {
	buffer := make([]byte, smallDatagram)
	for {
		_ = session.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, _, flags, _, err := session.conn.ReadMsgUDP(buffer, nil)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && time.Since(time.Unix(0, session.last.Load())) < udpIdleTimeout {
				continue
			}
			if !errors.Is(err, net.ErrClosed) && !(errors.As(err, &netErr) && netErr.Timeout()) {
				r.failedTarget(session.target)
			}
			return
		}
		if flags&syscall.MSG_TRUNC != 0 {
			// Larger than the buffer, so its tail is gone and it cannot be
			// forwarded. UDP senders cope with a lost datagram; from now on this
			// session can take the largest one.
			if len(buffer) < maxDatagram {
				buffer = make([]byte, maxDatagram)
			}
			continue
		}
		session.last.Store(time.Now().UnixNano())
		if sent, err := listener.WriteToUDPAddrPort(buffer[:n], client); err == nil {
			r.stats.down.Add(int64(sent))
			down := session.down.Add(int64(sent))
			// A session that receives far more than it sends is likely
			// being used as an amplifier/reflector. Warn once per session.
			if !session.warned.Load() && down > 1<<20 && down > 10*session.up.Load() {
				session.warned.Store(true)
				log.Printf("转发 %q UDP 会话 %s -> %s 回复/请求比异常: down=%d up=%d, 可能被用作放大反射", r.spec.Name, client, session.remote, down, session.up.Load())
			}
		}
	}
}

func sourceOf(addr net.Addr) netip.Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

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
