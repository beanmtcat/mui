// Package forward relays TCP connections and UDP datagrams from a local port to
// a fixed destination. One Service runs every rule of a server and can be
// reloaded in place: rules that did not change keep their listeners and
// connections.
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
		if _, dup := wanted[spec.ID]; dup {
			return fmt.Errorf("转发 %q: 重复的规则 ID %q", spec.Name, spec.ID)
		}
		order = append(order, spec.ID)
		wanted[spec.ID] = spec
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
			return fmt.Errorf("转发 %q 预绑定 %s 失败: %w", spec.Name, net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port)), err)
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
		stats := s.counts[id]
		if stats == nil {
			stats = &counter{}
			s.counts[id] = stats
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
				ostats := s.counts[oid]
				if ostats == nil {
					ostats = &counter{}
					s.counts[oid] = ostats
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

// tryBind binds a rule's listen address once and closes it immediately, to
// find out before anything is stopped whether the address is usable.
func tryBind(spec shared.ForwardRule) error {
	address := net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port))
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
	return a.Network == b.Network && a.Listen == b.Listen && a.Port == b.Port && a.TargetHost == b.TargetHost && a.TargetPort == b.TargetPort && a.FirewallPolicy == b.FirewallPolicy && a.FirewallSources == b.FirewallSources
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

// rule is one running forward: a listener, its destination and whatever is
// currently connected through it.
type rule struct {
	svc          *Service
	spec         shared.ForwardRule
	stats        *counter
	target       *target
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
	r.target = newTarget(spec.TargetHost, spec.TargetPort)
	// A literal target that rejectPrivateAddr refused must never start: the
	// administrator configured it, but forwarding to it would turn this host
	// into an SSRF relay. TestAllowLoopbackTarget (set only by tests)
	// lifts both this and the self-loop check below.
	if !TestAllowLoopbackTarget {
		if r.target.illegal {
			return nil, fmt.Errorf("转发 %q 目标地址 %s 被拒绝: 目标不得为回环/链路本地/组播/未指定或云元数据地址", spec.Name, spec.TargetHost)
		}
		// Self-loop check: a target that is one of this host's own interface
		// addresses would forward traffic back into this host. There is no
		// TargetPort == Port premise: any port on a local address is a loop.
		for _, addr := range r.target.snapshot() {
			if isLocalAddr(addr) {
				return nil, fmt.Errorf("转发 %q 目标地址 %s 属于本机网卡地址, 拒绝自环转发", spec.Name, addr)
			}
		}
	}
	address := net.JoinHostPort(spec.Listen, strconv.Itoa(spec.Port))
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
	if !r.target.static {
		ctx, cancel := context.WithCancel(context.Background())
		r.cancelLookup = cancel
		s.wg.Add(1)
		go r.followTarget(ctx)
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

// followTarget keeps a host-name destination current and moves UDP sessions
// off addresses the name no longer resolves to.
func (r *rule) followTarget(parent context.Context) {
	defer r.svc.wg.Done()
	ticker := time.NewTicker(resolveInterval)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		ok := r.target.refresh(ctx)
		cancel()
		if ok {
			r.mu.Lock()
			for key, session := range r.sessions {
				if !r.target.current(session.remote) {
					// Drop the stale mapping as well as the connection: the
					// client's next datagram must open a fresh session to
					// the new address instead of reusing this one. The
					// session's reply loop releases its admit slot when the
					// close ends its read.
					delete(r.sessions, key)
					_ = session.conn.Close()
				}
			}
			r.mu.Unlock()
		}
		select {
		case <-r.done:
			return
		case <-ticker.C:
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstream, err := r.target.dialTCP(ctx)
	cancel()
	if err != nil {
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
		}
	}
}

// openSession never waits on the network: the destination address comes from
// the resolver's last answer and connecting a UDP socket sends nothing, so one
// new client cannot hold up the datagrams of all the others.
func (r *rule) openSession(listener *net.UDPConn, client netip.AddrPort) *udpSession {
	remote, ok := r.target.first()
	if !ok {
		return nil // The name has not resolved yet; the client will retry.
	}
	src := client.Addr().Unmap()
	if !r.allowedSource(src) {
		return nil
	}
	if !r.admit(src, &r.svc.udpTotal, maxUDPTotal, maxUDPPerRule, maxUDPPerSource) {
		return nil
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, uint16(r.spec.TargetPort))))
	if err != nil {
		r.release(src, &r.svc.udpTotal)
		return nil
	}
	session := &udpSession{conn: conn, remote: remote}
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

	mu sync.RWMutex
	// latest is the most recent answer, in resolver order. previous is the one
	// before: an address counts as current while it is in either, which keeps
	// names that rotate between several records from looking like a move.
	latest, previous []netip.Addr
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
