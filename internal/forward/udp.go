package forward

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

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
	r.svc.clients.record(r.spec, src, time.Now())
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
