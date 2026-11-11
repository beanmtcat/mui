package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"mui/internal/shared"
)

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
		if pair.upstream != nil {
			r.svc.clients.record(r.spec, sourceOf(client.RemoteAddr()), time.Now())
		}
		pair.close()
	}()
	upstream := r.dialUpstream()
	if upstream == nil {
		return
	}
	r.mu.Lock()
	pair.upstream = upstream
	r.svc.clients.record(r.spec, sourceOf(client.RemoteAddr()), time.Now())
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

func tcpHealth(spec shared.ForwardRule) bool {
	return spec.HealthCheck == "tcp" || spec.HealthCheck == "" && spec.Network == "tcp"
}
