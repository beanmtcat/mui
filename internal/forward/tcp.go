package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"mui/internal/shared"
)

// ---- TCP

type tcpPair struct {
	client, upstream *net.TCPConn
	last             atomic.Int64
	transferred      atomic.Bool
	closeOnce        sync.Once
	closed           chan struct{}
}

func (p *tcpPair) close() {
	p.closeOnce.Do(func() {
		if p.closed != nil {
			close(p.closed)
		}
		_ = p.client.Close()
		if p.upstream != nil {
			_ = p.upstream.Close()
		}
	})
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
		if !r.allowedSource(src) || r.trafficBlocked() {
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
	pair := &tcpPair{client: client, closed: make(chan struct{})}
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
	upstream, target := r.dialUpstream()
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
	if target.quality.group != nil {
		observation := relayTCPObservation{target: target.quality, src: sourceOf(client.RemoteAddr()), started: time.Now()}
		go func() {
			defer close(done)
			observation.upload(pair, r)
		}()
		observation.download(pair, r)
	} else {
		go func() {
			defer close(done)
			r.relay(upstream, client, &r.stats.up, pair, true, nil)
		}()
		r.relay(client, upstream, &r.stats.down, pair, false, nil)
	}
	<-done
}

// dialUpstream connects to the first destination that answers, in candidate
// order, within ten seconds overall. A destination that refuses is marked down
// at once when there are others to use.
func (r *rule) dialUpstream() (*net.TCPConn, *target) {
	deadline := time.Now().Add(10 * time.Second)
	candidates := r.candidates()
	for i, t := range candidates {
		if state, manual := t.relayStatus(time.Now()); manual && state == shared.RelayDown {
			continue
		}
		budget := time.Until(deadline)
		if budget <= 0 {
			return nil, nil
		}
		if left := len(candidates) - i; left > 1 {
			// Leave time for the remaining destinations.
			budget = min(budget, max(budget/time.Duration(left), 3*time.Second))
		}
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		conn, err := t.dialTCP(ctx)
		cancel()
		if err == nil {
			return conn, t
		}
		r.failedTarget(t)
	}
	return nil, nil
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
const (
	quotaCopyChunk    = 256 << 10
	rateLimitBufBytes = 32 << 10
)

var rateLimitBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, rateLimitBufBytes)
		return &b
	},
}

func (r *rule) relay(dst, src *net.TCPConn, count *atomic.Int64, pair *tcpPair, isUpload bool, beforeClose func(error)) {
	for {
		if r.trafficBlocked() {
			pair.close()
			return
		}
		chunk := int64(copyChunk)
		var bucket *tokenBucket
		if g := r.limits.Load(); g != nil {
			if isUpload {
				bucket = g.upBucket
			} else {
				bucket = g.downBucket
			}
			if g.quotaLimit() > 0 && chunk > quotaCopyChunk {
				chunk = quotaCopyChunk
			}
		}
		// Rate-limited path: read actual available bytes FIRST, then acquire
		// global rate budget at send time so idle connections cannot bank
		// tokens and burst simultaneously later.
		if bucket != nil && bucket.rateBps() > 0 {
			rate := bucket.rateBps()
			readCap := int(min(int64(rateLimitBufBytes), max(int64(4<<10), rate/20)))
			bufPtr := rateLimitBufPool.Get().(*[]byte)
			buf := (*bufPtr)[:readCap]
			_ = src.SetReadDeadline(time.Now().Add(relayTick))
			n, readErr := src.Read(buf)
			if n > 0 {
				if r.trafficBlocked() {
					rateLimitBufPool.Put(bufPtr)
					pair.close()
					return
				}
				if !bucket.waitPre(pair.closed, int64(n), r.svc.now) {
					rateLimitBufPool.Put(bufPtr)
					return
				}
				if r.trafficBlocked() {
					rateLimitBufPool.Put(bufPtr)
					pair.close()
					return
				}
				written, writeErr := writeFullTCP(dst, buf[:n])
				rateLimitBufPool.Put(bufPtr)
				if written > 0 {
					pair.transferred.Store(true)
					count.Add(int64(written))
					pair.last.Store(time.Now().UnixNano())
					if isUpload {
						r.recordTraffic(int64(written), 0)
					} else {
						r.recordTraffic(0, int64(written))
					}
				}
				if writeErr != nil {
					if beforeClose != nil {
						beforeClose(writeErr)
					}
					break
				}
			} else {
				rateLimitBufPool.Put(bufPtr)
			}
			if readErr == nil {
				continue
			}
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				continue
			}
			if beforeClose != nil {
				beforeClose(readErr)
			}
			break
		}

		// Unlimited (or quota-only) path: keep kernel zero-copy splice(2).
		_ = src.SetReadDeadline(time.Now().Add(relayTick))
		n, err := io.CopyN(dst, src, chunk)
		if n > 0 {
			pair.transferred.Store(true)
			count.Add(n)
			pair.last.Store(time.Now().UnixNano())
			if isUpload {
				r.recordTraffic(n, 0)
			} else {
				r.recordTraffic(0, n)
			}
		}
		if err == nil {
			continue
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		if beforeClose != nil {
			beforeClose(err)
		}
		break
	}
	// Pass the end of stream on; the other direction may still have data to send.
	_ = dst.CloseWrite()
}

func writeFullTCP(dst *net.TCPConn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := dst.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func tcpHealth(spec shared.ForwardRule) bool {
	return spec.HealthCheck == "tcp" || spec.HealthCheck == "" && spec.Network == "tcp"
}
