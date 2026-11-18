package forward

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// Track only the start of real TCP flows. The first upstream read has a
// known origin, unlike a splice error which can come from either socket.
type relayTCPObservation struct {
	mu                       sync.Mutex
	target                   qualityRef
	src                      netip.Addr
	started                  time.Time
	sent, clientClosed, done bool
}

func (o *relayTCPObservation) noteUpload() {
	o.mu.Lock()
	o.sent = true
	o.mu.Unlock()
}

func (o *relayTCPObservation) noteClientClosed() {
	o.mu.Lock()
	o.clientClosed = true
	o.mu.Unlock()
}

func (o *relayTCPObservation) finish(result qualityObservation) {
	o.mu.Lock()
	if o.done {
		o.mu.Unlock()
		return
	}
	o.done = true
	eligible := !o.clientClosed && (result == qualityGood || o.sent)
	o.mu.Unlock()
	if eligible {
		o.target.observeConnection(o.src, result, o.started, time.Now())
	}
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Read the first client data normally to timestamp an upload even if splice
// would otherwise keep waiting for more data. Bulk transfer still uses relay.
func (o *relayTCPObservation) upload(pair *tcpPair, r *rule) {
	var first [1024]byte
	for {
		_ = pair.client.SetReadDeadline(time.Now().Add(relayTick))
		n, err := pair.client.Read(first[:])
		if n > 0 {
			written, writeErr := pair.upstream.Write(first[:n])
			if written > 0 {
				o.noteUpload()
				r.stats.up.Add(int64(written))
				pair.last.Store(time.Now().UnixNano())
				pair.transferred.Store(true)
			}
			if writeErr != nil {
				_ = pair.upstream.CloseWrite()
				return
			}
		}
		if err != nil && !timedOut(err) {
			o.noteClientClosed()
			_ = pair.upstream.CloseWrite()
			return
		}
		if n > 0 {
			break
		}
	}
	relay(pair.upstream, pair.client, &r.stats.up, &pair.last, &pair.transferred, func(err error) {
		// A relayed EOF is a clean client read ending. Also avoid counting
		// ambiguous splice resets as the target's fault.
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed) {
			o.noteClientClosed()
		}
	})
}

func (o *relayTCPObservation) download(pair *tcpPair, r *rule) {
	var first [1024]byte
	deadline := o.started.Add(tcpInitialTimeout)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			o.finish(qualityBad)
			break
		}
		readUntil := now.Add(relayTick)
		if readUntil.After(deadline) {
			readUntil = deadline
		}
		_ = pair.upstream.SetReadDeadline(readUntil)
		n, err := pair.upstream.Read(first[:])
		if n > 0 {
			o.finish(qualityGood)
			written, writeErr := pair.client.Write(first[:n])
			if written > 0 {
				r.stats.down.Add(int64(written))
				pair.last.Store(time.Now().UnixNano())
				pair.transferred.Store(true)
			}
			if writeErr != nil {
				_ = pair.client.CloseWrite()
				return
			}
			break
		}
		if err == nil || timedOut(err) {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
			o.finish(qualityBad)
		}
		_ = pair.client.CloseWrite()
		return
	}
	relay(pair.client, pair.upstream, &r.stats.down, &pair.last, &pair.transferred, nil)
}
