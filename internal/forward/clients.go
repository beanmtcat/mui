package forward

import (
	"container/list"
	"mui/internal/shared"
	"net/netip"
	"sync"
	"time"
)

const maxClientObservations = 500
const clientObservationTTL = 2 * time.Minute

type clientObservations struct {
	mu    sync.Mutex
	items map[string]*list.Element
	order list.List
}

// O(1), bounded memory. No per-packet scans; active sessions are sampled by
// ConnectionSnapshot on a timer, and short TCP connections are retained too.
func (c *clientObservations) record(spec shared.ForwardRule, ip netip.Addr, at time.Time) {
	if !spec.ObserveClients || spec.RouteID == "" || spec.ClientNodeID == "" || !ip.IsValid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = make(map[string]*list.Element)
	}
	key := spec.ID + "/" + ip.Unmap().String()
	if e := c.items[key]; e != nil {
		p := e.Value.(shared.ForwardConnectionPoint)
		if at.Before(p.At) {
			at = p.At
		}
		e.Value = shared.ForwardConnectionPoint{ForwardID: spec.ID, RouteID: spec.RouteID, NodeID: spec.ClientNodeID, IP: ip.Unmap().String(), At: at}
		c.order.MoveToBack(e)
		return
	}
	if c.order.Len() >= maxClientObservations {
		e := c.order.Front()
		p := e.Value.(shared.ForwardConnectionPoint)
		delete(c.items, p.ForwardID+"/"+p.IP)
		c.order.Remove(e)
	}
	c.items[key] = c.order.PushBack(shared.ForwardConnectionPoint{ForwardID: spec.ID, RouteID: spec.RouteID, NodeID: spec.ClientNodeID, IP: ip.Unmap().String(), At: at})
}

func (s *Service) ConnectionSnapshot() []shared.ForwardConnectionPoint {
	s.mu.Lock()
	now := time.Now()
	for _, r := range s.rules {
		if !r.spec.ObserveClients {
			continue
		}
		r.mu.Lock()
		for p := range r.pairs {
			if p.upstream != nil {
				s.clients.record(r.spec, sourceOf(p.client.RemoteAddr()), now)
			}
		}
		for addr, session := range r.sessions {
			s.clients.record(r.spec, addr.Addr(), time.Unix(0, session.last.Load()))
		}
		r.mu.Unlock()
	}
	s.mu.Unlock()
	s.clients.mu.Lock()
	defer s.clients.mu.Unlock()
	out := make([]shared.ForwardConnectionPoint, 0, s.clients.order.Len())
	for e := s.clients.order.Front(); e != nil; {
		next := e.Next()
		p := e.Value.(shared.ForwardConnectionPoint)
		if now.Sub(p.At) > clientObservationTTL {
			delete(s.clients.items, p.ForwardID+"/"+p.IP)
			s.clients.order.Remove(e)
		} else {
			out = append(out, p)
		}
		e = next
	}
	return out
}
