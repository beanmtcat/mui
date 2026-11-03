package agent

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"mui/internal/shared"
)

const (
	routeLatencyInterval = time.Minute
	routeLatencyTimeout  = 3 * time.Second
	maxRouteLatencyEdges = 200
	latencyWorkers       = 8
)

type routeLatencySampler struct {
	mu     sync.RWMutex
	points []shared.RouteLatency
}

func (s *routeLatencySampler) snapshot() []shared.RouteLatency {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]shared.RouteLatency(nil), s.points...)
}

func (s *routeLatencySampler) run(ctx context.Context) {
	ticker := time.NewTicker(routeLatencyInterval)
	defer ticker.Stop()
	for {
		sampleCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		points := sampleRouteLatencies(sampleCtx, ReadCurrent().Forwards)
		cancel()
		s.mu.Lock()
		s.points = points
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// These are TCP connect times between adjacent servers, not an end-to-end
// application RTT. Only route forwards from the applied state are probed, so
// the Agent cannot be given arbitrary targets through a reporting response.
// A manual TCP + UDP forward reused by a route arrives with its RouteID set.
func sampleRouteLatencies(ctx context.Context, forwards []shared.ForwardRule) []shared.RouteLatency {
	type task struct {
		index  int
		rule   shared.ForwardRule
		target shared.ForwardTarget
	}
	jobs := make([]task, 0)
	seen := make(map[string]bool)
	for _, rule := range forwards {
		if rule.RouteID == "" || !shared.ForwardNetworkIncludes(rule.Network, "tcp") || !rule.Enabled || rule.Deleting {
			continue
		}
		for _, target := range rule.Targets {
			if target.Host == "" || target.Port < 1 || target.Port > 65535 {
				continue
			}
			key := rule.ID + "\x00" + target.Host + "\x00" + strconv.Itoa(target.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			jobs = append(jobs, task{index: len(jobs), rule: rule, target: target})
			if len(jobs) == maxRouteLatencyEdges {
				break
			}
		}
		if len(jobs) == maxRouteLatencyEdges {
			break
		}
	}
	points := make([]shared.RouteLatency, len(jobs))
	queue := make(chan task)
	var wg sync.WaitGroup
	for i := 0; i < latencyWorkers && i < len(jobs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range queue {
				probeCtx, cancel := context.WithTimeout(ctx, routeLatencyTimeout)
				start := time.Now()
				conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", net.JoinHostPort(job.target.Host, strconv.Itoa(job.target.Port)))
				if err == nil {
					_ = conn.Close()
				}
				cancel()
				ms := time.Since(start).Milliseconds()
				if err == nil && ms < 1 {
					ms = 1
				}
				if ms > routeLatencyTimeout.Milliseconds() {
					ms = routeLatencyTimeout.Milliseconds()
				}
				points[job.index] = shared.RouteLatency{
					ForwardID: job.rule.ID, Host: job.target.Host, Port: job.target.Port,
					TCPMs: ms, OK: err == nil, At: time.Now(),
				}
			}
		}()
	}
queueing:
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			break queueing
		case queue <- job:
		}
	}
	close(queue)
	wg.Wait()
	valid := points[:0]
	for _, point := range points {
		if point.ForwardID != "" {
			valid = append(valid, point)
		}
	}
	points = valid
	sort.Slice(points, func(i, j int) bool {
		if points[i].ForwardID != points[j].ForwardID {
			return points[i].ForwardID < points[j].ForwardID
		}
		if points[i].Host != points[j].Host {
			return points[i].Host < points[j].Host
		}
		return points[i].Port < points[j].Port
	})
	return points
}
