package forward

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"mui/internal/shared"
)

const (
	relayWindow            = time.Minute
	relayProbeSamples      = 12
	relayBaselineMinutes   = 60
	relayRecoveryMin       = 2 * time.Minute
	relayRecoveryMax       = 30 * time.Minute
	relayProbationSamples  = 10
	relayProbationLimit    = 10 * time.Minute
	relayPassiveMinSources = 20
	relayPassiveMaxSources = 512
)

type probeResult struct {
	at      time.Time
	elapsed time.Duration
	ok      bool
}

type baselineMinute struct {
	minute int64
	total  time.Duration
	count  int
}

type passiveOutcomes struct{ good, bad time.Time }

type relayQualityTarget struct {
	state, reason                string
	since                        time.Time
	streak, badWindows           int
	healthySince, enoughTrialsAt time.Time
	recovery                     time.Duration
	trials                       int
	probationUnclean             bool
	probationProbeAt             time.Time

	probes   [relayProbeSamples]probeResult
	pos      int
	baseline [relayBaselineMinutes + 1]baselineMinute
	passive  map[netip.Addr]passiveOutcomes
	stats    shared.RelayStats
}

type relayQualityGroup struct {
	mu                        sync.Mutex
	targets                   []relayQualityTarget
	lastStart, lastEvaluation time.Time
}

type qualityRef struct {
	group *relayQualityGroup
	index int
}

func newRelayQualityGroup(size int, now time.Time) *relayQualityGroup {
	g := &relayQualityGroup{targets: make([]relayQualityTarget, size)}
	for i := range g.targets {
		g.targets[i].state = shared.RelayNormal
		g.targets[i].since = now
		g.targets[i].recovery = relayRecoveryMin
	}
	return g
}

func (q *relayQualityTarget) transition(state, reason string, now time.Time) {
	q.state, q.reason, q.since = state, reason, now
	q.healthySince, q.enoughTrialsAt = time.Time{}, time.Time{}
	q.badWindows, q.trials = 0, 0
	q.probationUnclean, q.probationProbeAt = false, time.Time{}
}

func (g *relayQualityGroup) beginProbe(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.lastStart) < healthInterval*4/5 {
		return false
	}
	g.lastStart = now
	return true
}

func (q *relayQualityTarget) addProbe(p probeResult) {
	q.probes[q.pos] = p
	q.pos = (q.pos + 1) % len(q.probes)
	if p.ok {
		minute := p.at.Unix() / 60
		bucket := &q.baseline[minute%int64(len(q.baseline))]
		if bucket.minute != minute {
			*bucket = baselineMinute{minute: minute}
		}
		bucket.total += p.elapsed
		bucket.count++
	}
	// A probe begun before a newer dial failure cannot confirm recovery.
	if q.state == shared.RelayDown && p.at.Before(q.since) {
		return
	}
	if p.ok != (q.state == shared.RelayDown) {
		q.streak = 0
		return
	}
	q.streak++
	if q.streak < healthStreak {
		return
	}
	q.streak = 0
	if p.ok {
		q.transition(shared.RelayDegraded, q.reason, p.at)
	} else {
		q.fail("probe_failed", p.at)
	}
}

func (q *relayQualityTarget) fail(reason string, now time.Time) {
	if q.state == shared.RelayProbation {
		q.recovery = min(relayRecoveryMax, 2*q.recovery)
	}
	q.transition(shared.RelayDown, reason, now)
}

func (q *relayQualityTarget) probeSummary(now time.Time) (success, loss int, median, baseline time.Duration) {
	var measured [relayProbeSamples]time.Duration
	for _, p := range q.probes {
		if p.at.IsZero() || now.Sub(p.at) > relayWindow {
			continue
		}
		if !p.ok {
			loss++
			continue
		}
		measured[success] = p.elapsed
		success++
	}
	if success > 0 {
		values := measured[:success]
		slices.Sort(values)
		median = (values[(success-1)/2] + values[success/2]) / 2
	}
	minute := now.Unix() / 60
	var count int
	var total time.Duration
	for _, b := range q.baseline {
		if b.minute < minute && b.minute >= minute-relayBaselineMinutes {
			count += b.count
			total += b.total
		}
	}
	if count > 0 {
		baseline = total / time.Duration(count)
	}
	return
}

func (q *relayQualityTarget) passiveSummary(now time.Time) (sources, good, bad int) {
	for addr, o := range q.passive {
		hasGood := !o.good.IsZero() && now.Sub(o.good) < relayWindow
		hasBad := !o.bad.IsZero() && now.Sub(o.bad) < relayWindow
		if !hasGood && !hasBad {
			delete(q.passive, addr)
			continue
		}
		sources++
		if hasGood {
			good++
		}
		if hasBad {
			bad++
		}
	}
	return
}

type qualityObservation uint8

const (
	qualityUnknown qualityObservation = iota
	qualityGood
	qualityBad
)

func (ref qualityRef) observeConnection(src netip.Addr, result qualityObservation, started, now time.Time) {
	if result == qualityUnknown || !src.IsValid() {
		return
	}
	g := ref.group
	g.mu.Lock()
	defer g.mu.Unlock()
	q := &g.targets[ref.index]
	if q.state == shared.RelayProbation && result == qualityBad && !now.Before(q.since) {
		q.probationUnclean = true
	}
	src = src.Unmap()
	if q.passive == nil {
		q.passive = make(map[netip.Addr]passiveOutcomes)
	}
	record, exists := q.passive[src]
	if !exists && len(q.passive) >= relayPassiveMaxSources {
		return // Keep memory bounded even when a port sees many spoofed sources.
	}
	var previous time.Time
	if result == qualityGood {
		previous, record.good = record.good, now
	} else {
		previous, record.bad = record.bad, now
	}
	q.passive[src] = record
	distinct := previous.IsZero() || now.Sub(previous) >= relayWindow
	if distinct && result == qualityGood && q.state == shared.RelayProbation && !started.Before(q.since) && q.trials < relayProbationSamples {
		q.trials++
		if q.trials == relayProbationSamples {
			q.enoughTrialsAt = now
		}
	}
}

func (q *relayQualityTarget) evaluate(now time.Time, reason string, newWindow bool) {
	switch q.state {
	case shared.RelayNormal:
		if reason != "" {
			q.healthySince = time.Time{}
		} else if q.healthySince.IsZero() {
			q.healthySince = now
		} else if now.Sub(q.healthySince) >= time.Hour {
			q.recovery = relayRecoveryMin
		}
		if !newWindow {
			return
		}
		if reason == "" {
			q.badWindows = 0
			return
		}
		q.badWindows++
		if q.badWindows >= 2 {
			q.transition(shared.RelayDegraded, reason, now)
		}
	case shared.RelayDegraded, shared.RelayProbation:
		if reason != "" {
			if q.state == shared.RelayProbation {
				q.recovery = min(relayRecoveryMax, 2*q.recovery)
				q.transition(shared.RelayDegraded, reason, now)
			} else {
				q.healthySince = time.Time{}
			}
			return
		}
		if q.state == shared.RelayProbation {
			enoughTraffic := !q.enoughTrialsAt.IsZero() && now.Sub(q.enoughTrialsAt) >= relayRecoveryMin
			cleanProbes := !q.probationUnclean && !q.probationProbeAt.IsZero() && now.Sub(q.probationProbeAt) <= 2*healthInterval
			if enoughTraffic || cleanProbes && now.Sub(q.since) >= relayProbationLimit {
				q.transition(shared.RelayNormal, "healthy", now)
			}
			return
		}
		if q.healthySince.IsZero() {
			q.healthySince = now
		}
		if now.Sub(q.healthySince) >= q.recovery {
			q.transition(shared.RelayProbation, "recovering", now)
		}
	}
}

type relayQualitySignals struct {
	median, baseline         time.Duration
	loss, sources, good, bad int
}

func (sig relayQualitySignals) badRatio() float64 {
	if sig.good+sig.bad == 0 {
		return 0
	}
	return float64(sig.bad) / float64(sig.good+sig.bad)
}

func (sig relayQualitySignals) passivelyWorseThan(peer relayQualitySignals) bool {
	total, peerTotal := sig.good+sig.bad, peer.good+peer.bad
	return 10*(sig.bad*peerTotal-peer.bad*total) >= 3*total*peerTotal
}

func (g *relayQualityGroup) observeProbes(probes []probeResult, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastEvaluation.IsZero() {
		g.lastEvaluation = now
	}
	newWindow := now.Sub(g.lastEvaluation) >= relayWindow
	if newWindow {
		g.lastEvaluation = now
	}
	signals := make([]relayQualitySignals, len(g.targets))
	for i := range g.targets {
		q := &g.targets[i]
		if !probes[i].at.IsZero() {
			q.addProbe(probes[i])
		}
		success, loss, median, baseline := q.probeSummary(now)
		sources, good, bad := q.passiveSummary(now)
		sig := relayQualitySignals{median, baseline, loss, sources, good, bad}
		signals[i] = sig
		q.stats = shared.RelayStats{
			ProbeSuccesses: success, MedianMS: min(3500, median.Milliseconds()), BaselineMS: min(3500, baseline.Milliseconds()),
			PassiveBadPercent: int(sig.badRatio()*100 + .5), PassiveSamples: sources,
		}
	}
	for i, sig := range signals {
		q := &g.targets[i]
		if q.state == shared.RelayDown {
			continue
		}
		var best time.Duration
		peerPassive := false
		var worstPeer relayQualitySignals
		for j, peer := range signals {
			if i == j || g.targets[j].state == shared.RelayDown {
				continue
			}
			if peer.median > 0 && (best == 0 || peer.median < best) {
				best = peer.median
			}
			if peer.sources >= relayPassiveMinSources && (!peerPassive ||
				peer.bad*(worstPeer.good+worstPeer.bad) > worstPeer.bad*(peer.good+peer.bad)) {
				peerPassive = true
				worstPeer = peer
			}
		}
		if q.state == shared.RelayProbation {
			p := probes[i]
			if !p.at.IsZero() && p.at.After(q.since) && p.at.After(q.probationProbeAt) {
				previous := q.probationProbeAt
				if previous.IsZero() {
					previous = q.since
				}
				q.probationUnclean = q.probationUnclean || !p.ok || p.at.Sub(previous) > 2*healthInterval ||
					relaySlowHandshake(p.elapsed, sig.baseline, best)
				q.probationProbeAt = p.at
			}
		}
		reason := ""
		switch {
		case sig.loss >= 3:
			reason = "probe_loss"
		case relaySlowHandshake(sig.median, sig.baseline, best):
			reason = "slow_handshake"
		case peerPassive && sig.sources >= relayPassiveMinSources && sig.bad >= sig.good && sig.passivelyWorseThan(worstPeer):
			reason = "blackhole"
		}
		q.evaluate(now, reason, newWindow)
	}
}

func relaySlowHandshake(sample, baseline, best time.Duration) bool {
	return best > 0 && baseline > 0 && sample > 3*baseline && sample-baseline >= 100*time.Millisecond &&
		2*sample > 5*best && sample-best >= 50*time.Millisecond
}

func (ref qualityRef) markDown(now time.Time) bool {
	g := ref.group
	g.mu.Lock()
	defer g.mu.Unlock()
	q := &g.targets[ref.index]
	q.streak = 0
	if q.state == shared.RelayDown {
		return false
	}
	q.fail("dial_failed", now)
	return true
}

func (ref qualityRef) status() (state, reason string, since time.Time, stats shared.RelayStats) {
	g := ref.group
	g.mu.Lock()
	defer g.mu.Unlock()
	q := &g.targets[ref.index]
	return q.state, q.reason, q.since, q.stats
}

func (ref qualityRef) currentState() string {
	g := ref.group
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.targets[ref.index].state
}
