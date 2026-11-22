package forward

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mui/internal/shared"
)

const (
	// StateFlushInterval is how often dirty per-route cycle counters are
	// atomically fsynced to disk. Quota hits, cycle rollovers, reloads, and
	// graceful shutdown flush immediately.
	StateFlushInterval = 5 * time.Second
	// entryProtectionPollInterval is how often the forwarder checks the local
	// entry-protection signal file written by mui-agent.
	entryProtectionPollInterval = 2 * time.Second
	minBucketBurst              = 32 * 1024
	maxBucketBurst              = 512 * 1024
	minPacedChunk               = 16 * 1024
	udpMaxWait                  = 50 * time.Millisecond
)

// EntryProtectionSignal is written by mui-agent/helper to notify mui-forward
// when entry server total traffic protection activates or clears locally.
type EntryProtectionSignal struct {
	Active       bool      `json:"active"`
	CycleStartMs int64     `json:"cycleStartMs,omitempty"`
	CycleEndMs   int64     `json:"cycleEndMs,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt,omitempty"`
}

// tokenBucket implements an aggregate byte rate limiter shared across all TCP
// connections and UDP sessions of a single route in one direction.
type tokenBucket struct {
	mu          sync.Mutex
	initialized bool
	rate        int64 // bytes per second; <=0 means unlimited
	burst       int64 // max burst in bytes
	tokens      float64
	last        time.Time
}

func newTokenBucket(rateBps int64, now time.Time) *tokenBucket {
	b := &tokenBucket{}
	b.setRateLocked(rateBps, now)
	return b
}

func bucketBurstFor(rateBps int64) int64 {
	if rateBps <= 0 {
		return 0
	}
	burst := rateBps / 10 // ~100ms burst
	if burst < minBucketBurst {
		burst = minBucketBurst
	}
	if burst > maxBucketBurst {
		burst = maxBucketBurst
	}
	return burst
}

func (b *tokenBucket) setRate(rateBps int64, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setRateLocked(rateBps, now)
}

func (b *tokenBucket) setRateLocked(rateBps int64, now time.Time) {
	if !b.initialized {
		b.initialized = true
		b.last = now
		b.rate = rateBps
		b.burst = bucketBurstFor(rateBps)
		b.tokens = float64(b.burst)
		return
	}
	b.refillLocked(now)
	prevRate := b.rate
	b.rate = rateBps
	b.burst = bucketBurstFor(rateBps)
	if rateBps <= 0 {
		b.tokens = 0
		return
	}
	if prevRate <= 0 {
		// Transitioned from unlimited to limited: start with a fresh burst.
		b.tokens = float64(b.burst)
		return
	}
	// Unchanged or adjusted rate: preserve existing budget and any negative
	// rate debt; only clamp positive surplus to the new burst ceiling.
	if b.tokens > float64(b.burst) {
		b.tokens = float64(b.burst)
	}
}

func (b *tokenBucket) refillLocked(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		b.tokens = float64(b.burst)
		return
	}
	if now.After(b.last) && b.rate > 0 {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * float64(b.rate)
		if b.tokens > float64(b.burst) {
			b.tokens = float64(b.burst)
		}
		b.last = now
	}
}

func (b *tokenBucket) rateBps() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate
}

func (b *tokenBucket) chunkSizeLocked() int64 {
	if b.rate <= 0 {
		return copyChunk
	}
	chunk := b.rate / 20 // ~50ms per chunk
	if chunk < minPacedChunk {
		chunk = minPacedChunk
	}
	if chunk > copyChunk {
		chunk = copyChunk
	}
	return chunk
}

// reserve claims up to maxBytes BEFORE sending so concurrent short connections
// cannot each send a free chunk and bypass the aggregate rate cap. Callers
// should call refund(granted - actual) if fewer bytes were transferred.
func (b *tokenBucket) reserve(done <-chan struct{}, maxBytes int64, nowFn func() time.Time) (int64, bool) {
	if b == nil || maxBytes <= 0 {
		return maxBytes, true
	}
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return maxBytes, true
	}
	want := maxBytes
	if chunk := b.chunkSizeLocked(); want > chunk {
		want = chunk
	}
	now := nowFn()
	b.refillLocked(now)
	b.tokens -= float64(want)
	var waitDur time.Duration
	if b.tokens < 0 {
		waitDur = time.Duration((-b.tokens / float64(b.rate)) * float64(time.Second))
	}
	b.mu.Unlock()
	if waitDur <= 0 {
		return want, true
	}
	timer := time.NewTimer(waitDur)
	defer timer.Stop()
	select {
	case <-done:
		b.refund(want)
		return 0, false
	case <-timer.C:
		return want, true
	}
}

// waitPre reserves n exact bytes BEFORE writing them (used by relay_passive
// first-packet paths where n is already known).
func (b *tokenBucket) waitPre(done <-chan struct{}, n int64, nowFn func() time.Time) bool {
	if b == nil || n <= 0 {
		return true
	}
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return true
	}
	now := nowFn()
	b.refillLocked(now)
	b.tokens -= float64(n)
	var waitDur time.Duration
	if b.tokens < 0 {
		waitDur = time.Duration((-b.tokens / float64(b.rate)) * float64(time.Second))
	}
	b.mu.Unlock()
	if waitDur <= 0 {
		return true
	}
	timer := time.NewTimer(waitDur)
	defer timer.Stop()
	select {
	case <-done:
		b.refund(n)
		return false
	case <-timer.C:
		return true
	}
}

// refund returns unused reserved tokens (e.g. when a short connection closes
// or a read times out after transferring fewer bytes than reserved).
func (b *tokenBucket) refund(unused int64) {
	if b == nil || unused <= 0 {
		return
	}
	b.mu.Lock()
	if b.rate > 0 {
		b.tokens += float64(unused)
		if b.tokens > float64(b.burst) {
			b.tokens = float64(b.burst)
		}
	}
	b.mu.Unlock()
}

// allowUDP enforces the aggregate rate limit for a UDP datagram BEFORE
// forwarding. Short waits (<= udpMaxWait) are paced smoothly; excessive bursts
// are dropped so a single UDP flood cannot stall the listener loop or bypass
// the aggregate cap.
func (b *tokenBucket) allowUDP(done <-chan struct{}, n int64, nowFn func() time.Time) bool {
	if b == nil || n <= 0 {
		return true
	}
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return true
	}
	now := nowFn()
	b.refillLocked(now)
	if b.tokens-float64(n) >= 0 {
		b.tokens -= float64(n)
		b.mu.Unlock()
		return true
	}
	need := float64(n) - b.tokens
	waitDur := time.Duration((need / float64(b.rate)) * float64(time.Second))
	if waitDur > udpMaxWait {
		b.mu.Unlock()
		return false
	}
	b.tokens -= float64(n)
	b.mu.Unlock()
	timer := time.NewTimer(waitDur)
	defer timer.Stop()
	select {
	case <-done:
		b.refund(n)
		return false
	case <-timer.C:
		return true
	}
}

// limitGroup enforces periodic traffic quota and aggregate up/down rate limits
// across all entry-hop listeners (TCP + UDP) belonging to one route.
type limitGroup struct {
	mu                     sync.Mutex
	routeID                string
	configured             bool
	limit                  int64
	limitType              string
	resetDay               int
	tzName                 string
	tzOffset               int
	cycleStartMs           int64
	cycleEndMs             int64
	up                     int64
	down                   int64
	autoPaused             bool
	pausedAt               time.Time
	entryBlocked           bool
	entryBlockedCycleStart int64
	entryBlockedCycleEnd   int64
	upBucket               *tokenBucket
	downBucket             *tokenBucket
	rules                  map[*rule]struct{}
	dirty                  bool
}

type persistedLimitState struct {
	Version int                        `json:"version"`
	SavedAt time.Time                  `json:"savedAt"`
	Routes  []shared.RouteTrafficState `json:"routes"`
}

func newLimitGroup(routeID string, now time.Time) *limitGroup {
	return &limitGroup{
		routeID:    routeID,
		limitType:  "sum",
		upBucket:   newTokenBucket(0, now),
		downBucket: newTokenBucket(0, now),
		rules:      map[*rule]struct{}{},
	}
}

func (g *limitGroup) quotaLimit() int64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit
}

func (g *limitGroup) location() *time.Location {
	return shared.ResolveTrafficLocation(g.tzName, g.tzOffset, time.Local)
}

func (g *limitGroup) clearExpiredEntryBlockLocked(now time.Time, rolledOver bool) {
	if !g.entryBlocked {
		return
	}
	if g.entryBlockedCycleEnd > 0 {
		if now.UTC().UnixMilli() >= g.entryBlockedCycleEnd {
			g.entryBlocked = false
			g.entryBlockedCycleStart = 0
			g.entryBlockedCycleEnd = 0
			g.dirty = true
		}
		return
	}
	if rolledOver {
		g.entryBlocked = false
		g.entryBlockedCycleStart = 0
		g.dirty = true
	}
}

func (g *limitGroup) ensureCycleLocked(now time.Time) (rolledOver bool) {
	// If this group was loaded from disk for a route that is currently disabled
	// (not active in Reload), preserve its persisted cycle window until its
	// stored cycleEndMs actually passes so a restart never wipes disabled usage.
	if !g.configured && g.cycleStartMs > 0 && g.cycleEndMs > 0 {
		if now.UTC().UnixMilli() < g.cycleEndMs {
			return false
		}
	}
	loc := g.location()
	start, end := shared.MonthlyCycleBounds(now, g.resetDay, loc)
	startMs := start.UTC().UnixMilli()
	endMs := end.UTC().UnixMilli()
	if g.cycleStartMs == 0 {
		g.cycleStartMs = startMs
		g.cycleEndMs = endMs
		return false
	}
	if startMs != g.cycleStartMs {
		// New billing cycle (or reset day moved to a different cycle): reset
		// cycle counters and clear auto-paused state.
		g.cycleStartMs = startMs
		g.cycleEndMs = endMs
		g.up = 0
		g.down = 0
		g.autoPaused = false
		g.pausedAt = time.Time{}
		g.dirty = true
		return true
	}
	g.cycleEndMs = endMs
	return false
}

func (g *limitGroup) configure(spec shared.ForwardRule, now time.Time) (shouldClose bool, flushed bool) {
	g.mu.Lock()
	g.configured = true
	g.limit = spec.RouteTrafficLimit
	lt := spec.RouteTrafficLimitType
	if lt == "" {
		lt = "sum"
	}
	g.limitType = lt
	g.resetDay = spec.RouteTrafficResetDay
	g.tzName = spec.RouteTrafficTimezone
	g.tzOffset = spec.RouteTrafficTZOffset
	g.entryBlocked = spec.EntryProtectionBlocked
	g.entryBlockedCycleStart = spec.EntryProtectionCycleStart
	g.entryBlockedCycleEnd = spec.EntryProtectionCycleEnd

	rolled := g.ensureCycleLocked(now)
	g.clearExpiredEntryBlockLocked(now, rolled)
	if spec.RouteTrafficBaselineCycleStart > 0 && spec.RouteTrafficBaselineCycleStart == g.cycleStartMs {
		if spec.RouteTrafficBaselineUp > g.up {
			g.up = spec.RouteTrafficBaselineUp
			g.dirty = true
		}
		if spec.RouteTrafficBaselineDown > g.down {
			g.down = spec.RouteTrafficBaselineDown
			g.dirty = true
		}
	}

	g.upBucket.setRate(spec.RouteUpSpeedLimitBps, now)
	g.downBucket.setRate(spec.RouteDownSpeedLimitBps, now)

	used := shared.ComputeRouteTrafficUsed(g.up, g.down, g.limitType)
	if g.limit > 0 && used >= g.limit {
		if !g.autoPaused {
			g.autoPaused = true
			g.pausedAt = now.UTC()
			g.dirty = true
			flushed = true
		}
		shouldClose = true
	} else if g.autoPaused {
		// Quota was increased or removed; resume automatically.
		g.autoPaused = false
		g.pausedAt = time.Time{}
		g.dirty = true
		flushed = true
	}
	if g.entryBlocked {
		shouldClose = true
	}
	if rolled {
		flushed = true
	}
	g.mu.Unlock()
	if shouldClose {
		g.closeActiveConnections()
	}
	return shouldClose, flushed
}

func (g *limitGroup) attachRule(r *rule) {
	g.mu.Lock()
	g.rules[r] = struct{}{}
	g.mu.Unlock()
}

func (g *limitGroup) detachRule(r *rule) {
	g.mu.Lock()
	delete(g.rules, r)
	g.mu.Unlock()
}

func (g *limitGroup) closeActiveConnections() {
	g.mu.Lock()
	rules := make([]*rule, 0, len(g.rules))
	for r := range g.rules {
		rules = append(rules, r)
	}
	g.mu.Unlock()
	for _, r := range rules {
		r.closeActive()
	}
}

func (g *limitGroup) blocked(now time.Time, serviceEntryBlocked bool) (isBlocked bool, rolledOver bool) {
	g.mu.Lock()
	rolledOver = g.ensureCycleLocked(now)
	g.clearExpiredEntryBlockLocked(now, rolledOver)
	if g.limit > 0 {
		used := shared.ComputeRouteTrafficUsed(g.up, g.down, g.limitType)
		if used >= g.limit {
			if !g.autoPaused {
				g.autoPaused = true
				g.pausedAt = now.UTC()
				g.dirty = true
			}
		} else if g.autoPaused {
			g.autoPaused = false
			g.pausedAt = time.Time{}
			g.dirty = true
		}
	}
	isBlocked = serviceEntryBlocked || g.entryBlocked || (g.limit > 0 && g.autoPaused)
	g.mu.Unlock()
	return isBlocked, rolledOver
}

func (g *limitGroup) record(upDelta, downDelta int64, now time.Time) (newlyExceeded bool, rolledOver bool) {
	if upDelta <= 0 && downDelta <= 0 {
		return false, false
	}
	g.mu.Lock()
	rolledOver = g.ensureCycleLocked(now)
	g.clearExpiredEntryBlockLocked(now, rolledOver)
	if upDelta > 0 {
		g.up += upDelta
	}
	if downDelta > 0 {
		g.down += downDelta
	}
	g.dirty = true
	if g.limit > 0 && !g.autoPaused {
		used := shared.ComputeRouteTrafficUsed(g.up, g.down, g.limitType)
		if used >= g.limit {
			g.autoPaused = true
			g.pausedAt = now.UTC()
			newlyExceeded = true
		}
	}
	g.mu.Unlock()
	if newlyExceeded {
		g.closeActiveConnections()
	}
	return newlyExceeded, rolledOver
}

func (g *limitGroup) snapshot(instanceID string, now time.Time) shared.RouteTrafficState {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureCycleLocked(now)
	var pausedAt *time.Time
	if g.autoPaused && !g.pausedAt.IsZero() {
		t := g.pausedAt
		pausedAt = &t
	}
	used := shared.ComputeRouteTrafficUsed(g.up, g.down, g.limitType)
	return shared.RouteTrafficState{
		RouteID:      g.routeID,
		CycleStartMs: g.cycleStartMs,
		CycleEndMs:   g.cycleEndMs,
		Uplink:       g.up,
		Downlink:     g.down,
		Used:         used,
		Limit:        g.limit,
		LimitType:    g.limitType,
		ResetDay:     g.resetDay,
		Timezone:     g.tzName,
		TZOffset:     g.tzOffset,
		Paused:       g.limit > 0 && g.autoPaused,
		PausedAt:     pausedAt,
		InstanceID:   instanceID,
		UpdatedAt:    now.UTC(),
	}
}

func (g *limitGroup) consumeDirty() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.dirty {
		return false
	}
	g.dirty = false
	return true
}

func isEntryRouteRule(spec shared.ForwardRule) bool {
	return spec.RouteID != "" && (spec.EntryHop || spec.ObserveClients || spec.RouteTrafficLimit > 0 || spec.RouteUpSpeedLimitBps > 0 || spec.RouteDownSpeedLimitBps > 0 || spec.EntryProtectionBlocked)
}

func (s *Service) now() time.Time {
	if fn := s.nowFn.Load(); fn != nil && *fn != nil {
		return (*fn)()
	}
	return time.Now()
}

// SetClock overrides the clock used for cycle boundaries and rate limiting (for tests).
func (s *Service) SetClock(fn func() time.Time) {
	if fn == nil {
		s.nowFn.Store(nil)
		return
	}
	f := fn
	s.nowFn.Store(&f)
}

// SetStatePath configures persistent storage for per-route cycle counters and
// loads any existing state from disk.
func (s *Service) SetStatePath(path string) error {
	s.mu.Lock()
	s.statePath = path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	return s.loadLimitState(path)
}

// SetEntryProtectionPath configures a local signal file written by mui-agent
// to block/unblock all entry-hop routes when entry total traffic protection fires.
func (s *Service) SetEntryProtectionPath(path string) {
	s.mu.Lock()
	s.entryProtectionPath = path
	s.mu.Unlock()
	if path != "" {
		s.pollEntryProtectionFile()
	}
}

// SetEntryProtectionBlocked sets the local/offline entry-hop block state
// (owned by runOfflineEntryProtectionLoop and direct callers). It is kept
// independent from the online signal file so online signal polling never
// overwrites offline entry protection.
func (s *Service) SetEntryProtectionBlocked(blocked bool) {
	s.offlineEntryBlocked.Store(blocked)
	s.syncEntryBlocked()
}

func (s *Service) setOnlineEntryProtectionBlocked(blocked bool) {
	s.onlineEntryBlocked.Store(blocked)
	s.syncEntryBlocked()
}

func (s *Service) syncEntryBlocked() {
	effective := s.onlineEntryBlocked.Load() || s.offlineEntryBlocked.Load()
	prev := s.entryBlocked.Swap(effective)
	if effective && !prev {
		s.closeAllEntryConnections()
	}
}

func (s *Service) closeAllEntryConnections() {
	s.mu.Lock()
	groups := make([]*limitGroup, 0, len(s.limitGroups))
	for _, g := range s.limitGroups {
		groups = append(groups, g)
	}
	entryRules := make([]*rule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.entryHop.Load() {
			entryRules = append(entryRules, r)
		}
	}
	s.mu.Unlock()
	for _, g := range groups {
		g.closeActiveConnections()
	}
	for _, r := range entryRules {
		r.closeActive()
	}
}

func (s *Service) limitGroupFor(spec shared.ForwardRule) *limitGroup {
	if !isEntryRouteRule(spec) {
		return nil
	}
	now := s.now()
	g := s.limitGroups[spec.RouteID]
	if g == nil {
		g = newLimitGroup(spec.RouteID, now)
		s.limitGroups[spec.RouteID] = g
	}
	return g
}

func (s *Service) triggerStateFlush() {
	select {
	case s.flushCh <- struct{}{}:
	default:
	}
}

// RouteTrafficSnapshot returns the current per-route cycle counters and pause states.
func (s *Service) RouteTrafficSnapshot(instanceID string) []shared.RouteTrafficState {
	s.mu.Lock()
	groups := make([]*limitGroup, 0, len(s.limitGroups))
	for _, g := range s.limitGroups {
		groups = append(groups, g)
	}
	s.mu.Unlock()
	now := s.now()
	out := make([]shared.RouteTrafficState, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.snapshot(instanceID, now))
	}
	return out
}

func (s *Service) loadLimitState(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc persistedLimitState
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range doc.Routes {
		if item.RouteID == "" || item.CycleStartMs <= 0 {
			continue
		}
		g := s.limitGroups[item.RouteID]
		if g == nil {
			g = newLimitGroup(item.RouteID, now)
			s.limitGroups[item.RouteID] = g
		}
		g.mu.Lock()
		if g.cycleStartMs == 0 || item.CycleStartMs > g.cycleStartMs {
			g.cycleStartMs = item.CycleStartMs
			g.cycleEndMs = item.CycleEndMs
			g.up = item.Uplink
			g.down = item.Downlink
			g.autoPaused = item.Paused
			if item.Limit > 0 {
				g.limit = item.Limit
			}
			if item.LimitType != "" {
				g.limitType = item.LimitType
			}
			if item.ResetDay > 0 {
				g.resetDay = item.ResetDay
			}
			if item.Timezone != "" {
				g.tzName = item.Timezone
			}
			if item.TZOffset != 0 {
				g.tzOffset = item.TZOffset
			}
			if item.PausedAt != nil {
				g.pausedAt = *item.PausedAt
			}
		} else if item.CycleStartMs == g.cycleStartMs {
			if item.Uplink > g.up {
				g.up = item.Uplink
			}
			if item.Downlink > g.down {
				g.down = item.Downlink
			}
			if item.Paused && !g.autoPaused {
				g.autoPaused = true
				if item.PausedAt != nil {
					g.pausedAt = *item.PausedAt
				}
			}
		}
		g.mu.Unlock()
	}
	return nil
}

// FlushLimitState atomically writes all per-route cycle states to statePath.
func (s *Service) FlushLimitState(force bool) error {
	s.mu.Lock()
	path := s.statePath
	if path == "" {
		s.mu.Unlock()
		return nil
	}
	groups := make([]*limitGroup, 0, len(s.limitGroups))
	for _, g := range s.limitGroups {
		groups = append(groups, g)
	}
	s.mu.Unlock()

	dirty := force
	for _, g := range groups {
		if g.consumeDirty() {
			dirty = true
		}
	}
	if !dirty {
		return nil
	}
	now := s.now()
	routes := make([]shared.RouteTrafficState, 0, len(groups))
	for _, g := range groups {
		routes = append(routes, g.snapshot("", now))
	}
	doc := persistedLimitState{Version: 1, SavedAt: now.UTC(), Routes: routes}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mui-traffic-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Service) persistLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(StateFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			_ = s.FlushLimitState(true)
			return
		case <-s.flushCh:
			_ = s.FlushLimitState(false)
		case <-ticker.C:
			_ = s.FlushLimitState(false)
		}
	}
}

func (s *Service) pollEntryProtectionFile() {
	s.mu.Lock()
	path := s.entryProtectionPath
	s.mu.Unlock()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.setOnlineEntryProtectionBlocked(false)
		}
		return
	}
	var sig EntryProtectionSignal
	if err := json.Unmarshal(raw, &sig); err != nil {
		return
	}
	active := sig.Active
	if active && sig.CycleEndMs > 0 && s.now().UTC().UnixMilli() >= sig.CycleEndMs {
		active = false
	}
	s.setOnlineEntryProtectionBlocked(active)
}

func (s *Service) entryProtectionLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(entryProtectionPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.pollEntryProtectionFile()
		}
	}
}
