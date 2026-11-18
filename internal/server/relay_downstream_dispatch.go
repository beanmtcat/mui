package server

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

// Dispatch runs after releasing the reporting server's lock. Two agents on
// opposite legs can report concurrently without locking each other out.
func (a *App) dispatchDownstream(reporterID string) {
	a.relayDownstreamDispatchMu.Lock()
	defer a.relayDownstreamDispatchMu.Unlock()

	reporter, err := a.Store.Server(reporterID)
	if err != nil || len(reporter.RelayDownstreamPending) == 0 {
		return
	}
	completed := make(map[string]time.Time, len(reporter.RelayDownstreamPending))
	for previous, generation := range reporter.RelayDownstreamPending {
		unlock := a.lockServer(previous)
		source, err := a.Store.Server(previous)
		if err == nil && downstreamEligible(source) && source.ForwardSupport {
			err = a.queueApplyLocked(previous, "forwards.apply")
		}
		unlock()
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.Printf("queue relay downstream %s via %s: %v", reporterID, previous, err)
			continue
		}
		completed[previous] = generation
	}
	if len(completed) == 0 {
		return
	}

	unlock := a.lockServer(reporterID)
	defer unlock()
	current, err := a.Store.Server(reporterID)
	if err != nil {
		return
	}
	for previous, generation := range completed {
		if current.RelayDownstreamPending[previous].Equal(generation) {
			delete(current.RelayDownstreamPending, previous)
		}
	}
	if err = a.Store.PutServer(current); err != nil {
		log.Printf("ack relay downstream %s: %v", reporterID, err)
	}
}

// FlushRelayDownstream retries durable pending jobs and clears hints belonging
// to a changed topology or a server that ceased to be managed online.
func (a *App) FlushRelayDownstream() {
	servers, err := a.Store.Servers()
	if err != nil {
		log.Printf("list relay downstream sources: %v", err)
		return
	}
	var tracked []string
	for _, s := range servers {
		if len(s.RelayDownstream) > 0 || len(s.RelayDownstreamPending) > 0 {
			tracked = append(tracked, s.ID)
		}
	}
	if len(tracked) == 0 {
		return
	}
	a.mu.Lock()
	world, err := a.loadRouteWorld()
	if err != nil {
		a.mu.Unlock()
		log.Printf("reconcile relay downstream: %v", err)
		return
	}
	topology := world.downstreamTopology("")
	for _, id := range tracked {
		unlock := a.lockServer(id)
		s, err := a.Store.Server(id)
		snapshot := world.servers[id]
		newReport := s.LastSeen != nil && (snapshot.LastSeen == nil || s.LastSeen.After(*snapshot.LastSeen))
		if err == nil && !newReport && reconcileDownstream(&s, topology, time.Now()) {
			if err = a.Store.PutServer(s); err != nil {
				log.Printf("reconcile relay downstream %s: %v", id, err)
			}
		}
		unlock()
	}
	a.mu.Unlock()
	for _, id := range tracked {
		a.dispatchDownstream(id)
	}
}
