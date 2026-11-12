package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"mui/internal/shared"
)

func (s *Store) Operation(id string) (shared.Operation, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_operations WHERE id=$1`, id).Scan(&raw)
	var v shared.Operation
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

// PutOperation queues a job. The desired state carries node passwords and
// certificate keys, so it is encrypted like every other secret column.
func (s *Store) PutOperation(v shared.Operation, state shared.DesiredState) error {
	sealed, err := s.Encrypt(Marshal(state))
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO mui_operations(id,server_id,data,state) VALUES($1,$2,$3,$4)`, v.ID, v.ServerID, Marshal(v), sealed)
	return err
}

// SupersedeQueuedApply keeps the newest desired configuration authoritative.
// A running job is left alone; its stale revision cannot mark nodes active.
func (s *Store) SupersedeQueuedApply(serverID string) error {
	rows, err := s.DB.Query(`SELECT id,data FROM mui_operations WHERE server_id=$1 AND claimed_at=0`, serverID)
	if err != nil {
		return err
	}
	type pending struct {
		id string
		op shared.Operation
	}
	items := []pending{}
	for rows.Next() {
		var id, raw string
		if err = rows.Scan(&id, &raw); err != nil {
			break
		}
		var op shared.Operation
		if err = json.Unmarshal([]byte(raw), &op); err != nil {
			break
		}
		if op.Status == "queued" && strings.HasSuffix(op.Kind, ".apply") {
			items = append(items, pending{id, op})
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		item.op.Status = "superseded"
		item.op.UpdatedAt = time.Now()
		if _, err = s.DB.Exec(`UPDATE mui_operations SET data=$1,state='',claimed_at=-1 WHERE id=$2 AND claimed_at=0`, Marshal(item.op), item.id); err != nil {
			return err
		}
	}
	return nil
}

// ClaimJob hands the oldest claimable job to the agent. allowApply=false
// (an agent that cannot apply firewall policies) skips *.apply jobs instead
// of blocking the queue, so upgrade and init jobs behind them still flow.
// Every claim mints a fresh fencing token that the agent must echo in its
// report; a stale or replayed report carries the wrong token and is refused.
// Upgrade jobs get a 30-minute claim window (slow downloads); other jobs 5.
func (s *Store) ClaimJob(serverID string, allowApply bool) (*shared.Job, error) {
	{
		rows, err := s.DB.Query(`SELECT id,data,state,claimed_at FROM mui_operations WHERE server_id=$1 AND claimed_at>=0 ORDER BY id LIMIT 50`, serverID)
		if err != nil {
			return nil, err
		}
		type candidate struct {
			id, raw, stateRaw string
			claimedAt         int64
		}
		candidates := []candidate{}
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.id, &c.raw, &c.stateRaw, &c.claimedAt); err != nil {
				rows.Close()
				return nil, err
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		for _, c := range candidates {
			var op shared.Operation
			if err := json.Unmarshal([]byte(c.raw), &op); err != nil {
				return nil, err
			}
			if op.Status == "success" || op.Status == "failed" {
				_, _ = s.DB.Exec(`UPDATE mui_operations SET state='',claimed_at=-1 WHERE id=$1`, c.id)
				continue
			}
			if !allowApply && strings.HasSuffix(op.Kind, ".apply") {
				continue
			}
			window := 5 * time.Minute
			if op.Kind == "agent.upgrade" || op.Kind == "core.upgrade" {
				window = 30 * time.Minute
			}
			if c.claimedAt > 0 && c.claimedAt >= time.Now().Add(-window).UnixMilli() {
				continue // Still owned by a live claim.
			}
			var state shared.DesiredState
			stateRaw := c.stateRaw
			if clear, e := s.Decrypt(stateRaw); e == nil {
				stateRaw = clear
			} // else: a job queued before state encryption, still plain JSON
			if err := json.Unmarshal([]byte(stateRaw), &state); err != nil {
				return nil, err
			}
			op.FencingToken = Token()
			op.Status = "running"
			op.UpdatedAt = time.Now()
			now := time.Now().UnixMilli()
			result, err := s.DB.Exec(`UPDATE mui_operations SET claimed_at=$1,data=$2 WHERE id=$3 AND claimed_at=$4`, now, Marshal(op), c.id, c.claimedAt)
			if err != nil {
				return nil, err
			}
			affected, _ := result.RowsAffected()
			if affected == 0 {
				continue // Lost a race to another claimer; try the next job.
			}
			return &shared.Job{ID: c.id, ServerID: serverID, Kind: op.Kind, State: state, FencingToken: op.FencingToken}, nil
		}
		// No claimable job right now (or every candidate was terminal and got
		// cleared above).
		return nil, nil
	}
}

func (s *Store) FinishJob(id, status, message string) error {
	op, err := s.Operation(id)
	if err != nil {
		return err
	}
	op.Status = status
	op.Error = message
	op.UpdatedAt = time.Now()
	_, err = s.DB.Exec(`UPDATE mui_operations SET data=$1,state='',claimed_at=-1 WHERE id=$2`, Marshal(op), id)
	return err
}

func (s *Store) MarkUpgradeActivating(id string) error {
	op, err := s.Operation(id)
	if err != nil {
		return err
	}
	if op.Kind != "agent.upgrade" || op.Status != "running" {
		return errors.New("Agent upgrade is not running")
	}
	op.Status = "activating"
	op.UpdatedAt = time.Now()
	_, err = s.DB.Exec(`UPDATE mui_operations SET data=$1,claimed_at=-1 WHERE id=$2`, Marshal(op), id)
	return err
}

// The upgrade is complete only after the restarted Agent reports its new hash.
// When the agent supplies buildDigest (the hex SHA-256 of the binary it is
// running), it must equal the queued upgrade's target hash; a self-reported
// build string alone is not proof that the new binary is installed.
func (s *Store) CompleteUpgradeByBuild(serverID, build, digest string) error {
	rows, err := s.DB.Query(`SELECT data FROM mui_operations WHERE server_id=$1 AND state<>'' ORDER BY id DESC`, serverID)
	if err != nil {
		return err
	}
	var complete []string
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var op shared.Operation
		if json.Unmarshal([]byte(raw), &op) == nil && op.Kind == "agent.upgrade" && op.TargetBuild == build && (op.Status == "running" || op.Status == "activating") {
			if digest != "" && digest != op.TargetBuild {
				continue // Claims the new build but proves a different binary.
			}
			complete = append(complete, op.ID)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range complete {
		if err = s.FinishJob(id, "success", ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ExpireUpgrades() error {
	rows, err := s.DB.Query(`SELECT data FROM mui_operations WHERE claimed_at=-1 AND state<>'' ORDER BY id DESC`)
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var op shared.Operation
		if json.Unmarshal([]byte(raw), &op) == nil && op.Kind == "agent.upgrade" && op.Status == "activating" && time.Since(op.UpdatedAt) > 5*time.Minute {
			expired = append(expired, op.ID)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range expired {
		if err = s.FinishJob(id, "failed", "升级后 5 分钟内未收到新版 Agent 上报；请检查目标服务器服务状态"); err != nil {
			return err
		}
	}
	return nil
}

// PruneOperations deletes terminal operations (claimed_at=-1 and state='')
// created before the cutoff, using the hex-encoded UnixNano timestamp prefix
// of operation IDs without parsing JSON payloads.
func (s *Store) PruneOperations(before time.Time) error {
	cutoff := before.UnixNano()
	if cutoff <= 0 {
		return nil
	}
	_, err := s.DB.Exec(`DELETE FROM mui_operations WHERE claimed_at=-1 AND state='' AND id<$1`, fmt.Sprintf("%016x", cutoff))
	return err
}
