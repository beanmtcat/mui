package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"mui/internal/shared"
)

// NodeTotals returns cumulative uplink and downlink per node ID.
func (s *Store) NodeTotals() (map[string][2]int64, error) {
	return s.totals(`SELECT node_id,uplink,downlink FROM mui_node_totals`)
}

func (s *Store) totals(query string) (map[string][2]int64, error) {
	rows, err := s.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var id string
		var a, b int64
		if err = rows.Scan(&id, &a, &b); err != nil {
			return nil, err
		}
		out[id] = [2]int64{a, b}
	}
	return out, rows.Err()
}

// PruneTraffic deletes raw samples older than the cutoff. Totals are unaffected.
func (s *Store) PruneTraffic(before time.Time) error {
	for _, table := range []string{"mui_traffic", "mui_server_traffic", "mui_user_traffic"} {
		if _, err := s.DB.Exec(`DELETE FROM `+table+` WHERE at_ms<$1`, before.UnixMilli()); err != nil {
			return err
		}
	}
	if _, err := s.DB.Exec(`DELETE FROM mui_subscription_access WHERE at_ms<$1`, before.UnixMilli()); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM mui_connection_ips WHERE at_ms<$1`, before.UnixMilli()); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM mui_entry_connection_ips WHERE at_ms<$1`, before.UnixMilli()); err != nil {
		return err
	}
	return nil
}

func (s *Store) SaveForwardTraffic(serverID string, points []shared.ForwardTrafficPoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	forwardIDs := make([]string, 0, len(points))
	for _, point := range points {
		forwardIDs = append(forwardIDs, point.ForwardID)
	}
	owned, err := ownedIDs(ctx, tx, "mui_forwards", serverID, forwardIDs)
	if err != nil {
		return err
	}
	for _, point := range points {
		if point.ForwardID == "" || point.InstanceID == "" || len(point.InstanceID) > 128 || point.Uplink < 0 || point.Downlink < 0 {
			continue
		}
		if !owned[point.ForwardID] {
			continue
		}
		var priorUp, priorDown int64
		err := tx.QueryRowContext(ctx, `SELECT uplink,downlink FROM mui_forward_counters WHERE forward_id=$1 AND instance_id=$2`, point.ForwardID, point.InstanceID).Scan(&priorUp, &priorDown)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		up, down := point.Uplink-priorUp, point.Downlink-priorDown
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mui_forward_counters(forward_id,instance_id,uplink,downlink) VALUES($1,$2,$3,$4) ON CONFLICT(forward_id,instance_id) DO UPDATE SET uplink=excluded.uplink,downlink=excluded.downlink`, point.ForwardID, point.InstanceID, max(point.Uplink, priorUp), max(point.Downlink, priorDown)); err != nil {
			return err
		}
		if up > 0 || down > 0 {
			if _, err = tx.ExecContext(ctx, `INSERT INTO mui_forward_totals(forward_id,uplink,downlink) VALUES($1,$2,$3) ON CONFLICT(forward_id) DO UPDATE SET uplink=mui_forward_totals.uplink+excluded.uplink,downlink=mui_forward_totals.downlink+excluded.downlink`, point.ForwardID, up, down); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) SaveTraffic(serverID string, points []shared.TrafficPoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nodeIDs := make([]string, 0, len(points))
	for _, p := range points {
		nodeIDs = append(nodeIDs, p.NodeID)
	}
	owned, err := ownedIDs(ctx, tx, "mui_nodes", serverID, nodeIDs)
	if err != nil {
		return err
	}
	for _, p := range points {
		if p.NodeID == "" || p.InstanceID == "" || len(p.InstanceID) > 128 || p.Uplink < 0 || p.Downlink < 0 || p.At.IsZero() {
			continue
		}
		if !owned[p.NodeID] {
			continue
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO mui_traffic(node_id,instance_id,sequence,uplink,downlink,at_ms) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node_id,instance_id,sequence) DO NOTHING`, p.NodeID, p.InstanceID, p.Sequence, p.Uplink, p.Downlink, p.At.UnixMilli())
		if err != nil {
			return err
		}
		// A re-sent sample inserts nothing and must not be counted twice.
		if inserted, _ := result.RowsAffected(); inserted == 0 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mui_node_totals(node_id,uplink,downlink) VALUES($1,$2,$3) ON CONFLICT(node_id) DO UPDATE SET uplink=mui_node_totals.uplink+excluded.uplink,downlink=mui_node_totals.downlink+excluded.downlink`, p.NodeID, p.Uplink, p.Downlink); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveUserTraffic(serverID string, points []shared.UserTrafficPoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nodeIDs := make([]string, 0, len(points))
	subIDs := make([]string, 0, len(points))
	for _, p := range points {
		nodeIDs = append(nodeIDs, p.NodeID)
		subIDs = append(subIDs, p.SubscriptionID)
	}
	owned, err := ownedIDs(ctx, tx, "mui_nodes", serverID, nodeIDs)
	if err != nil {
		return err
	}
	knownSubs, err := existingIDs(ctx, tx, "mui_subscriptions", subIDs)
	if err != nil {
		return err
	}
	for _, p := range points {
		if p.NodeID == "" || p.SubscriptionID == "" || p.InstanceID == "" || len(p.InstanceID) > 128 || p.Uplink < 0 || p.Downlink < 0 || p.At.IsZero() {
			continue
		}
		if !owned[p.NodeID] || !knownSubs[p.SubscriptionID] {
			continue
		}
		result, e := tx.ExecContext(ctx, `INSERT INTO mui_user_traffic(node_id,subscription_id,instance_id,sequence,uplink,downlink,at_ms) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node_id,subscription_id,instance_id,sequence) DO NOTHING`, p.NodeID, p.SubscriptionID, p.InstanceID, p.Sequence, p.Uplink, p.Downlink, p.At.UnixMilli())
		if e != nil {
			return e
		}
		if inserted, _ := result.RowsAffected(); inserted == 0 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mui_user_totals(node_id,subscription_id,uplink,downlink) VALUES($1,$2,$3,$4) ON CONFLICT(node_id,subscription_id) DO UPDATE SET uplink=mui_user_totals.uplink+excluded.uplink,downlink=mui_user_totals.downlink+excluded.downlink`, p.NodeID, p.SubscriptionID, p.Uplink, p.Downlink); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveServerTraffic(serverID string, points []shared.ServerTrafficPoint) error {
	unlock := s.lockCycleTraffic(serverID)
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var srv shared.Server
	var rawSrv string
	if scanErr := tx.QueryRowContext(ctx, `SELECT data FROM mui_servers WHERE id=$1`, serverID).Scan(&rawSrv); scanErr == nil {
		_ = json.Unmarshal([]byte(rawSrv), &srv)
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return scanErr
	}
	loc := s.timeLocation()
	cycleDelta := map[int64][2]int64{}
	var cycleOrder []int64

	for _, p := range points {
		if p.BootID == "" || len(p.BootID) > 128 || p.Interface == "" || len(p.Interface) > 128 || p.Sequence <= 0 || p.Rx < 0 || p.Tx < 0 || p.At.IsZero() {
			continue
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO mui_server_traffic(server_id,boot_id,sequence,interface,rx,tx,at_ms) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(server_id,boot_id,sequence) DO NOTHING`, serverID, p.BootID, p.Sequence, p.Interface, p.Rx, p.Tx, p.At.UnixMilli())
		if err != nil {
			return err
		}
		if inserted, _ := result.RowsAffected(); inserted == 0 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mui_server_totals(server_id,rx,tx) VALUES($1,$2,$3) ON CONFLICT(server_id) DO UPDATE SET rx=mui_server_totals.rx+excluded.rx,tx=mui_server_totals.tx+excluded.tx`, serverID, p.Rx, p.Tx); err != nil {
			return err
		}
		cycleStart, _ := serverTrafficCycleBounds(srv, p.At, loc)
		startMs := cycleStart.UTC().UnixMilli()
		cur, exists := cycleDelta[startMs]
		if !exists {
			cycleOrder = append(cycleOrder, startMs)
		}
		cycleDelta[startMs] = [2]int64{cur[0] + p.Rx, cur[1] + p.Tx}
	}

	for _, startMs := range cycleOrder {
		delta := cycleDelta[startMs]
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO mui_server_cycle_traffic(server_id,cycle_start_ms,rx,tx) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,cycle_start_ms) DO UPDATE SET rx=mui_server_cycle_traffic.rx+excluded.rx,tx=mui_server_cycle_traffic.tx+excluded.tx`,
			serverID, startMs, delta[0], delta[1],
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}
