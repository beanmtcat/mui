package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"mui/internal/shared"
)

func (s *Store) Customers() ([]shared.Customer, error) {
	return queryJSON[shared.Customer](s.DB, `SELECT data FROM mui_customers ORDER BY id`)
}

func (s *Store) Customer(id string) (shared.Customer, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_customers WHERE id=$1`, id).Scan(&raw)
	var out shared.Customer
	if err == nil {
		err = json.Unmarshal([]byte(raw), &out)
	}
	return out, err
}

func (a *App) validCustomer(id string) bool {
	if id == "" {
		return true
	}
	_, err := a.Store.Customer(id)
	return err == nil
}

func (a *App) customers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Customers()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(c shared.Customer) string { return c.ID })
		return
	}
	var in shared.Customer
	if !readJSON(w, r, &in) {
		return
	}
	in.Name, in.Notes = strings.TrimSpace(in.Name), strings.TrimSpace(in.Notes)
	if in.Name == "" || len(in.Name) > 100 || len(in.Notes) > 1000 {
		errorJSON(w, 400, "客户名称或备注无效")
		return
	}
	in.ID, in.CreatedAt = ID(), time.Now().UTC()
	if _, err := a.Store.DB.Exec(`INSERT INTO mui_customers(id,data) VALUES($1,$2)`, in.ID, Marshal(in)); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("customer.create", in.ID, in.Name)
	writeJSON(w, 201, in)
}

func (a *App) customerByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.Customer(id)
	if errors.Is(err, sql.ErrNoRows) {
		errorJSON(w, 404, "客户不存在")
		return
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if r.Method == "DELETE" {
		subs, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, sub := range subs {
			if sub.CustomerID == id {
				errorJSON(w, 409, "客户仍有关联订阅，请先解除关联")
				return
			}
		}
		if _, err := a.Store.DB.Exec(`DELETE FROM mui_customers WHERE id=$1`, id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("customer.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in shared.Customer
	if !readJSON(w, r, &in) {
		return
	}
	in.Name, in.Notes = strings.TrimSpace(in.Name), strings.TrimSpace(in.Notes)
	if in.Name == "" || len(in.Name) > 100 || len(in.Notes) > 1000 {
		errorJSON(w, 400, "客户名称或备注无效")
		return
	}
	old.Name, old.Notes = in.Name, in.Notes
	if _, err := a.Store.DB.Exec(`UPDATE mui_customers SET data=$1 WHERE id=$2`, Marshal(old), id); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("customer.update", id, old.Name)
	writeJSON(w, 200, old)
}

func (a *App) accessLog(query *logQuery, limit, offset int) ([]shared.SubscriptionAccess, error) {
	out := []shared.SubscriptionAccess{}
	rows, err := a.Store.DB.Query(query.sql("id DESC", limit, offset), query.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item shared.SubscriptionAccess
		var at int64
		if err = rows.Scan(&item.ID, &item.SubscriptionID, &item.CustomerID, &item.IP, &at); err != nil {
			return nil, err
		}
		item.At = time.UnixMilli(at).UTC()
		out = append(out, item)
	}
	return out, rows.Err()
}

type connectionCursor struct {
	FirstSeenMs int64  `json:"firstSeenMs"`
	ServerID    string `json:"serverId"`
	NodeID      string `json:"nodeId"`
	IP          string `json:"ip"`
}

func (a *App) connectionLog(query *logQuery, limit, offset int) ([]shared.ConnectionIP, error) {
	out := []shared.ConnectionIP{}
	rows, err := a.Store.DB.Query(query.sql("first_seen_ms DESC, server_id DESC, node_id DESC, ip DESC", limit, offset), query.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item shared.ConnectionIP
		var at, firstSeen int64
		if err = rows.Scan(&item.ServerID, &item.NodeID, &item.IP, &at, &firstSeen); err != nil {
			return nil, err
		}
		item.LastSeen = time.UnixMilli(at).UTC()
		cursor, err := json.Marshal(connectionCursor{FirstSeenMs: firstSeen, ServerID: item.ServerID, NodeID: item.NodeID, IP: item.IP})
		if err != nil {
			return nil, err
		}
		item.Cursor = base64.RawURLEncoding.EncodeToString(cursor)
		out = append(out, item)
	}
	return out, rows.Err()
}

const accessColumns = `SELECT id,subscription_id,customer_id,ip,at_ms FROM mui_subscription_access`
const connectionColumns = `SELECT server_id,node_id,ip,at_ms,first_seen_ms FROM mui_connection_ips`

// clientAccesses lists subscription downloads, newest first. ?before= takes the
// ID of the last row already shown.
func (a *App) clientAccesses(w http.ResponseWriter, r *http.Request) {
	query, _ := newLogQuery(accessColumns)
	query.equal("customer_id", r.URL.Query().Get("customerId"))
	query.equal("subscription_id", r.URL.Query().Get("subscriptionId"))
	page, err := readLogPage(r)
	if err == nil {
		err = query.timeRange(r, "at_ms")
	}
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	limit, offset := pageLimit(r), 0
	if page.paged {
		limit, offset = page.size, page.offset()
	} else {
		query.before("id", r.URL.Query().Get("before"))
	}
	out, err := a.accessLog(query, limit, offset)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if page.paged {
		a.writeLogPage(w, query, out)
		return
	}
	writeJSON(w, 200, out)
}

// clientConnections pages by the immutable discovery order. Updating a last
// seen timestamp cannot move a row across a previously returned page.
func (a *App) clientConnections(w http.ResponseWriter, r *http.Request) {
	query, _ := newLogQuery(connectionColumns)
	query.equal("server_id", r.URL.Query().Get("serverId"))
	page, err := readLogPage(r)
	if err == nil {
		// The page shows when each address was last seen; filter on that.
		err = query.timeRange(r, "at_ms")
	}
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if before := r.URL.Query().Get("before"); before != "" && !page.paged {
		if len(before) > 512 {
			errorJSON(w, 400, "无效的连接记录游标")
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(before)
		var cursor connectionCursor
		if err != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.FirstSeenMs <= 0 || cursor.ServerID == "" || cursor.NodeID == "" || net.ParseIP(cursor.IP) == nil {
			errorJSON(w, 400, "无效的连接记录游标")
			return
		}
		query.where("(first_seen_ms,server_id,node_id,ip)<(" + query.arg(cursor.FirstSeenMs) + "," + query.arg(cursor.ServerID) + "," + query.arg(cursor.NodeID) + "," + query.arg(cursor.IP) + ")")
	}
	limit, offset := pageLimit(r), 0
	if page.paged {
		limit, offset = page.size, page.offset()
	}
	out, err := a.connectionLog(query, limit, offset)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if page.paged {
		a.writeLogPage(w, query, out)
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) clientActivity(w http.ResponseWriter, r *http.Request) {
	accessQuery, _ := newLogQuery(accessColumns)
	access, err := a.accessLog(accessQuery, 200, 0)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	connectionQuery, _ := newLogQuery(connectionColumns)
	connections, err := a.connectionLog(connectionQuery, 200, 0)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"accesses": access, "connections": connections})
}

func (s *Store) SaveConnectionIPs(serverID string, points []shared.ConnectionPoint) error {
	if len(points) > 500 {
		points = points[:500]
	}
	nodes, err := s.Nodes(serverID)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		allowed[node.ID] = true
	}
	at := time.Now().UnixMilli()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO mui_connection_ips(server_id,node_id,ip,at_ms,first_seen_ms) VALUES($1,$2,$3,$4,$4) ON CONFLICT(server_id,node_id,ip) DO UPDATE SET at_ms=excluded.at_ms`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, point := range points {
		ip := net.ParseIP(point.IP)
		if !allowed[point.NodeID] || ip == nil {
			continue
		}
		_, err = stmt.Exec(serverID, point.NodeID, ip.String(), at)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
