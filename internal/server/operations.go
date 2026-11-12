package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"mui/internal/shared"
)

// operationKinds are the jobs the panel queues for agents.
var operationKinds = []string{"nodes.apply", "firewall.apply", "forwards.apply", "subscriptions.apply", "ufw.init", "ufw.delete", "agent.upgrade", "core.upgrade"}

func (a *App) operations(w http.ResponseWriter, r *http.Request) {
	// IDs start with their creation time, so "before an ID" means "older than".
	query, args := newLogQuery(`SELECT data FROM mui_operations`)
	query.equal("server_id", r.URL.Query().Get("serverId"))
	if kind := r.URL.Query().Get("kind"); kind != "" {
		// The kind lives in the JSON document, which the panel writes with
		// json.Marshal: exactly `"kind":"<kind>"`. Only known kinds are
		// accepted, so the pattern is never user text.
		if !slices.Contains(operationKinds, kind) {
			errorJSON(w, 400, "操作类型无效")
			return
		}
		query.where("data LIKE " + query.arg(`%"kind":"`+likeEscape(kind)+`"%`) + ` ESCAPE '\'`)
	}
	page, err := readLogPage(r)
	if err == nil {
		err = query.idRange(r, "id")
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
	rows, err := a.Store.DB.Query(query.sql("id DESC", limit, offset), *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []shared.Operation{}
	for rows.Next() {
		var raw string
		_ = rows.Scan(&raw)
		var op shared.Operation
		_ = json.Unmarshal([]byte(raw), &op)
		op.Deployed = nil
		out = append(out, op)
	}
	if page.paged {
		a.writeLogPage(w, query, out)
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) retryOperation(w http.ResponseWriter, r *http.Request) {
	op, err := a.Store.Operation(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "操作不存在")
		return
	}
	if op.Status != "failed" {
		errorJSON(w, 409, "仅失败操作可重试")
		return
	}
	if op.Kind == "agent.upgrade" {
		_, err = a.queueAgentUpgrade(op.ServerID, a.clientIP(r))
	} else if op.Kind == "core.upgrade" {
		_, err = a.queueCoreUpgrade(op.ServerID, a.clientIP(r))
	} else {
		err = a.queueApply(op.ServerID, op.Kind)
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "operation.retry", op.ID, op.Kind)
	writeJSON(w, 202, map[string]bool{"queued": true})
}

func (a *App) audit(w http.ResponseWriter, r *http.Request) {
	query, args := newLogQuery(`SELECT id,at_ms,action,target,detail,ip FROM mui_audit`)
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
		query.where("LOWER(action || ' ' || detail || ' ' || ip) LIKE " + query.arg("%"+likeEscape(q)+"%") + ` ESCAPE '\'`)
	}
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
	rows, err := a.Store.DB.Query(query.sql("id DESC", limit, offset), *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at int64
		var id, action, target, detail, ip string
		if rows.Scan(&id, &at, &action, &target, &detail, &ip) == nil {
			out = append(out, map[string]any{"id": id, "at": time.UnixMilli(at), "action": action, "target": target, "detail": detail, "ip": ip})
		}
	}
	if page.paged {
		a.writeLogPage(w, query, out)
		return
	}
	writeJSON(w, 200, out)
}
