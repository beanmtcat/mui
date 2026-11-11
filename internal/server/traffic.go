package server

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"
)

func (a *App) traffic(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("nodeId")
	if id == "" {
		errorJSON(w, 400, "nodeId required")
		return
	}
	rows, err := a.Store.DB.Query(`SELECT at_ms,uplink,downlink FROM mui_traffic WHERE node_id=$1 ORDER BY at_ms DESC LIMIT 1000`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, up, down int64
		if rows.Scan(&at, &up, &down) == nil {
			out = append(out, map[string]any{"at": time.UnixMilli(at), "uplink": up, "downlink": down})
		}
	}
	writeJSON(w, 200, out)
}

// trafficSeries returns traffic per hour for the last `hours` hours (24 by
// default, at most 31 days), oldest first, with empty hours filled in: one
// node's when nodeId is given, otherwise all nodes together.
func (a *App) trafficSeries(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("nodeId")
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 31*24 {
		hours = 24
	}
	const hour = int64(3600000)
	last := time.Now().UnixMilli() / hour
	first := last - int64(hours) + 1
	query, args := newLogQuery(`SELECT at_ms/3600000 AS bucket,SUM(uplink),SUM(downlink) FROM mui_traffic`)
	query.equal("node_id", id)
	query.where("at_ms>=" + query.arg(first*hour))
	rows, err := a.Store.DB.Query(query.filtered()+" GROUP BY at_ms/3600000", *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	sums := map[int64][2]int64{}
	for rows.Next() {
		var bucket, up, down int64
		if rows.Scan(&bucket, &up, &down) == nil {
			sums[bucket] = [2]int64{up, down}
		}
	}
	out := make([]map[string]any, 0, hours)
	for bucket := first; bucket <= last; bucket++ {
		out = append(out, map[string]any{"at": time.UnixMilli(bucket * hour), "uplink": sums[bucket][0], "downlink": sums[bucket][1]})
	}
	writeJSON(w, 200, out)
}

// trafficRanking sums traffic since ?since= (Unix milliseconds, the browser's
// local midnight; by default the server's) per node and per subscription.
func (a *App) trafficRanking(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	since := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).UnixMilli()
	if n, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); err == nil && n >= now.AddDate(0, 0, -31).UnixMilli() && n <= now.UnixMilli() {
		since = n
	}
	type usage struct {
		ID       string `json:"id"`
		Uplink   int64  `json:"uplink"`
		Downlink int64  `json:"downlink"`
	}
	sum := func(table, column string) ([]usage, error) {
		rows, err := a.Store.DB.Query(`SELECT `+column+`,SUM(uplink),SUM(downlink) FROM `+table+` WHERE at_ms>=$1 GROUP BY `+column, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []usage{}
		for rows.Next() {
			var item usage
			if err = rows.Scan(&item.ID, &item.Uplink, &item.Downlink); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, rows.Err()
	}
	nodes, err := sum("mui_traffic", "node_id")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	subscriptions, err := sum("mui_user_traffic", "subscription_id")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes, "subscriptions": subscriptions})
}

func (a *App) serverTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.Store.Server(id); err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	rows, err := a.Store.DB.Query(`SELECT at_ms,interface,rx,tx FROM mui_server_traffic WHERE server_id=$1 ORDER BY at_ms DESC LIMIT 1000`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, rx, tx int64
		var iface string
		if rows.Scan(&at, &iface, &rx, &tx) == nil {
			out = append(out, map[string]any{"at": time.UnixMilli(at), "interface": iface, "rx": rx, "tx": tx})
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) trafficSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	parse := func(key string, fallback time.Time) int64 {
		v := r.URL.Query().Get(key)
		if v == "" {
			return fallback.UnixMilli()
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < now.AddDate(-2, 0, 0).UnixMilli() || n > now.UnixMilli() {
			return fallback.UnixMilli()
		}
		return n
	}
	sum := func(start int64) (map[string]int64, error) {
		var up, down sql.NullInt64
		err := a.Store.DB.QueryRow(`SELECT SUM(uplink),SUM(downlink) FROM mui_traffic WHERE at_ms>=$1`, start).Scan(&up, &down)
		return map[string]int64{"uplink": up.Int64, "downlink": down.Int64}, err
	}
	d, err := sum(parse("dayStart", today))
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	m, err := sum(parse("monthStart", month))
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"today": d, "month": m})
}
