package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func (a *App) subscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		rows, err := a.Store.DB.Query(`SELECT subscription_id,SUM(uplink),SUM(downlink) FROM mui_user_totals GROUP BY subscription_id`)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		totals := map[string][2]int64{}
		for rows.Next() {
			var id string
			var up, down int64
			if err = rows.Scan(&id, &up, &down); err != nil {
				break
			}
			totals[id] = [2]int64{up, down}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		linkRows, err := a.Store.DB.Query(`SELECT id FROM mui_subscriptions WHERE token_enc<>''`)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		hasLink := map[string]bool{}
		for linkRows.Next() {
			var id string
			if linkRows.Scan(&id) == nil {
				hasLink[id] = true
			}
		}
		linkRows.Close()
		var world *routeWorld
		if slices.ContainsFunc(list, func(s shared.Subscription) bool { return len(s.RouteIDs) > 0 }) {
			loaded, err := a.loadRouteWorld()
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
			world = &loaded
		}
		for i := range list {
			list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
			list[i].LinkAvailable = hasLink[list[i].ID]
			if list[i].Enabled && (list[i].ExpiresAt == nil || time.Now().Before(*list[i].ExpiresAt)) {
				if _, _, pending, err := a.subscriptionItems(list[i], world); err == nil {
					for _, id := range pending {
						if slices.Contains(list[i].RouteIDs, id) {
							list[i].PendingRouteIDs = append(list[i].PendingRouteIDs, id)
						} else {
							list[i].PendingNodeIDs = append(list[i].PendingNodeIDs, id)
						}
					}
				}
			}
		}
		paginateList(w, r, list, func(s shared.Subscription) string { return s.ID })
		return
	}
	var raw struct {
		shared.Subscription
		// Enabled is a pointer so creation can tell "omitted" (default true)
		// from an explicit false.
		Enabled *bool `json:"enabled"`
	}
	if !readJSON(w, r, &raw) {
		return
	}
	in := raw.Subscription
	if in.SurgeTemplateID == "default" {
		in.SurgeTemplateID = ""
	}
	if in.Name == "" || (in.Format != "sing-box" && in.Format != "surge" && in.Format != "v2rayn") {
		errorJSON(w, 400, "名称或格式无效")
		return
	}
	if !a.validCustomer(in.CustomerID) {
		errorJSON(w, 400, "客户不存在")
		return
	}
	if in.Format != "surge" && in.SurgeTemplateID != "" {
		errorJSON(w, 400, "只有 Surge 订阅可以选择完整配置模板")
		return
	}
	if err := a.checkSubscriptionMembers(in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	in.ID = ID()
	in.Enabled = true
	if raw.Enabled != nil {
		in.Enabled = *raw.Enabled
	}
	token := Token()
	sealed, err := a.Store.Encrypt(token)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.Uplink, in.Downlink, in.URL, in.PendingNodeIDs, in.PendingRouteIDs, in.LinkAvailable = 0, 0, "", nil, nil, false
	if err = a.Store.CreateSubscription(in, Hash(token), sealed); err != nil {
		var badTemplate surgeTemplateValidationError
		if errors.As(err, &badTemplate) {
			errorJSON(w, 400, badTemplate.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueSubscriptionsApply(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.URL = a.publicURLForRequest(r) + "/s/" + token
	a.auditRequest(r, "subscription.create", in.ID, in.Name)
	writeJSON(w, 201, in)
}

func (a *App) subscriptionTrafficSeries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	found := false
	for _, sub := range list {
		if sub.ID == id {
			found = true
			break
		}
	}
	if !found {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 31*24 {
		hours = 24
	}
	const hour = int64(3600000)
	last := time.Now().UnixMilli() / hour
	first := last - int64(hours) + 1
	rows, err := a.Store.DB.Query(`SELECT at_ms/3600000 AS bucket,SUM(uplink),SUM(downlink) FROM mui_user_traffic WHERE subscription_id=$1 AND at_ms>=$2 GROUP BY at_ms/3600000`, id, first*hour)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	sums := map[int64][2]int64{}
	for rows.Next() {
		var bucket, up, down int64
		if err = rows.Scan(&bucket, &up, &down); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		sums[bucket] = [2]int64{up, down}
	}
	if err = rows.Err(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, hours)
	for bucket := first; bucket <= last; bucket++ {
		out = append(out, map[string]any{"at": time.UnixMilli(bucket * hour), "uplink": sums[bucket][0], "downlink": sums[bucket][1]})
	}
	writeJSON(w, 200, out)
}

func (a *App) subscriptionByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, _ := a.Store.Subscriptions()
	var old *shared.Subscription
	for i := range list {
		if list[i].ID == id {
			old = &list[i]
			break
		}
	}
	if old == nil {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	if r.Method == "DELETE" {
		_, err := a.Store.DB.Exec(`DELETE FROM mui_subscriptions WHERE id=$1`, id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		_, _ = a.Store.DB.Exec(`DELETE FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, id)
		if err = a.queueSubscriptionsApply(*old); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "subscription.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in shared.Subscription
	if !readJSON(w, r, &in) {
		return
	}
	if in.SurgeTemplateID == "default" {
		in.SurgeTemplateID = ""
	}
	if strings.TrimSpace(in.Name) == "" || (in.Format != "sing-box" && in.Format != "surge" && in.Format != "v2rayn") {
		errorJSON(w, 400, "名称或格式无效")
		return
	}
	if !a.validCustomer(in.CustomerID) {
		errorJSON(w, 400, "客户不存在")
		return
	}
	if in.Format != "surge" && in.SurgeTemplateID != "" {
		errorJSON(w, 400, "只有 Surge 订阅可以选择完整配置模板")
		return
	}
	if err := a.checkSubscriptionMembers(in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	previous, updated, err := a.Store.UpdateSubscription(id, in)
	if err != nil {
		var badTemplate surgeTemplateValidationError
		if errors.As(err, &badTemplate) {
			errorJSON(w, 400, badTemplate.Error())
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "订阅不存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	// A profile template only affects the downloaded Surge text. Neither
	// template-only edits nor unmodified saves should restart sing-box or
	// reapply node credentials on exit servers.
	withoutTemplate := previous
	withoutTemplate.SurgeTemplateID = updated.SurgeTemplateID
	if len(withoutTemplate.NodeIDs) == 0 && len(updated.NodeIDs) == 0 {
		withoutTemplate.NodeIDs = updated.NodeIDs
	}
	if len(withoutTemplate.RouteIDs) == 0 && len(updated.RouteIDs) == 0 {
		withoutTemplate.RouteIDs = updated.RouteIDs
	}
	if Marshal(withoutTemplate) != Marshal(updated) {
		_, _ = a.Store.DB.Exec(`DELETE FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, id)
		if err = a.queueSubscriptionsApply(previous, updated); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	a.auditRequest(r, "subscription.update", id, updated.Name)
	writeJSON(w, 200, &updated)
}

// checkSubscriptionMembers validates a subscription's direct nodes and routes.
func (a *App) checkSubscriptionMembers(sub shared.Subscription) error {
	for _, id := range sub.NodeIDs {
		n, err := a.Store.Node(id)
		if err != nil {
			return errors.New("节点不存在: " + id)
		}
		if !n.Direct {
			return errors.New("节点“" + n.Name + "”未开启直连，只能通过链路订阅")
		}
		if err := validateSubscriptionNode(sub.Format, n); err != nil {
			return err
		}
	}
	routes, err := a.Store.Routes()
	if err != nil {
		return err
	}
	for _, id := range sub.RouteIDs {
		i := slices.IndexFunc(routes, func(rt shared.Route) bool { return rt.ID == id })
		if i < 0 {
			return errors.New("链路不存在: " + id)
		}
		n, err := a.Store.Node(routes[i].NodeID)
		if err != nil {
			return errors.New("链路“" + routes[i].Name + "”的落地节点不存在")
		}
		if err := validateSubscriptionNode(sub.Format, n); err != nil {
			return errors.New("链路“" + routes[i].Name + "”：" + err.Error())
		}
	}
	return nil
}

// queueSubscriptionsApply queues the servers of every node the given
// subscriptions need a login on.
func (a *App) queueSubscriptionsApply(subs ...shared.Subscription) error {
	routes, err := a.Store.Routes()
	if err != nil {
		return err
	}
	var ids []string
	for _, sub := range subs {
		ids = append(ids, subscriptionNodeIDs(sub, routes)...)
	}
	return a.queueSubscriptionApply(ids)
}

func validateSubscriptionNode(format string, n shared.Node) error {
	if format == "v2rayn" && n.Protocol != "ss" && n.Protocol != "anytls" && n.Protocol != "socks5" {
		return errors.New("v2rayN 订阅仅支持 SS、AnyTLS 和 SOCKS5 节点，不支持 Snell / ShadowTLS")
	}
	if format == "surge" {
		switch {
		case n.Protocol == "ss" && n.Method == "2022-blake3-chacha20-poly1305":
			return errors.New("Surge 订阅不支持 2022-blake3-chacha20-poly1305")
		case n.Protocol == "snell" && n.ShadowTLSHost == "" && !n.SingleUser:
			return errors.New("Surge 订阅中的托管 Snell 节点需启用 ShadowTLS")
		}
	}
	return nil
}

func (a *App) queueSubscriptionApply(nodeIDs []string) error {
	servers := map[string]bool{}
	for _, id := range nodeIDs {
		n, err := a.Store.Node(id)
		if err == nil && !shared.SharedSubscriptionPassword(n) {
			servers[n.ServerID] = true
		}
	}
	for id := range servers {
		server, err := a.Store.Server(id)
		if err != nil {
			return err
		}
		if !server.MultiUserStats {
			continue
		} // The upgraded Agent queues the first apply when it reports support.
		if err := a.queueApply(id, "subscriptions.apply"); err != nil {
			return err
		}
	}
	return nil
}

// A subscription expiry must remove its credentials even if no administrator
// is using the panel. Agents poll this path, so one of them schedules the apply.
func (a *App) syncExpiredSubscriptions() error {
	subs, err := a.Store.Subscriptions()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, sub := range subs {
		if !sub.Enabled || sub.ExpiresAt == nil || now.Before(*sub.ExpiresAt) {
			continue
		}
		at := sub.ExpiresAt.UnixMilli()
		var done int64
		err = a.Store.DB.QueryRow(`SELECT expires_at FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, sub.ID).Scan(&done)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if done == at {
			continue
		}
		if err = a.queueSubscriptionsApply(sub); err != nil {
			return err
		}
		if _, err = a.Store.DB.Exec(`INSERT INTO mui_subscription_expiry_applied(subscription_id,expires_at) VALUES($1,$2) ON CONFLICT(subscription_id) DO UPDATE SET expires_at=excluded.expires_at`, sub.ID, at); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) rotateSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := Token()
	sealed, err := a.Store.Encrypt(token)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	result, err := a.Store.DB.Exec(`UPDATE mui_subscriptions SET token_hash=$1,token_enc=$2 WHERE id=$3`, Hash(token), sealed, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	a.auditRequest(r, "subscription.rotate", id, "")
	writeJSON(w, 200, map[string]string{"url": a.publicURLForRequest(r) + "/s/" + token})
}

// subscriptionLink shows an existing link again. Links created before tokens
// were kept (encrypted) cannot be recovered and have to be rotated once.
func (a *App) subscriptionLink(w http.ResponseWriter, r *http.Request) {
	var sealed string
	err := a.Store.DB.QueryRow(`SELECT token_enc FROM mui_subscriptions WHERE id=$1`, r.PathValue("id")).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if sealed == "" {
		errorJSON(w, 409, "该订阅创建于旧版本，链接未保存；轮换一次后即可随时查看")
		return
	}
	token, err := a.Store.Decrypt(sealed)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"url": a.publicURLForRequest(r) + "/s/" + token})
}

func (a *App) subscriptionDownload(w http.ResponseWriter, r *http.Request) {
	if a.rateCount(r, "subscription", 1) > 120 {
		errorJSON(w, 429, "请求过于频繁")
		return
	}
	sub, err := a.Store.SubscriptionByToken(r.PathValue("token"))
	if err != nil || !sub.Enabled || (sub.ExpiresAt != nil && time.Now().After(*sub.ExpiresAt)) {
		errorJSON(w, 404, "订阅无效")
		return
	}
	// ?profile=1 serves a Surge subscription as a complete profile; without it
	// the link stays a node list for policy-path.
	profile := r.URL.Query().Get("profile") == "1"
	if profile && sub.Format != "surge" {
		errorJSON(w, 400, "只有 Surge 订阅提供完整配置")
		return
	}
	items, skipped, pending, err := a.subscriptionItems(sub, nil)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Some nodes waiting is fine: the rest are served. All of them waiting is
	// usually a few seconds after a change, and an empty answer would make the
	// client drop nodes that are about to work.
	if len(items) == 0 && len(pending) > 0 {
		w.Header().Set("Retry-After", "30")
		errorJSON(w, 503, "订阅中的节点配置正在生效，请稍后重试")
		return
	}
	// Every node skipped for a permanent reason (disabled, incompatible)
	// must not become a silent empty configuration: the client would drop
	// nodes without knowing why.
	if len(items) == 0 && len(pending) == 0 {
		errorJSON(w, 503, "订阅中没有可用节点："+strings.Join(skipped, "; "))
		return
	}
	var body []byte
	if profile {
		var template string
		template, err = a.Store.SurgeTemplateContent(sub.SurgeTemplateID)
		if errors.Is(err, sql.ErrNoRows) && sub.SurgeTemplateID != "" {
			template, err = a.Store.SurgeTemplateContent("")
		}
		if errors.Is(err, sql.ErrNoRows) {
			template, err = "", nil
		}
		if err != nil {
			errorJSON(w, 500, "无法读取 Surge 模板")
			return
		}
		body, skipped, err = shared.RenderSurgeProfile(items, a.publicURLForRequest(r)+"/s/"+r.PathValue("token")+"?profile=1", template)
		if err != nil {
			if len(skipped) > 0 {
				err = fmt.Errorf("%w：%s", err, strings.Join(skipped, "; "))
			}
			errorJSON(w, 503, err.Error())
			return
		}
	} else if body, _, err = shared.RenderSubscription(sub.Format, items); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err := a.Store.DB.Exec(`INSERT INTO mui_subscription_access(id,subscription_id,customer_id,ip,at_ms,user_agent) VALUES($1,$2,$3,$4,$5,$6)`, ID(), sub.ID, sub.CustomerID, a.clientIP(r), time.Now().UnixMilli(), cleanUserAgent(r.UserAgent())); err != nil {
		errorJSON(w, 500, "无法记录订阅访问")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if sub.Format == "sing-box" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else if profile {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="MUI.conf"`)
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	_, _ = w.Write(body)
}

func (a *App) previewSubscription(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	var selected *shared.Subscription
	for i := range list {
		if list[i].ID == r.PathValue("id") {
			selected = &list[i]
			break
		}
	}
	if selected == nil {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	items, skipped, _, err := a.subscriptionItems(*selected, nil)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	body, excluded, err := shared.RenderSubscription(selected.Format, items)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	excluded = append(skipped, excluded...)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"content": string(body), "excluded": excluded})
}

func (a *App) subscriptionItem(sub shared.Subscription, n shared.Node, server shared.Server) (shared.SubscriptionItem, error) {
	password, err := a.Store.NodeSecret(n.ID)
	if err != nil {
		return shared.SubscriptionItem{}, err
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
	if err != nil {
		return shared.SubscriptionItem{}, err
	}
	item := shared.SubscriptionItem{Node: n, Server: server, Password: password, Username: n.Username, ShadowTLSPassword: shadowPassword}
	if shared.SharedSubscriptionPassword(n) {
		// Single-user nodes and legacy AEAD SS share their original node
		// credential across subscriptions.
		return item, nil
	}
	user := a.Store.SubscriptionUser(n, sub.ID)
	switch n.Protocol {
	case "ss":
		item.Password = password + ":" + user.Password
	case "snell":
		// See SingBoxConfig: behind ShadowTLS the per-subscription secret is the
		// ShadowTLS password. An agent that predates this still expects a Snell
		// user key as well.
		if n.ShadowTLSHost != "" {
			item.ShadowTLSPassword = user.ShadowTLSPassword
		}
		if n.ShadowTLSHost == "" || !server.ShadowTLSAuth {
			item.UserKey = user.Password
		}
	case "socks5":
		item.Username, item.Password = user.Name, user.Password
	case "anytls":
		item.Password = user.Password
	}
	return item, nil
}

// subscriptionItems resolves a subscription to the nodes that can be handed
// out right now. Nodes that cannot are named in skipped, with the reason, and
// pending lists those that are merely waiting for their server to apply.
// world may be nil; it is then loaded when the subscription has routes. A
// caller resolving many subscriptions loads it once and passes it in.
func (a *App) subscriptionItems(sub shared.Subscription, world *routeWorld) (items []shared.SubscriptionItem, skipped []string, pending []string, err error) {
	items, skipped, pending = []shared.SubscriptionItem{}, []string{}, []string{}
	for _, id := range sub.NodeIDs {
		n, e := a.Store.Node(id)
		if e != nil {
			continue
		}
		server, e := a.Store.Server(n.ServerID)
		if e != nil {
			continue
		}
		if !n.Enabled || n.Deleting {
			skipped = append(skipped, n.Name+": 节点已停用或正在删除")
			continue
		}
		if e := validateSubscriptionNode(sub.Format, n); e != nil {
			skipped = append(skipped, n.Name+": "+e.Error())
			continue
		}
		live, e := a.nodeLive(n, server, sub.ID)
		if e != nil {
			return nil, nil, nil, e
		}
		if !live {
			skipped = append(skipped, n.Name+": 配置尚未在服务器 "+server.Name+" 上生效")
			pending = append(pending, n.ID)
			continue
		}
		item, e := a.subscriptionItem(sub, n, server)
		if e != nil {
			skipped = append(skipped, n.Name+": "+e.Error())
			continue
		}
		// Liveness was just established from what the server runs; the stored
		// status only says whether the latest edit has been confirmed.
		item.Node.Status = "active"
		items = append(items, item)
	}
	if len(sub.RouteIDs) == 0 {
		return items, skipped, pending, nil
	}
	if world == nil {
		loaded, err := a.loadRouteWorld()
		if err != nil {
			return nil, nil, nil, err
		}
		world = &loaded
	}
	for _, rt := range world.routes {
		if !slices.Contains(sub.RouteIDs, rt.ID) {
			continue
		}
		n, ok := world.nodes[rt.NodeID]
		if !ok {
			continue
		}
		if !rt.Enabled || !n.Enabled || n.Deleting {
			skipped = append(skipped, rt.Name+": 链路或落地节点已停用")
			continue
		}
		if e := validateSubscriptionNode(sub.Format, n); e != nil {
			skipped = append(skipped, rt.Name+": "+e.Error())
			continue
		}
		live, e := a.routeLive(rt, *world, sub.ID)
		if e != nil {
			return nil, nil, nil, e
		}
		if !live {
			skipped = append(skipped, rt.Name+": 链路配置尚未全部生效")
			pending = append(pending, rt.ID)
			continue
		}
		item, e := a.subscriptionItem(sub, n, world.servers[n.ServerID])
		if e != nil {
			skipped = append(skipped, rt.Name+": "+e.Error())
			continue
		}
		// Clients dial the entry on the route's port; protocol, logins and
		// TLS names stay the exit node's, carried through by the forwards.
		item.Node.ID, item.Node.Name, item.Node.Port = rt.ID, rt.Name, rt.Port
		item.Node.PublishAddress = clientAddress(world.servers[rt.EntryServerID])
		item.Node.Status = "active"
		items = append(items, item)
	}
	return items, skipped, pending, nil
}
