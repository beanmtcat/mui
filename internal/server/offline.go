package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func validateManagement(server shared.Server) error {
	if server.ManagementMode != "" && server.ManagementMode != "online" && server.ManagementMode != "offline" {
		return errors.New("管理方式无效")
	}
	if shared.OfflineManaged(server) && (!shared.ManualFirewall(server.FirewallMode) || shared.HasRole(server, shared.RoleExit)) {
		return errors.New("离线管理仅支持入口、线路、中转，且必须手动管理防火墙；落地节点仍需在线 Agent")
	}
	return nil
}

// Remove runtime fields so exporting a config cannot accidentally
// write stale status/counters back into the panel.
func (a *App) offlineForwards(id string) ([]shared.ForwardRule, error) {
	list, err := a.Store.Forwards(id)
	if err != nil {
		return nil, err
	}
	out := []shared.ForwardRule{}
	for _, f := range list {
		if f.Deleting {
			continue
		}
		f.FirewallPolicy, f.FirewallSources = "manual", ""
		f.Status, f.Error, f.Uplink, f.Downlink = "", "", 0, 0
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (a *App) offlineExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	unlock := a.lockServer(id)
	defer unlock()
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if !shared.OfflineManaged(server) {
		errorJSON(w, 409, "请先将服务器设为离线管理")
		return
	}
	if err := validateManagement(server); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	forwards, err := a.offlineForwards(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if len(forwards) > 500 {
		errorJSON(w, 409, "离线配置最多支持 500 条转发")
		return
	}
	if server.Revision == 0 {
		server.Revision = 1
	}
	private, err := a.Store.PanelSigningPrivateKey()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	bundle := shared.OfflineBundle{ExportID: ID(), ServerID: id, Revision: server.Revision, Forwards: forwards}
	bundle.Sign(private)
	fileJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if len(fileJSON)+1 > 1<<20 {
		errorJSON(w, 409, "离线配置超过 1 MiB，请减少本机转发规则或目标数量")
		return
	}
	// Export records only what the administrator downloaded. It never claims
	// the isolated host has applied the file or is currently reachable.
	if err := a.recordOfflineExport(server); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// An export file is private administrator data, never a public URL.
	w.Header().Set("Cache-Control", "no-store")
	a.Store.Audit("offline.export", id, "revision "+strconv.FormatInt(bundle.Revision, 10))
	guide := a.standaloneInstallAt(a.publicURLForRequest(r))
	guide.MigrationCommand = managementMigrationCommand(server)
	guide.ExampleConfig = ""
	guide.Command = strings.ReplaceAll(guide.Command, "./forwards.json", "./mui-offline.json")
	writeJSON(w, 200, map[string]any{"bundle": bundle, "install": guide})
}

func (a *App) recordOfflineExport(server shared.Server) error {
	list, err := a.Store.Forwards(server.ID)
	if err != nil {
		return err
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, f := range list {
		if f.Deleting {
			// The complete exported snapshot omits these rules. Removing the
			// panel record does not stop a process on the isolated machine.
			for _, stmt := range []string{`DELETE FROM mui_forward_counters WHERE forward_id=$1`, `DELETE FROM mui_forward_totals WHERE forward_id=$1`, `DELETE FROM mui_forwards WHERE id=$1`} {
				if _, err := tx.Exec(stmt, f.ID); err != nil {
					return err
				}
			}
			continue
		}
		f.Status, f.Error = "exported", ""
		if !f.Enabled {
			f.Status = "disabled"
		}
		if _, err := tx.Exec(`UPDATE mui_forwards SET data=$1 WHERE id=$2`, Marshal(f), f.ID); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	server.OfflineExportedRevision, server.OfflineExportedAt = server.Revision, &now
	if _, err := tx.Exec(`UPDATE mui_servers SET data=$1 WHERE id=$2`, Marshal(server), server.ID); err != nil {
		return err
	}
	return tx.Commit()
}
