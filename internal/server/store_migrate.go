package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func migrateLegacySQLiteFile(oldPath, newPath string) error {
	oldInfo, oldErr := os.Lstat(oldPath)
	if os.IsNotExist(oldErr) {
		return nil
	}
	if oldErr != nil {
		return fmt.Errorf("inspect legacy SQLite database: %w", oldErr)
	}
	if !oldInfo.Mode().IsRegular() {
		return fmt.Errorf("legacy SQLite database %s is not a regular file", oldPath)
	}
	if _, err := os.Lstat(newPath); err == nil {
		return fmt.Errorf("both %s and %s exist; choose a database before starting", oldPath, newPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect SQLite database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(oldPath + suffix); err == nil {
			return fmt.Errorf("cannot move %s while %s exists; close SQLite writers and checkpoint the database first", oldPath, oldPath+suffix)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect SQLite journal: %w", err)
		}
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename legacy SQLite database: %w", err)
	}
	return nil
}

// migrations are applied in order, each exactly once; append, never edit.
// The first one predates version tracking and is safe to run on a database
// that already has those tables.
func (s *Store) migrate(driver string) error {
	if err := s.renameLegacyTables(driver); err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS mui_schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	var applied sql.NullInt64
	if err := s.DB.QueryRow(`SELECT MAX(version) FROM mui_schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	for i, statements := range migrations {
		version := int64(i + 1)
		if version <= applied.Int64 {
			continue
		}
		tx, err := s.DB.Begin()
		if err != nil {
			return fmt.Errorf("migration %d: %w", version, err)
		}
		for _, stmt := range statements {
			if _, err = tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d: %w", version, err)
			}
		}
		if fn := dataMigrations[version]; fn != nil {
			if err = fn(tx, driver); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d: %w", version, err)
			}
		}
		if _, err = tx.Exec(`INSERT INTO mui_schema_migrations(version) VALUES($1)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: %w", version, err)
		}
	}
	return nil
}

// Older releases used unprefixed table names. Rename them together so an
// existing database keeps its rows and migration history.
var legacyTables = []string{
	"schema_migrations", "admin", "sessions", "servers", "nodes",
	"certificates", "firewall_rules", "subscriptions", "operations",
	"traffic", "server_traffic", "audit", "totp_pending",
	"node_totals", "server_totals",
}

func (s *Store) renameLegacyTables(driver string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	legacy, err := tableExists(tx, driver, "schema_migrations")
	if err != nil || !legacy {
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	for _, name := range legacyTables {
		oldExists, err := tableExists(tx, driver, name)
		if err != nil {
			return err
		}
		if !oldExists {
			continue
		}
		newName := "mui_" + name
		newExists, err := tableExists(tx, driver, newName)
		if err != nil {
			return err
		}
		if newExists {
			return fmt.Errorf("both %s and %s exist; resolve the duplicate tables before starting", name, newName)
		}
		if _, err := tx.Exec("ALTER TABLE " + name + " RENAME TO " + newName); err != nil {
			return fmt.Errorf("rename %s: %w", name, err)
		}
	}
	return tx.Commit()
}

func tableExists(tx *sql.Tx, driver, name string) (bool, error) {
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$1`
	if driver == "pgx" {
		query = `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=$1`
	}
	var count int
	if err := tx.QueryRow(query, name).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

var migrations = [][]string{
	{
		`CREATE TABLE IF NOT EXISTS mui_admin (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS mui_sessions (token_hash TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mui_servers (id TEXT PRIMARY KEY, data TEXT NOT NULL, agent_hash TEXT NOT NULL DEFAULT '', enroll_hash TEXT NOT NULL DEFAULT '', enroll_expires BIGINT NOT NULL DEFAULT 0, revision BIGINT NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS mui_nodes (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, data TEXT NOT NULL, secret TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS mui_idx_nodes_server ON mui_nodes(server_id)`,
		`CREATE TABLE IF NOT EXISTS mui_certificates (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, data TEXT NOT NULL, secret TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mui_firewall_rules (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mui_subscriptions (id TEXT PRIMARY KEY, data TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE)`,
		`CREATE TABLE IF NOT EXISTS mui_operations (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, data TEXT NOT NULL, state TEXT NOT NULL, claimed_at BIGINT NOT NULL DEFAULT 0)`,
		`CREATE INDEX IF NOT EXISTS mui_idx_ops_server ON mui_operations(server_id)`,
		`CREATE TABLE IF NOT EXISTS mui_traffic (node_id TEXT NOT NULL, instance_id TEXT NOT NULL, sequence BIGINT NOT NULL, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL, at_ms BIGINT NOT NULL, PRIMARY KEY(node_id,instance_id,sequence))`,
		`CREATE INDEX IF NOT EXISTS mui_idx_traffic_node_at ON mui_traffic(node_id,at_ms)`,
		`CREATE TABLE IF NOT EXISTS mui_server_traffic (server_id TEXT NOT NULL, boot_id TEXT NOT NULL, sequence BIGINT NOT NULL, interface TEXT NOT NULL, rx BIGINT NOT NULL, tx BIGINT NOT NULL, at_ms BIGINT NOT NULL, PRIMARY KEY(server_id,boot_id,sequence))`,
		`CREATE INDEX IF NOT EXISTS mui_idx_server_traffic_at ON mui_server_traffic(server_id,at_ms)`,
		`CREATE TABLE IF NOT EXISTS mui_audit (id TEXT PRIMARY KEY, at_ms BIGINT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL)`,
	},
	{
		`CREATE TABLE IF NOT EXISTS mui_totp_pending (session_hash TEXT PRIMARY KEY, secret TEXT NOT NULL)`,
		// Running totals, so that old samples can be pruned without losing them.
		`CREATE TABLE mui_node_totals (node_id TEXT PRIMARY KEY, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL)`,
		`INSERT INTO mui_node_totals(node_id,uplink,downlink) SELECT node_id,SUM(uplink),SUM(downlink) FROM mui_traffic GROUP BY node_id`,
		`CREATE TABLE mui_server_totals (server_id TEXT PRIMARY KEY, rx BIGINT NOT NULL, tx BIGINT NOT NULL)`,
		`INSERT INTO mui_server_totals(server_id,rx,tx) SELECT server_id,SUM(rx),SUM(tx) FROM mui_server_traffic GROUP BY server_id`,
		// Finished operations no longer need their configuration snapshot, which
		// before this version was stored unencrypted and contained node secrets.
		`UPDATE mui_operations SET state='' WHERE claimed_at=-1`,
	},
	{
		`CREATE TABLE mui_node_templates (id TEXT PRIMARY KEY, data TEXT NOT NULL)`,
	},
	{
		`ALTER TABLE mui_node_templates ADD COLUMN secret TEXT NOT NULL DEFAULT ''`,
	},
	{
		`ALTER TABLE mui_nodes ADD COLUMN shadow_tls_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mui_node_templates ADD COLUMN shadow_tls_secret TEXT NOT NULL DEFAULT ''`,
	},
	{
		`CREATE TABLE mui_customers (id TEXT PRIMARY KEY, data TEXT NOT NULL)`,
		`CREATE TABLE mui_subscription_access (id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, customer_id TEXT NOT NULL, ip TEXT NOT NULL, at_ms BIGINT NOT NULL)`,
		`CREATE INDEX mui_idx_subscription_access_at ON mui_subscription_access(at_ms)`,
		`CREATE TABLE mui_connection_ips (server_id TEXT NOT NULL, node_id TEXT NOT NULL, ip TEXT NOT NULL, at_ms BIGINT NOT NULL, PRIMARY KEY(server_id,node_id,ip))`,
		`CREATE INDEX mui_idx_connection_ips_at ON mui_connection_ips(at_ms)`,
	},
	{
		`CREATE TABLE mui_user_traffic (node_id TEXT NOT NULL, subscription_id TEXT NOT NULL, instance_id TEXT NOT NULL, sequence BIGINT NOT NULL, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL, at_ms BIGINT NOT NULL, PRIMARY KEY(node_id,subscription_id,instance_id,sequence))`,
		`CREATE INDEX mui_idx_user_traffic_subscription_at ON mui_user_traffic(subscription_id,at_ms)`,
		`CREATE TABLE mui_user_totals (node_id TEXT NOT NULL, subscription_id TEXT NOT NULL, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL, PRIMARY KEY(node_id,subscription_id))`,
		`CREATE TABLE mui_subscription_expiry_applied (subscription_id TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)`,
	},
	{
		`CREATE TABLE mui_forwards (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, data TEXT NOT NULL)`,
		`CREATE INDEX mui_idx_forwards_server ON mui_forwards(server_id)`,
		`CREATE TABLE mui_forward_counters (forward_id TEXT NOT NULL, instance_id TEXT NOT NULL, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL, PRIMARY KEY(forward_id,instance_id))`,
		`CREATE TABLE mui_forward_totals (forward_id TEXT PRIMARY KEY, uplink BIGINT NOT NULL, downlink BIGINT NOT NULL)`,
	},
	{
		// What each server is known to be running, from its last successful apply.
		`CREATE TABLE mui_server_applied (server_id TEXT PRIMARY KEY, data TEXT NOT NULL)`,
		// The subscription token, encrypted, so the link can be shown again.
		`ALTER TABLE mui_subscriptions ADD COLUMN token_enc TEXT NOT NULL DEFAULT ''`,
	},
	{
		// Last-seen changes on every sample. Keep the discovery time stable so
		// paging cannot skip or repeat IPs when their last-seen order changes.
		`ALTER TABLE mui_connection_ips ADD COLUMN first_seen_ms BIGINT NOT NULL DEFAULT 0`,
		`UPDATE mui_connection_ips SET first_seen_ms=at_ms WHERE first_seen_ms=0`,
		`CREATE INDEX mui_idx_connection_ips_first_seen ON mui_connection_ips(first_seen_ms DESC,server_id DESC,node_id DESC,ip DESC)`,
	},
	{
		// Panel signing key for DesiredState signatures (private half encrypted).
		`CREATE TABLE mui_panel_signing_key (id INTEGER PRIMARY KEY, private_enc TEXT NOT NULL, public_b64 TEXT NOT NULL)`,
		// Durable TOTP replay state: the accepted step, consecutive failures and
		// the lock expiry survive a restart.
		`CREATE TABLE mui_totp_state (id INTEGER PRIMARY KEY, last_step BIGINT NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, locked_until_ms BIGINT NOT NULL DEFAULT 0)`,
		// Agent token rotation: the previous hash stays valid for a short grace
		// window so an in-flight agent is not locked out by a rotation.
		`ALTER TABLE mui_servers ADD COLUMN prev_agent_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE mui_servers ADD COLUMN prev_agent_expires BIGINT NOT NULL DEFAULT 0`,
		// Idle timeout for admin sessions (see require).
		`ALTER TABLE mui_sessions ADD COLUMN last_seen_at BIGINT NOT NULL DEFAULT 0`,
	},
	{
		// Set on an agent's first signed request; from then on its requests
		// must be signed. Older agents never sign and keep working until
		// upgraded.
		`ALTER TABLE mui_servers ADD COLUMN agent_signs INTEGER NOT NULL DEFAULT 0`,
	},
	{
		// Routes: entry → hop groups → exit node. Their forwards live in
		// mui_forwards, marked with the route ID.
		`CREATE TABLE mui_routes (id TEXT PRIMARY KEY, data TEXT NOT NULL)`,
	},
	{
		// Certificates are shared across servers; keep their IDs, PEM chains,
		// encrypted keys and existing node references intact.
		`ALTER TABLE mui_certificates DROP COLUMN server_id`,
	},
	{
		`CREATE TABLE mui_offline_exports (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, revision BIGINT NOT NULL, bundle_enc TEXT NOT NULL, imported_at BIGINT NOT NULL DEFAULT 0)`,
		`CREATE INDEX mui_offline_exports_server ON mui_offline_exports(server_id)`,
	},
	{
		// Offline exports no longer need receipt secrets or stored snapshots.
		// The server document records only its latest exported revision.
		`DROP TABLE mui_offline_exports`,
	},
	{
		`CREATE TABLE mui_entry_connection_ips (server_id TEXT NOT NULL, route_id TEXT NOT NULL, node_id TEXT NOT NULL, ip TEXT NOT NULL, at_ms BIGINT NOT NULL, first_seen_ms BIGINT NOT NULL, PRIMARY KEY(server_id,route_id,node_id,ip))`,
		`CREATE INDEX mui_entry_connection_ips_at ON mui_entry_connection_ips(at_ms)`,
	},
	{
		`ALTER TABLE mui_audit ADD COLUMN ip TEXT NOT NULL DEFAULT ''`,
	},
	{
		`CREATE TABLE IF NOT EXISTS mui_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS mui_komari_tokens (server_id TEXT PRIMARY KEY, token_enc TEXT NOT NULL)`,
	},
	{
		`CREATE TABLE IF NOT EXISTS mui_help_articles (id TEXT PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS mui_idx_help_articles_position ON mui_help_articles(position,id)`,
		`INSERT INTO mui_help_articles(id,question,answer,position,updated_at) VALUES('faq-compose-update','Docker Compose 怎样更新镜像？','使用远端镜像的 Compose 项目，在部署目录执行：

` + "```sh" + `
docker compose pull
docker compose up -d
` + "```" + `

仅执行 docker compose up -d 不会主动拉取远端的新镜像。MUI 项目在部署机从源码构建镜像，请使用项目的 ` + "`./deploy/publish.sh`" + ` 发布。',10,0) ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO mui_help_articles(id,question,answer,position,updated_at) VALUES('faq-agent-upgrade','为什么 Agent 升级按钮是灰色的？','先确认面板已发布对应 CPU 架构的 Agent 构建文件。需要重新构建并发布时，在项目目录执行：

` + "```sh" + `
./deploy/build-agent.sh amd64
./deploy/publish.sh --with-agent
` + "```" + `

ARM64 服务器将 amd64 换成 arm64。已是当前构建、Agent 不支持自更新或已有升级任务时，按钮也会不可用。',20,0) ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO mui_help_articles(id,question,answer,position,updated_at) VALUES('faq-ufw-protected','UFW 规则显示“SSH 保护”是什么意思？','这条主机规则可能放行 SSH 端口。为防止远程失联，面板不提供修改和删除操作；需要调整时，请登录服务器检查 UFW 规则和 SSH 实际端口。',30,0) ON CONFLICT(id) DO NOTHING`,
	},
	{
		// The software that fetched the subscription, as it named itself.
		`ALTER TABLE mui_subscription_access ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`,
	},
	{
		// Keep the former global Surge profile as the default template. Old
		// subscriptions have no template ID and continue to use this row.
		`CREATE TABLE IF NOT EXISTS mui_surge_templates (id TEXT PRIMARY KEY, name TEXT NOT NULL, template TEXT NOT NULL)`,
		`INSERT INTO mui_surge_templates(id,name,template) VALUES('default','默认模板',COALESCE((SELECT value FROM mui_settings WHERE key='surge_profile_template'),'')) ON CONFLICT(id) DO NOTHING`,
	},
	{
		// Adds mui_surge_templates.name_key, backfills Go-normalised keys
		// (deduplicating any colliding names), and creates a unique index;
		// executed via dataMigrations[23] because SQLite lower() is ASCII-only.
	},
	{
		`CREATE INDEX IF NOT EXISTS mui_idx_traffic_at_ms ON mui_traffic(at_ms)`,
		`CREATE INDEX IF NOT EXISTS mui_idx_user_traffic_at_ms ON mui_user_traffic(at_ms)`,
		`CREATE INDEX IF NOT EXISTS mui_idx_server_traffic_at_ms ON mui_server_traffic(at_ms)`,
	},
	{
		`CREATE INDEX IF NOT EXISTS mui_idx_ops_server_claimed ON mui_operations(server_id,claimed_at)`,
	},
}

var dataMigrations = map[int64]func(*sql.Tx, string) error{
	23: migrateSurgeTemplateNameKeys,
}

func columnExists(tx *sql.Tx, driver, table, column string) (bool, error) {
	query := `SELECT COUNT(*) FROM pragma_table_info($1) WHERE name=$2`
	if driver == "pgx" {
		query = `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2`
	}
	var count int
	if err := tx.QueryRow(query, table, column).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func migrateSurgeTemplateNameKeys(tx *sql.Tx, driver string) error {
	exists, err := columnExists(tx, driver, "mui_surge_templates", "name_key")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := tx.Exec(`ALTER TABLE mui_surge_templates ADD COLUMN name_key TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT id,name FROM mui_surge_templates ORDER BY CASE WHEN id='default' THEN 0 ELSE 1 END,id`)
	if err != nil {
		return err
	}
	type item struct{ id, name string }
	var list []item
	for rows.Next() {
		var row item
		if err = rows.Scan(&row.id, &row.name); err != nil {
			break
		}
		list = append(list, row)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, row := range list {
		base := strings.TrimSpace(row.name)
		if row.id == "default" {
			base = "默认模板"
		} else if base == "" {
			base = row.id
		}
		candidate := base
		key := surgeTemplateNameKey(candidate)
		for suffix := 2; used[key]; suffix++ {
			tag := fmt.Sprintf(" (%d)", suffix)
			runes := []rune(base)
			if maxBase := 80 - len([]rune(tag)); len(runes) > maxBase {
				runes = runes[:maxBase]
			}
			candidate = strings.TrimSpace(string(runes)) + tag
			key = surgeTemplateNameKey(candidate)
		}
		used[key] = true
		if _, err := tx.Exec(`UPDATE mui_surge_templates SET name=$1,name_key=$2 WHERE id=$3`, candidate, key, row.id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS mui_idx_surge_templates_name_key ON mui_surge_templates(name_key)`)
	return err
}

// reencryptLegacyOperationStates migrates queued job snapshots that were
// stored as plaintext (pre-encryption releases) to encrypted form. Snapshots
// that are neither decryptable nor valid JSON are cleared rather than left
// readable.
func (s *Store) reencryptLegacyOperationStates() error {
	rows, err := s.DB.Query(`SELECT id,state FROM mui_operations WHERE state<>''`)
	if err != nil {
		return err
	}
	type pending struct {
		id, state string
	}
	items := []pending{}
	for rows.Next() {
		var item pending
		if err := rows.Scan(&item.id, &item.state); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range items {
		if _, err := s.Decrypt(item.state); err == nil {
			continue // Already encrypted.
		}
		var probe any
		if err := json.Unmarshal([]byte(item.state), &probe); err != nil {
			if _, err := s.DB.Exec(`UPDATE mui_operations SET state='' WHERE id=$1`, item.id); err != nil {
				return err
			}
			continue
		}
		sealed, err := s.Encrypt(item.state)
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(`UPDATE mui_operations SET state=$1 WHERE id=$2`, sealed, item.id); err != nil {
			return err
		}
	}
	return nil
}
