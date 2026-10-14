package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	DB  *sql.DB
	key []byte
}

// checkSecretStrength requires length plus character-class diversity. The key
// is a single SHA-256 of the secret (see the Argon2id note below), so a
// guessable 32-character passphrase would fall to fast offline brute force
// once a database backup leaks.
func checkSecretStrength(secret string) error {
	if len(secret) < 32 {
		return errors.New("MUI_SECRET must contain at least 32 characters")
	}
	// Strength comes from length and randomness, not from the mix of
	// character classes: `openssl rand -hex 32` is 256 random bits in two
	// classes. Refuse only what is clearly not random: the shipped
	// placeholders and strings built from a handful of characters.
	if strings.HasPrefix(strings.ToLower(secret), "replace-with") {
		return errors.New("MUI_SECRET is still the placeholder from the example file")
	}
	distinct := map[rune]bool{}
	for _, r := range secret {
		distinct[r] = true
	}
	if len(distinct) < 10 {
		return errors.New("MUI_SECRET looks repetitive; use a random value such as `openssl rand -hex 32`")
	}
	return nil
}

func NewStore(dsn, secret string) (*Store, error) {
	// NOTE: the encryption key is still a single SHA-256 of MUI_SECRET. A
	// future release should migrate to Argon2id with a versioned KDF (old
	// databases cannot be decrypted with a new KDF without a migration path,
	// so the derivation must not simply be swapped).
	if err := checkSecretStrength(secret); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(secret))
	driver := "sqlite3"
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		driver = "pgx"
	} else {
		if dsn == "" {
			dsn = "data/mui.db"
			if err := migrateLegacySQLiteFile("data/panel.db", dsn); err != nil {
				return nil, err
			}
		}
		if err := os.MkdirAll(filepath.Dir(dsn), 0700); err != nil {
			return nil, err
		}
		dsn += "?_busy_timeout=5000&_foreign_keys=1"
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite3" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	if err = db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{DB: db, key: key[:]}
	if err = s.migrate(driver); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = s.reencryptLegacyOperationStates(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

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
}

func ID() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%016x%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}
func Token() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func Marshal(v any) string { b, _ := json.Marshal(v); return string(b) }

func (s *Store) Encrypt(value string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(value), nil)), nil
}
func (s *Store) Decrypt(value string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	clear, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	return string(clear), err
}

// Fingerprint is a keyed digest: it lets two values be compared for equality
// later without keeping either of them, and reveals nothing without the secret.
func (s *Store) Fingerprint(parts ...string) string {
	mac := hmac.New(sha256.New, s.key)
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
		_, _ = mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// AppliedDeployment returns what the server's last successful apply put in
// place. known is false for a server that has not completed one since this was
// first recorded.
func (s *Store) AppliedDeployment(serverID string) (nodes map[string]shared.NodeDeployment, known bool, err error) {
	var raw string
	err = s.DB.QueryRow(`SELECT data FROM mui_server_applied WHERE server_id=$1`, serverID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	nodes = map[string]shared.NodeDeployment{}
	return nodes, true, json.Unmarshal([]byte(raw), &nodes)
}

func (s *Store) SetAppliedDeployment(serverID string, nodes map[string]shared.NodeDeployment) error {
	if nodes == nil {
		nodes = map[string]shared.NodeDeployment{}
	}
	_, err := s.DB.Exec(`INSERT INTO mui_server_applied(server_id,data) VALUES($1,$2) ON CONFLICT(server_id) DO UPDATE SET data=excluded.data`, serverID, Marshal(nodes))
	return err
}

func (s *Store) Audit(action, target, detail string) {
	if _, err := s.DB.Exec(`INSERT INTO mui_audit(id,at_ms,action,target,detail) VALUES($1,$2,$3,$4,$5)`, ID(), time.Now().UnixMilli(), action, target, detail); err != nil {
		// Audit rows must never carry secrets, so logging the failure is safe.
		log.Printf("audit %s %s: %v", action, target, err)
	}
}

// PruneAudit deletes audit rows older than the cutoff. Callers run it on the
// same schedule as traffic pruning.
func (s *Store) PruneAudit(before time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM mui_audit WHERE at_ms<$1`, before.UnixMilli())
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

// TOTP replay state is a single row (id=1) in mui_totp_state.
func (s *Store) TOTPState() (lastStep uint64, failures int, lockedUntil time.Time, err error) {
	var step, lockedMs int64
	err = s.DB.QueryRow(`SELECT last_step,failures,locked_until_ms FROM mui_totp_state WHERE id=1`).Scan(&step, &failures, &lockedMs)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, time.Time{}, nil
	}
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	return uint64(step), failures, time.UnixMilli(lockedMs), nil
}

func (s *Store) SetTOTPState(lastStep uint64, failures int, lockedUntil time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO mui_totp_state(id,last_step,failures,locked_until_ms) VALUES(1,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET last_step=excluded.last_step,failures=excluded.failures,locked_until_ms=excluded.locked_until_ms`, int64(lastStep), failures, lockedUntil.UnixMilli())
	return err
}

// EnsurePanelSigningKey loads the panel's Ed25519 signing key, generating and
// storing it (private half encrypted) on first use. Agents verify DesiredState
// signatures against the public half.
func (s *Store) EnsurePanelSigningKey() (ed25519.PublicKey, error) {
	var sealed, publicB64 string
	err := s.DB.QueryRow(`SELECT private_enc,public_b64 FROM mui_panel_signing_key WHERE id=1`).Scan(&sealed, &publicB64)
	if err == nil {
		raw, err := base64.StdEncoding.DecodeString(publicB64)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("stored panel signing public key is invalid")
		}
		return ed25519.PublicKey(raw), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sealed, err = s.Encrypt(base64.StdEncoding.EncodeToString(private.Seed()))
	if err != nil {
		return nil, err
	}
	publicB64 = base64.StdEncoding.EncodeToString(public)
	if _, err := s.DB.Exec(`INSERT INTO mui_panel_signing_key(id,private_enc,public_b64) VALUES(1,$1,$2)`, sealed, publicB64); err != nil {
		return nil, err
	}
	return public, nil
}

func (s *Store) PanelSigningPrivateKey() (ed25519.PrivateKey, error) {
	var sealed string
	if err := s.DB.QueryRow(`SELECT private_enc FROM mui_panel_signing_key WHERE id=1`).Scan(&sealed); err != nil {
		return nil, err
	}
	clear, err := s.Decrypt(sealed)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(clear)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("stored panel signing private key is invalid")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func queryJSON[T any](db *sql.DB, query string, args ...any) ([]T, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item T
		if err = json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Servers() ([]shared.Server, error) {
	list, err := queryJSON[shared.Server](s.DB, `SELECT data FROM mui_servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	totals, err := s.totals(`SELECT server_id,rx,tx FROM mui_server_totals`)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].NetworkRx, list[i].NetworkTx = totals[list[i].ID][0], totals[list[i].ID][1]
	}
	return list, nil
}

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
	return nil
}
func (s *Store) Server(id string) (shared.Server, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_servers WHERE id=$1`, id).Scan(&raw)
	var v shared.Server
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
func (s *Store) PutServer(v shared.Server) error {
	_, err := s.DB.Exec(`UPDATE mui_servers SET data=$1,revision=$2 WHERE id=$3`, Marshal(v), v.Revision, v.ID)
	return err
}
func (s *Store) Nodes(serverID string) ([]shared.Node, error) {
	if serverID == "" {
		return queryJSON[shared.Node](s.DB, `SELECT data FROM mui_nodes ORDER BY id`)
	}
	return queryJSON[shared.Node](s.DB, `SELECT data FROM mui_nodes WHERE server_id=$1 ORDER BY id`, serverID)
}
func (s *Store) NodeTemplates() ([]shared.NodeTemplate, error) {
	return queryJSON[shared.NodeTemplate](s.DB, `SELECT data FROM mui_node_templates ORDER BY id`)
}
func (s *Store) NodeTemplate(id string) (shared.NodeTemplate, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_node_templates WHERE id=$1`, id).Scan(&raw)
	var v shared.NodeTemplate
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
func (s *Store) NodeTemplateSecret(id string) (string, error) {
	var secret string
	if err := s.DB.QueryRow(`SELECT secret FROM mui_node_templates WHERE id=$1`, id).Scan(&secret); err != nil {
		return "", err
	}
	if secret == "" {
		return "", nil
	}
	return s.Decrypt(secret)
}
func (s *Store) NodeTemplateShadowTLSSecret(id string) (string, error) {
	return s.optionalSecret(`SELECT shadow_tls_secret FROM mui_node_templates WHERE id=$1`, id)
}
func (s *Store) optionalSecret(query, id string) (string, error) {
	var raw string
	if err := s.DB.QueryRow(query, id).Scan(&raw); err != nil {
		return "", err
	}
	if raw == "" {
		return "", nil
	}
	return s.Decrypt(raw)
}
func (s *Store) PutNodeTemplate(v shared.NodeTemplate, password, shadowTLSPassword string) error {
	secret := ""
	shadowSecret := ""
	var err error
	if password != "" {
		secret, err = s.Encrypt(password)
		if err != nil {
			return err
		}
	}
	if shadowTLSPassword != "" {
		shadowSecret, err = s.Encrypt(shadowTLSPassword)
		if err != nil {
			return err
		}
	}
	_, err = s.DB.Exec(`INSERT INTO mui_node_templates(id,data,secret,shadow_tls_secret) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=excluded.data,secret=excluded.secret,shadow_tls_secret=excluded.shadow_tls_secret`, v.ID, Marshal(v), secret, shadowSecret)
	return err
}
func (s *Store) DeleteNodeTemplate(id string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_node_templates WHERE id=$1`, id)
	return err
}
func (s *Store) Node(id string) (shared.Node, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_nodes WHERE id=$1`, id).Scan(&raw)
	var v shared.Node
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
func (s *Store) NodeSecret(id string) (string, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, id).Scan(&raw)
	if err != nil {
		return "", err
	}
	return s.Decrypt(raw)
}
func (s *Store) NodeShadowTLSSecret(id string) (string, error) {
	return s.optionalSecret(`SELECT shadow_tls_secret FROM mui_nodes WHERE id=$1`, id)
}

// SubscriptionUser deterministically derives a separate login for each
// subscription/node pair. The server secret already protects node secrets, so
// no extra plaintext credential table is needed.
func (s *Store) SubscriptionUser(n shared.Node, subscriptionID string) shared.NodeUser {
	derive := func(purpose string) []byte {
		mac := hmac.New(sha256.New, s.key)
		_, _ = mac.Write([]byte("mui-user-v1\x00" + purpose + "\x00" + n.ID + "\x00" + subscriptionID))
		return mac.Sum(nil)
	}
	key := derive("login")
	if n.Protocol == "ss" && n.Method == "2022-blake3-aes-128-gcm" {
		key = key[:16]
	}
	password := base64.RawURLEncoding.EncodeToString(key)
	if n.Protocol == "ss" {
		password = base64.StdEncoding.EncodeToString(key)
	}
	return shared.NodeUser{
		SubscriptionID:    subscriptionID,
		Name:              "mui-" + n.ID + "-" + subscriptionID,
		Password:          password,
		ShadowTLSPassword: base64.RawURLEncoding.EncodeToString(derive("shadowtls")),
	}
}
func (s *Store) PutNode(v shared.Node, password string) error {
	secret, err := s.Encrypt(password)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO mui_nodes(id,server_id,data,secret) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data,secret=excluded.secret`, v.ID, v.ServerID, Marshal(v), secret)
	return err
}
func (s *Store) PutNodeWithShadowTLS(v shared.Node, password, shadowTLSPassword string) error {
	secret, err := s.Encrypt(password)
	if err != nil {
		return err
	}
	shadowSecret := ""
	if shadowTLSPassword != "" {
		shadowSecret, err = s.Encrypt(shadowTLSPassword)
		if err != nil {
			return err
		}
	}
	_, err = s.DB.Exec(`INSERT INTO mui_nodes(id,server_id,data,secret,shadow_tls_secret) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data,secret=excluded.secret,shadow_tls_secret=excluded.shadow_tls_secret`, v.ID, v.ServerID, Marshal(v), secret, shadowSecret)
	return err
}
func (s *Store) Certificates(serverID string) ([]shared.Certificate, error) {
	if serverID == "" {
		return queryJSON[shared.Certificate](s.DB, `SELECT data FROM mui_certificates ORDER BY id`)
	}
	return queryJSON[shared.Certificate](s.DB, `SELECT data FROM mui_certificates WHERE server_id=$1 ORDER BY id`, serverID)
}
func (s *Store) Certificate(id string) (shared.Certificate, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_certificates WHERE id=$1`, id).Scan(&raw)
	var v shared.Certificate
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
func (s *Store) CertificateKey(id string) (string, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT secret FROM mui_certificates WHERE id=$1`, id).Scan(&raw)
	if err != nil {
		return "", err
	}
	return s.Decrypt(raw)
}
func (s *Store) PutCertificate(v shared.Certificate) error {
	secret, err := s.Encrypt(v.Key)
	if err != nil {
		return err
	}
	v.Key = ""
	_, err = s.DB.Exec(`INSERT INTO mui_certificates(id,server_id,data,secret) VALUES($1,$2,$3,$4)`, v.ID, v.ServerID, Marshal(v), secret)
	return err
}
func (s *Store) Rules(serverID string) ([]shared.FirewallRule, error) {
	if serverID == "" {
		return queryJSON[shared.FirewallRule](s.DB, `SELECT data FROM mui_firewall_rules ORDER BY id`)
	}
	return queryJSON[shared.FirewallRule](s.DB, `SELECT data FROM mui_firewall_rules WHERE server_id=$1 ORDER BY id`, serverID)
}
func (s *Store) Forwards(serverID string) ([]shared.ForwardRule, error) {
	var list []shared.ForwardRule
	var err error
	if serverID == "" {
		list, err = queryJSON[shared.ForwardRule](s.DB, `SELECT data FROM mui_forwards ORDER BY id`)
	} else {
		list, err = queryJSON[shared.ForwardRule](s.DB, `SELECT data FROM mui_forwards WHERE server_id=$1 ORDER BY id`, serverID)
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(`SELECT forward_id,uplink,downlink FROM mui_forward_totals`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	totals := map[string][2]int64{}
	for rows.Next() {
		var id string
		var up, down int64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		totals[id] = [2]int64{up, down}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
	}
	return list, nil
}
func (s *Store) Forward(id string) (shared.ForwardRule, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_forwards WHERE id=$1`, id).Scan(&raw)
	var v shared.ForwardRule
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
func (s *Store) PutForward(v shared.ForwardRule) error {
	v.Uplink, v.Downlink = 0, 0
	_, err := s.DB.Exec(`INSERT INTO mui_forwards(id,server_id,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data`, v.ID, v.ServerID, Marshal(v))
	return err
}

// ownedIDs resolves, in one query, which of ids belong to serverID in table.
// Table and column names are fixed literals from the callers, never input.
func ownedIDs(ctx context.Context, tx *sql.Tx, table, serverID string, ids []string) (map[string]bool, error) {
	seen := map[string]bool{}
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	out := map[string]bool{}
	if len(unique) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(unique)+1)
	args = append(args, serverID)
	placeholders := make([]string, 0, len(unique))
	for i, id := range unique {
		args = append(args, id)
		placeholders = append(placeholders, "$"+strconv.Itoa(i+2))
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM `+table+` WHERE server_id=$1 AND id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
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
		if point.ForwardID == "" || point.InstanceID == "" || point.Uplink < 0 || point.Downlink < 0 {
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
func (s *Store) Subscriptions() ([]shared.Subscription, error) {
	return queryJSON[shared.Subscription](s.DB, `SELECT data FROM mui_subscriptions ORDER BY id`)
}
func (s *Store) SubscriptionByToken(token string) (shared.Subscription, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_subscriptions WHERE token_hash=$1`, Hash(token)).Scan(&raw)
	var v shared.Subscription
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
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
		if p.NodeID == "" || p.InstanceID == "" || p.Uplink < 0 || p.Downlink < 0 {
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
	for _, p := range points {
		nodeIDs = append(nodeIDs, p.NodeID)
	}
	owned, err := ownedIDs(ctx, tx, "mui_nodes", serverID, nodeIDs)
	if err != nil {
		return err
	}
	for _, p := range points {
		if p.NodeID == "" || p.SubscriptionID == "" || p.InstanceID == "" || p.Uplink < 0 || p.Downlink < 0 || p.At.IsZero() {
			continue
		}
		if !owned[p.NodeID] {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, p := range points {
		if p.BootID == "" || p.Interface == "" || p.Sequence <= 0 || p.Rx < 0 || p.Tx < 0 {
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
	}
	return tx.Commit()
}
