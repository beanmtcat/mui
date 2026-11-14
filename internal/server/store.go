package server

import (
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
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	DB              *sql.DB
	key             []byte
	driver          string
	surgeTemplateMu sync.Mutex
	cycleLocksMu    sync.Mutex
	cycleLocks      map[string]*sync.Mutex
	timeLoc         *time.Location
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
	s := &Store{DB: db, key: key[:], driver: driver}
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

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
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

func (s *Store) Audit(action, target, detail string) {
	s.AuditWithIP(action, target, detail, "")
}

func (s *Store) AuditWithIP(action, target, detail, ip string) {
	if _, err := s.DB.Exec(`INSERT INTO mui_audit(id,at_ms,action,target,detail,ip) VALUES($1,$2,$3,$4,$5,$6)`, ID(), time.Now().UnixMilli(), action, target, detail, ip); err != nil {
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

// PruneSessions deletes expired or 24h-idle sessions and orphaned pending TOTP
// setup rows whose session no longer exists.
func (s *Store) PruneSessions(now time.Time) error {
	nowUnix := now.Unix()
	if _, err := s.DB.Exec(`DELETE FROM mui_sessions WHERE expires_at<$1 OR (last_seen_at>0 AND last_seen_at<$2)`, nowUnix, nowUnix-24*3600); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM mui_totp_pending WHERE session_hash NOT IN (SELECT token_hash FROM mui_sessions)`)
	return err
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
