package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshDatabaseUsesMuiTables(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "mui.db"), "Test-Secret-With-32-Bytes-1234!Aa")
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	for _, name := range legacyTables {
		assertTable(t, store, "mui_"+name, true)
		assertTable(t, store, name, false)
	}
}

func TestLegacySQLiteFileAndTablesMoveTogether(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "panel.db")
	newPath := filepath.Join(dir, "mui.db")
	secret := "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(oldPath, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO mui_admin(id,password_hash) VALUES(1,'preserved-hash')`); err != nil {
		t.Fatal(err)
	}
	for _, name := range legacyTables {
		if _, err := store.DB.Exec("ALTER TABLE mui_" + name + " RENAME TO " + name); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacySQLiteFile(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("legacy file still exists: %v", err)
	}
	store, err = NewStore(newPath, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	var hash string
	if err := store.DB.QueryRow(`SELECT password_hash FROM mui_admin WHERE id=1`).Scan(&hash); err != nil || hash != "preserved-hash" {
		t.Fatalf("database row was not preserved: %q, %v", hash, err)
	}
}

func TestLegacySQLiteFileConflictIsRejected(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "panel.db")
	newPath := filepath.Join(dir, "mui.db")
	for _, path := range []string{oldPath, newPath} {
		if err := os.WriteFile(path, []byte("database"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateLegacySQLiteFile(oldPath, newPath); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestMigrationRejectsMixedTableNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mui.db")
	secret := "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	store.DB.Close()
	if _, err := NewStore(path, secret); err == nil || !strings.Contains(err.Error(), "both schema_migrations and mui_schema_migrations exist") {
		t.Fatalf("expected mixed-schema error, got %v", err)
	}
}

func TestLegacyTablesAreRenamedWithoutLosingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mui.db")
	secret := "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO mui_admin(id,password_hash) VALUES(1,'existing-hash')`); err != nil {
		t.Fatal(err)
	}
	for _, name := range legacyTables {
		if _, err := store.DB.Exec("ALTER TABLE mui_" + name + " RENAME TO " + name); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	for _, name := range legacyTables {
		assertTable(t, store, "mui_"+name, true)
		assertTable(t, store, name, false)
	}
	var hash string
	if err := store.DB.QueryRow(`SELECT password_hash FROM mui_admin WHERE id=1`).Scan(&hash); err != nil || hash != "existing-hash" {
		t.Fatalf("old admin row lost: %q, %v", hash, err)
	}
	var version int
	if err := store.DB.QueryRow(`SELECT MAX(version) FROM mui_schema_migrations`).Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("migration history changed: %d, %v", version, err)
	}
}

func assertTable(t *testing.T, store *Store, name string, want bool) {
	t.Helper()
	var count int
	if err := store.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$1`, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if got := count > 0; got != want {
		t.Fatalf("table %s exists = %v, want %v", name, got, want)
	}
}
