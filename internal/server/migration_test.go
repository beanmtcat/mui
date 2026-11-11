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

func TestSurgeTemplateMigrationKeepsExistingProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mui.db")
	secret := "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	profile := "[Proxy]\n{{PROXIES}}\n[Rule]\nFINAL,DIRECT\n"
	if _, err := store.DB.Exec(`INSERT INTO mui_settings(key,value) VALUES('surge_profile_template',$1)`, profile); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DROP TABLE mui_surge_templates`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DELETE FROM mui_schema_migrations WHERE version>=22`); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	got, err := store.SurgeTemplateContent("")
	if err != nil || got != profile {
		t.Fatalf("migrated profile: %q, %v", got, err)
	}
	if _, err := store.DB.Exec(`INSERT INTO mui_subscriptions(id,data,token_hash) VALUES('old',$1,'old-token')`, `{"id":"old","name":"Old Surge","format":"surge"}`); err != nil {
		t.Fatal(err)
	}
	subs, err := store.Subscriptions()
	if err != nil || len(subs) != 1 || subs[0].SurgeTemplateID != "" {
		t.Fatalf("legacy subscription changed: %#v, %v", subs, err)
	}
}

func TestSurgeTemplateNameKeyMigrationDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mui.db")
	secret := "Test-Secret-With-32-Bytes-1234!Aa"
	store, err := NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`DROP TABLE mui_surge_templates`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`CREATE TABLE mui_surge_templates (id TEXT PRIMARY KEY, name TEXT NOT NULL, template TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	body := "[Proxy]\n{{PROXIES}}\n[Rule]\nFINAL,DIRECT\n"
	for _, row := range [][3]string{
		{"default", "默认模板", ""},
		{"dup-default", "  默认模板  ", body},
		{"work-1", "Work", body},
		{"work-2", " work ", body},
		{"work-3", "Work (2)", body},
		{"cyr-1", "Берлин", body},
		{"cyr-2", "берлин", body},
	} {
		if _, err := store.DB.Exec(`INSERT INTO mui_surge_templates(id,name,template) VALUES($1,$2,$3)`, row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB.Exec(`DELETE FROM mui_schema_migrations WHERE version>=23`); err != nil {
		t.Fatal(err)
	}
	if err := store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	rows, err := store.DB.Query(`SELECT id,name,name_key FROM mui_surge_templates ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][2]string{}
	for rows.Next() {
		var id, name, key string
		if err := rows.Scan(&id, &name, &key); err != nil {
			t.Fatal(err)
		}
		got[id] = [2]string{name, key}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][2]string{
		"default":     {"默认模板", "默认模板"},
		"dup-default": {"默认模板 (2)", "默认模板 (2)"},
		"work-1":      {"Work", "work"},
		"work-2":      {"work (2)", "work (2)"},
		"work-3":      {"Work (2) (2)", "work (2) (2)"},
		"cyr-1":       {"Берлин", "берлин"},
		"cyr-2":       {"берлин (2)", "берлин (2)"},
	} {
		if got[id] != want {
			t.Fatalf("migrated template %s = %#v, want %#v", id, got[id], want)
		}
	}
	if _, err := store.DB.Exec(`INSERT INTO mui_surge_templates(id,name,name_key,template) VALUES('collide','WORK','work',$1)`, body); !isUniqueViolation(err) {
		t.Fatalf("expected unique violation on name_key, got %v", err)
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
