package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "release.key")
	// keygen prints the public key on stdout; capture it.
	read, write, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = write
	err := run([]string{"keygen", keyFile})
	write.Close()
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := read.Read(buf)
	_, encoded, found := strings.Cut(string(buf[:n]), "MUI_RELEASE_PUBLIC_KEY=")
	if !found {
		t.Fatalf("no public key in output: %s", buf[:n])
	}
	key, err := shared.ParseReleaseKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"keygen", keyFile}); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
	manifest := []byte("aaaa  mui-agent\nbbbb  sing-box\n")
	if err = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"sign", keyFile, dir}); err != nil {
		t.Fatal(err)
	}
	signature, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err = shared.VerifyManifest(key, manifest, signature); err != nil {
		t.Fatal(err)
	}
	if shared.VerifyManifest(key, []byte("cccc  mui-agent\nbbbb  sing-box\n"), signature) == nil {
		t.Fatal("a modified manifest passed verification")
	}
	if hash, ok := shared.ManifestHash(manifest, "sing-box"); !ok || hash != "bbbb" {
		t.Fatalf("manifest lookup: %q %v", hash, ok)
	}
}
