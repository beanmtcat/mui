// release-sign creates the key pair and the detached signatures that let
// agents verify upgrades independently of the panel that serves them.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 2 && args[0] == "keygen":
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		// O_EXCL: never overwrite a key that already signed releases.
		f, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err = f.WriteString(base64.StdEncoding.EncodeToString(private.Seed()) + "\n"); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		fmt.Println("private key written to", args[1], "- keep it off the panel host")
		fmt.Println("MUI_RELEASE_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(public))
		return nil
	case len(args) == 3 && args[0] == "sign":
		info, err := os.Stat(args[1])
		if err != nil {
			return err
		}
		// Never sign with a private key other users on the host can read.
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			return fmt.Errorf("refusing to use private key %s: permissions %04o are wider than 0600", args[1], perm)
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("%s is not a release-sign private key", args[1])
		}
		manifest, err := os.ReadFile(filepath.Join(args[2], "SHA256SUMS"))
		if err != nil {
			return err
		}
		private := ed25519.NewKeyFromSeed(seed)
		signature := ed25519.Sign(private, manifest)
		// Verify with the derived public key before publishing the signature.
		if !ed25519.Verify(private.Public().(ed25519.PublicKey), manifest, signature) {
			return fmt.Errorf("self-verification of the signature failed")
		}
		// Atomic write: a reader must never see a half-written signature.
		sigPath := filepath.Join(args[2], "SHA256SUMS.sig")
		tmp, err := os.CreateTemp(args[2], ".SHA256SUMS.sig.*.tmp")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		if _, err = tmp.WriteString(base64.StdEncoding.EncodeToString(signature) + "\n"); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
		if err = tmp.Chmod(0644); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
		if err = tmp.Close(); err != nil {
			os.Remove(tmpName)
			return err
		}
		if err = os.Rename(tmpName, sigPath); err != nil {
			os.Remove(tmpName)
			return err
		}
		return nil
	}
	return fmt.Errorf("usage: release-sign keygen PRIVATE_KEY_FILE | release-sign sign PRIVATE_KEY_FILE RELEASE_DIR")
}
