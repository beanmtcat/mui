package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"

	"mui/internal/shared"
)

// Unsigned installs trust the panel's manifest and expected hash. A pinned
// release key additionally requires a valid signature, with no fallback.
func fetchUpgradeManifest(ctx context.Context, client *http.Client, prefix string, key ed25519.PublicKey, name, expected string) ([]byte, error) {
	manifest, err := fetchSmall(ctx, client, prefix+"SHA256SUMS")
	if err != nil {
		return nil, err
	}
	if key != nil {
		signature, err := fetchSmall(ctx, client, prefix+"SHA256SUMS.sig")
		if err != nil {
			return nil, err
		}
		if err = shared.VerifyManifest(key, manifest, signature); err != nil {
			return nil, err
		}
	}
	if listed, ok := shared.ManifestHash(manifest, name); !ok || listed != expected {
		return nil, fmt.Errorf("%s is not listed with the expected hash in the release manifest", name)
	}
	return manifest, nil
}

func fetchSmall(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", endpoint, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}
