package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"mui/internal/shared"
)

const OfflineBundlePath = ForwardDir + "/panel-bundle.json"

func readOfflineDocument(path string) ([]shared.ForwardRule, []byte, *shared.OfflineBundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(raw) > 1<<20 {
		return nil, nil, nil, errors.New("离线配置不能超过 1 MiB")
	}
	if len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '{' {
		// A panel file is signed as a whole, unknown fields included, and
		// says which agent it needs; see shared.ParseOfflineBundle.
		bundle, err := shared.ParseOfflineBundle(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := bundle.CheckAgentVersion(Version); err != nil {
			return nil, nil, nil, err
		}
		forwards, _ := json.Marshal(bundle.Forwards)
		rules, canonical, err := parseOfflineForwards(forwards)
		return rules, canonical, &bundle, err
	}
	rules, canonical, err := parseOfflineForwards(raw)
	return rules, canonical, nil, err
}

func checkOfflineIdentity(bundle *shared.OfflineBundle) error {
	raw, err := os.ReadFile(OfflineBundlePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	previous, err := shared.ParseOfflineBundle(raw)
	if err != nil {
		return err
	}
	if bundle == nil {
		return errors.New("此机由面板离线配置管理，不能用本地规则覆盖；请从面板导出配置")
	}
	if previous.ServerID != bundle.ServerID || previous.PanelPublicKey != bundle.PanelPublicKey {
		return errors.New("离线配置与本机固定的服务器身份或面板公钥不符")
	}
	if bundle.Revision < previous.Revision {
		return errors.New("不能应用旧版本的离线配置，请重新从面板导出")
	}
	if bundle.Revision == previous.Revision {
		// Compare the signed values, including fields this agent ignores.
		a, err := bundle.CanonicalForwards()
		if err != nil {
			return err
		}
		b, err := previous.CanonicalForwards()
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			return errors.New("不能应用同版本不同内容的离线配置，请重新从面板导出")
		}
	}
	return nil
}

// Called only after the forwarding process has acknowledged this config.
func commitOfflineBundle(bundle *shared.OfflineBundle) error {
	if bundle == nil {
		return nil
	}
	// Keep the file as received: re-encoding it would drop fields this
	// agent does not know and break its signature.
	return writeFileAtomic(OfflineBundlePath, bundle.Raw(), 0600)
}
