package server

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"mui/internal/shared"
)

type serverInput struct {
	shared.Server
	// nil preserves the existing token; an empty string removes it.
	KomariToken *string `json:"komariToken,omitempty"`
}

func validateKomariEndpoint(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", nil
	}
	if len(raw) > 500 {
		return "", errors.New("Komari 地址过长")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("Komari 地址无效")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1") {
		return "", errors.New("Komari 地址必须使用 HTTPS；本机 127.0.0.1 可使用 HTTP")
	}
	return u.String(), nil
}

func validateKomariToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if len(token) > 2048 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("Komari token 格式无效")
	}
	return token, nil
}

func (s *Store) KomariEndpoint() (string, error) {
	var endpoint string
	err := s.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='komari_endpoint'`).Scan(&endpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return endpoint, err
}

func (s *Store) SetKomariEndpoint(endpoint string) error {
	_, err := s.DB.Exec(`INSERT INTO mui_settings(key,value) VALUES('komari_endpoint',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, endpoint)
	return err
}

func (s *Store) KomariToken(id string) (string, error) {
	var sealed string
	err := s.DB.QueryRow(`SELECT token_enc FROM mui_komari_tokens WHERE server_id=$1`, id).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s.Decrypt(sealed)
}

func (s *Store) SetKomariToken(id, token string) error {
	if token == "" {
		_, err := s.DB.Exec(`DELETE FROM mui_komari_tokens WHERE server_id=$1`, id)
		return err
	}
	sealed, err := s.Encrypt(token)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO mui_komari_tokens(server_id,token_enc) VALUES($1,$2) ON CONFLICT(server_id) DO UPDATE SET token_enc=excluded.token_enc`, id, sealed)
	return err
}

func (s *Store) KomariTokenFlags() (map[string]bool, error) {
	rows, err := s.DB.Query(`SELECT server_id FROM mui_komari_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	flags := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		flags[id] = true
	}
	return flags, rows.Err()
}

func (a *App) komariSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		endpoint, err := a.Store.KomariEndpoint()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"endpoint": endpoint})
		return
	}
	var in struct {
		Endpoint string `json:"endpoint"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	endpoint, err := validateKomariEndpoint(in.Endpoint)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.SetKomariEndpoint(endpoint); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "settings.komari", "", endpoint)
	writeJSON(w, 200, map[string]string{"endpoint": endpoint})
}

// The signed Agent request receives only its own token. An absent token or
// endpoint produces an empty config, so the Agent never starts Komari work.
func (a *App) agentKomari(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.Header.Get("X-Server-ID")
	endpoint, err := a.Store.KomariEndpoint()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if endpoint == "" {
		writeJSON(w, 200, map[string]string{"endpoint": "", "token": ""})
		return
	}
	token, err := a.Store.KomariToken(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if token == "" {
		endpoint = ""
	}
	writeJSON(w, 200, map[string]string{"endpoint": endpoint, "token": token})
}
