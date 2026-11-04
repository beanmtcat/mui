package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"mui/internal/shared"
)

// An empty stored template means the built-in default, so later releases can
// improve the default for everyone who never customised it.
func (s *Store) SurgeProfileTemplate() (string, error) {
	var template string
	err := s.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='surge_profile_template'`).Scan(&template)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return template, err
}

func (s *Store) SetSurgeProfileTemplate(template string) error {
	_, err := s.DB.Exec(`INSERT INTO mui_settings(key,value) VALUES('surge_profile_template',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, template)
	return err
}

func (a *App) surgeProfileSetting(w http.ResponseWriter, r *http.Request) {
	reply := func(template string) {
		custom := template != ""
		if !custom {
			template = shared.DefaultSurgeProfileTemplate
		}
		writeJSON(w, 200, map[string]any{"template": template, "custom": custom, "defaultTemplate": shared.DefaultSurgeProfileTemplate})
	}
	if r.Method == http.MethodGet {
		template, err := a.Store.SurgeProfileTemplate()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		reply(template)
		return
	}
	var in struct {
		Template string `json:"template"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	template := ""
	if strings.TrimSpace(in.Template) != "" {
		var err error
		if template, err = shared.ValidateSurgeProfileTemplate(in.Template); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		if strings.TrimSpace(template) == strings.TrimSpace(shared.DefaultSurgeProfileTemplate) {
			template = ""
		}
	}
	if err := a.Store.SetSurgeProfileTemplate(template); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	action := "custom"
	if template == "" {
		action = "default"
	}
	a.auditRequest(r, "settings.surge_profile", "", action)
	reply(template)
}
