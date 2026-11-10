package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"mui/internal/shared"
)

type surgeTemplate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Template string `json:"template"`
	Custom   bool   `json:"custom,omitempty"`
}

func (s *Store) SurgeTemplates() ([]surgeTemplate, error) {
	rows, err := s.DB.Query(`SELECT id,name,template FROM mui_surge_templates ORDER BY CASE WHEN id='default' THEN 0 ELSE 1 END,name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []surgeTemplate{}
	for rows.Next() {
		var item surgeTemplate
		if err := rows.Scan(&item.ID, &item.Name, &item.Template); err != nil {
			return nil, err
		}
		item.Custom = item.ID == "default" && item.Template != ""
		if item.Template == "" {
			item.Template = shared.DefaultSurgeProfileTemplate
		}
		list = append(list, item)
	}
	return list, rows.Err()
}

func (s *Store) surgeTemplateNameExists(name, exceptID string) (bool, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM mui_surge_templates WHERE lower(name)=lower($1) AND id<>$2`, name, exceptID).Scan(&count)
	return count > 0, err
}

func (s *Store) SurgeTemplateContent(id string) (string, error) {
	if id == "" {
		id = "default"
	}
	var template string
	err := s.DB.QueryRow(`SELECT template FROM mui_surge_templates WHERE id=$1`, id).Scan(&template)
	if err != nil {
		return "", err
	}
	return template, nil
}

func (a *App) checkSurgeTemplate(sub shared.Subscription) error {
	if sub.Format != "surge" {
		if sub.SurgeTemplateID != "" {
			return errors.New("只有 Surge 订阅可以选择完整配置模板")
		}
		return nil
	}
	_, err := a.Store.SurgeTemplateContent(sub.SurgeTemplateID)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("所选 Surge 模板不存在")
	}
	return err
}

// An empty stored template means the built-in default, so later releases can
// improve the default for everyone who never customised it.
func (s *Store) SurgeProfileTemplate() (string, error) {
	return s.SurgeTemplateContent("default")
}

func (s *Store) SetSurgeProfileTemplate(template string) error {
	_, err := s.DB.Exec(`UPDATE mui_surge_templates SET template=$1 WHERE id='default'`, template)
	return err
}

func (a *App) surgeTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := a.Store.SurgeTemplates()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, list)
		return
	}
	var in struct {
		Name     string `json:"name"`
		Template string `json:"template"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > 80 {
		errorJSON(w, 400, "模板名称应为 1–80 个字符")
		return
	}
	exists, err := a.Store.surgeTemplateNameExists(name, "")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if exists {
		errorJSON(w, 400, "模板名称已存在")
		return
	}
	template, err := shared.ValidateSurgeProfileTemplate(in.Template)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	item := surgeTemplate{ID: ID(), Name: name, Template: template}
	if _, err = a.Store.DB.Exec(`INSERT INTO mui_surge_templates(id,name,template) VALUES($1,$2,$3)`, item.ID, item.Name, item.Template); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "surge_template.create", item.ID, item.Name)
	writeJSON(w, 201, item)
}

func (a *App) surgeTemplateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var current surgeTemplate
	err := a.Store.DB.QueryRow(`SELECT id,name,template FROM mui_surge_templates WHERE id=$1`, id).Scan(&current.ID, &current.Name, &current.Template)
	if errors.Is(err, sql.ErrNoRows) {
		errorJSON(w, 404, "Surge 模板不存在")
		return
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if r.Method == http.MethodDelete {
		if id == "default" {
			errorJSON(w, 409, "默认模板不能删除")
			return
		}
		subs, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, sub := range subs {
			if sub.SurgeTemplateID == id {
				errorJSON(w, 409, "该模板仍被订阅“"+sub.Name+"”使用，请先为订阅选择其他模板")
				return
			}
		}
		if _, err := a.Store.DB.Exec(`DELETE FROM mui_surge_templates WHERE id=$1`, id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "surge_template.delete", id, current.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in struct {
		Name     string `json:"name"`
		Template string `json:"template"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if id == "default" {
		name = "默认模板"
	}
	if name == "" || len([]rune(name)) > 80 {
		errorJSON(w, 400, "模板名称应为 1–80 个字符")
		return
	}
	if id != "default" {
		exists, err := a.Store.surgeTemplateNameExists(name, id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if exists {
			errorJSON(w, 400, "模板名称已存在")
			return
		}
	}
	template := ""
	if strings.TrimSpace(in.Template) != "" {
		if template, err = shared.ValidateSurgeProfileTemplate(in.Template); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		if id == "default" && strings.TrimSpace(template) == strings.TrimSpace(shared.DefaultSurgeProfileTemplate) {
			template = ""
		}
	} else if id != "default" {
		errorJSON(w, 400, "自定义模板内容不能为空")
		return
	}
	custom := id == "default" && template != ""
	if _, err := a.Store.DB.Exec(`UPDATE mui_surge_templates SET name=$1,template=$2 WHERE id=$3`, name, template, id); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "surge_template.update", id, name)
	if template == "" {
		template = shared.DefaultSurgeProfileTemplate
	}
	writeJSON(w, 200, surgeTemplate{ID: id, Name: name, Template: template, Custom: custom})
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
