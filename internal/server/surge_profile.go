package server

import (
	"database/sql"
	"encoding/json"
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

type surgeTemplateValidationError struct{ msg string }

func (e surgeTemplateValidationError) Error() string { return e.msg }

type surgeTemplateConflictError struct{ msg string }

func (e surgeTemplateConflictError) Error() string { return e.msg }

func surgeTemplateNameKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
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
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM mui_surge_templates WHERE name_key=$1 AND id<>$2`, surgeTemplateNameKey(name), exceptID).Scan(&count)
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

func (s *Store) checkSurgeTemplateTx(tx *sql.Tx, sub shared.Subscription) error {
	if sub.Format != "surge" {
		if sub.SurgeTemplateID != "" {
			return surgeTemplateValidationError{"只有 Surge 订阅可以选择完整配置模板"}
		}
		return nil
	}
	id := sub.SurgeTemplateID
	if id == "" {
		id = "default"
	}
	query := `SELECT 1 FROM mui_surge_templates WHERE id=$1`
	if s.driver == "pgx" {
		query += ` FOR SHARE`
	}
	var one int
	err := tx.QueryRow(query, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return surgeTemplateValidationError{"所选 Surge 模板不存在"}
	}
	return err
}

func (s *Store) CreateSubscription(sub shared.Subscription, tokenHash, sealedToken string) error {
	s.surgeTemplateMu.Lock()
	defer s.surgeTemplateMu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.checkSurgeTemplateTx(tx, sub); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO mui_subscriptions(id,data,token_hash,token_enc) VALUES($1,$2,$3,$4)`, sub.ID, Marshal(sub), tokenHash, sealedToken); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateSubscription(id string, in shared.Subscription) (previous, updated shared.Subscription, err error) {
	s.surgeTemplateMu.Lock()
	defer s.surgeTemplateMu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return previous, updated, err
	}
	defer tx.Rollback()
	if err = s.checkSurgeTemplateTx(tx, in); err != nil {
		return previous, updated, err
	}
	query := `SELECT data FROM mui_subscriptions WHERE id=$1`
	if s.driver == "pgx" {
		query += ` FOR UPDATE`
	}
	var raw string
	if err = tx.QueryRow(query, id).Scan(&raw); err != nil {
		return previous, updated, err
	}
	if err = json.Unmarshal([]byte(raw), &previous); err != nil {
		return previous, updated, err
	}
	updated = previous
	updated.Name = in.Name
	updated.CustomerID = in.CustomerID
	updated.Format = in.Format
	updated.SurgeTemplateID = in.SurgeTemplateID
	updated.NodeIDs = in.NodeIDs
	updated.RouteIDs = in.RouteIDs
	updated.Enabled = in.Enabled
	updated.ExpiresAt = in.ExpiresAt
	if _, err = tx.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(updated), id); err != nil {
		return previous, updated, err
	}
	return previous, updated, tx.Commit()
}

func (s *Store) DeleteSurgeTemplate(id string) (string, error) {
	s.surgeTemplateMu.Lock()
	defer s.surgeTemplateMu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	query := `SELECT name FROM mui_surge_templates WHERE id=$1`
	if s.driver == "pgx" {
		query += ` FOR UPDATE`
	}
	var name string
	if err := tx.QueryRow(query, id).Scan(&name); err != nil {
		return "", err
	}
	if id == "default" {
		return "", surgeTemplateConflictError{"默认模板不能删除"}
	}
	rows, err := tx.Query(`SELECT data FROM mui_subscriptions ORDER BY id`)
	if err != nil {
		return "", err
	}
	var usedBy string
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var sub struct {
			Name            string `json:"name"`
			SurgeTemplateID string `json:"surgeTemplateId"`
		}
		if err = json.Unmarshal([]byte(raw), &sub); err != nil {
			break
		}
		if sub.SurgeTemplateID == id {
			usedBy = sub.Name
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return "", err
	}
	if usedBy != "" {
		return "", surgeTemplateConflictError{"该模板仍被订阅“" + usedBy + "”使用，请先为订阅选择其他模板"}
	}
	if _, err := tx.Exec(`DELETE FROM mui_surge_templates WHERE id=$1`, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return name, nil
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
	if _, err = a.Store.DB.Exec(`INSERT INTO mui_surge_templates(id,name,name_key,template) VALUES($1,$2,$3,$4)`, item.ID, item.Name, surgeTemplateNameKey(item.Name), item.Template); err != nil {
		if isUniqueViolation(err) {
			errorJSON(w, 400, "模板名称已存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "surge_template.create", item.ID, item.Name)
	writeJSON(w, 201, item)
}

func (a *App) surgeTemplateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.Method == http.MethodDelete {
		name, err := a.Store.DeleteSurgeTemplate(id)
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "Surge 模板不存在")
			return
		}
		var conflict surgeTemplateConflictError
		if errors.As(err, &conflict) {
			errorJSON(w, 409, conflict.Error())
			return
		}
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "surge_template.delete", id, name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
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
	res, err := a.Store.DB.Exec(`UPDATE mui_surge_templates SET name=$1,name_key=$2,template=$3 WHERE id=$4`, name, surgeTemplateNameKey(name), template, id)
	if err != nil {
		if isUniqueViolation(err) {
			errorJSON(w, 400, "模板名称已存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		errorJSON(w, 404, "Surge 模板不存在")
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
