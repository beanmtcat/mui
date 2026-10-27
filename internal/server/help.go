package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type helpArticle struct {
	ID        string `json:"id"`
	Question  string `json:"question"`
	Answer    string `json:"answer"`
	Position  int    `json:"position"`
	UpdatedAt int64  `json:"updatedAt"`
}

type helpArticleInput struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
	Position int    `json:"position"`
}

func (s *Store) helpArticles() ([]helpArticle, error) {
	rows, err := s.DB.Query(`SELECT id,question,answer,position,updated_at FROM mui_help_articles ORDER BY position,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []helpArticle{}
	for rows.Next() {
		var item helpArticle
		if err := rows.Scan(&item.ID, &item.Question, &item.Answer, &item.Position, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) helpArticle(id string) (helpArticle, error) {
	var item helpArticle
	err := s.DB.QueryRow(`SELECT id,question,answer,position,updated_at FROM mui_help_articles WHERE id=$1`, id).
		Scan(&item.ID, &item.Question, &item.Answer, &item.Position, &item.UpdatedAt)
	return item, err
}

func validHelpArticle(in *helpArticleInput) bool {
	in.Question = strings.TrimSpace(in.Question)
	in.Answer = strings.TrimSpace(strings.ReplaceAll(in.Answer, "\r\n", "\n"))
	return in.Question != "" && in.Answer != "" && len(in.Question) <= 200 && len(in.Answer) <= 50000 && in.Position >= 0 && in.Position <= 9999
}

func (a *App) helpArticles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		items, err := a.Store.helpArticles()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, items)
		return
	}
	var in helpArticleInput
	if !readJSON(w, r, &in) {
		return
	}
	if !validHelpArticle(&in) {
		errorJSON(w, 400, "问题、答案或排序无效")
		return
	}
	item := helpArticle{ID: ID(), Question: in.Question, Answer: in.Answer, Position: in.Position, UpdatedAt: time.Now().UnixMilli()}
	if _, err := a.Store.DB.Exec(`INSERT INTO mui_help_articles(id,question,answer,position,updated_at) VALUES($1,$2,$3,$4,$5)`, item.ID, item.Question, item.Answer, item.Position, item.UpdatedAt); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "help.create", item.ID, item.Question)
	writeJSON(w, 201, item)
}

func (a *App) helpArticleByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.helpArticle(id)
	if errors.Is(err, sql.ErrNoRows) {
		errorJSON(w, 404, "帮助条目不存在")
		return
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if r.Method == http.MethodDelete {
		if _, err := a.Store.DB.Exec(`DELETE FROM mui_help_articles WHERE id=$1`, id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "help.delete", id, old.Question)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in helpArticleInput
	if !readJSON(w, r, &in) {
		return
	}
	if !validHelpArticle(&in) {
		errorJSON(w, 400, "问题、答案或排序无效")
		return
	}
	old.Question, old.Answer, old.Position, old.UpdatedAt = in.Question, in.Answer, in.Position, time.Now().UnixMilli()
	if _, err := a.Store.DB.Exec(`UPDATE mui_help_articles SET question=$1,answer=$2,position=$3,updated_at=$4 WHERE id=$5`, old.Question, old.Answer, old.Position, old.UpdatedAt, id); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "help.update", id, old.Question)
	writeJSON(w, 200, old)
}
