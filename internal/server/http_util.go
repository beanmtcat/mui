package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// pageLimit reads ?limit=, between 1 and 500. Without it a caller gets the
// 200 most recent rows, as every list did before paging existed.
func pageLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n < 1 {
		return 200
	}
	return min(n, 500)
}

// logQuery assembles the optional filters of a log listing with numbered
// placeholders. Column names come from the handlers, never from the request.
type logQuery struct {
	base    string
	clauses []string
	args    []any
}

func newLogQuery(base string) (*logQuery, *[]any) {
	q := &logQuery{base: base}
	return q, &q.args
}

func (q *logQuery) arg(value any) string {
	q.args = append(q.args, value)
	return "$" + strconv.Itoa(len(q.args))
}

func (q *logQuery) where(clause string) { q.clauses = append(q.clauses, clause) }

func (q *logQuery) equal(column, value string) {
	if value != "" {
		q.where(column + "=" + q.arg(value))
	}
}

func (q *logQuery) before(column, value string) {
	if value != "" {
		q.where(column + "<" + q.arg(value))
	}
}

func (q *logQuery) filtered() string {
	if len(q.clauses) == 0 {
		return q.base
	}
	return q.base + " WHERE " + strings.Join(q.clauses, " AND ")
}

func (q *logQuery) sql(order string, limit, offset int) string {
	s := q.filtered() + " ORDER BY " + order + " LIMIT " + strconv.Itoa(limit)
	if offset > 0 {
		s += " OFFSET " + strconv.Itoa(offset)
	}
	return s
}

// likeEscape makes user text match literally inside a LIKE pattern.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// clip shortens untrusted text to at most max bytes without splitting a rune.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && s[max]&0xC0 == 0x80 {
		max--
	}
	return s[:max]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errorJSON(w http.ResponseWriter, status int, msg string) {
	if status == 500 {
		// Internal details (database errors, driver messages) must not reach
		// the client; they go to the server log instead. Other 5xx codes
		// (503, ...) carry client-meaningful reasons and keep them.
		log.Printf("internal error (%d): %s", status, msg)
		msg = "内部错误"
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

// paginateList serves a list endpoint with optional cursor paging. Without
// ?limit= the legacy behaviour is kept: the full bare array. With ?limit= the
// response is an envelope {items, nextCursor, total}; cursor is the ID of the
// last item already seen (IDs sort chronologically). limit is clamped to 500.
func paginateList[T any](w http.ResponseWriter, r *http.Request, list []T, getID func(T) string) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		writeJSON(w, 200, list)
		return
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		limit = 100
	}
	limit = min(limit, 500)
	cursor := r.URL.Query().Get("cursor")
	page := make([]T, 0, limit)
	nextCursor := ""
	for _, item := range list {
		id := getID(item)
		if cursor != "" && id <= cursor {
			continue
		}
		if len(page) >= limit {
			break
		}
		page = append(page, item)
	}
	// nextCursor is the last returned ID, set only when more items remain.
	if len(page) == limit {
		for _, item := range list {
			if getID(item) > getID(page[len(page)-1]) {
				nextCursor = getID(page[len(page)-1])
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"items": page, "nextCursor": nextCursor, "total": len(list)})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		errorJSON(w, 400, err.Error())
		return false
	}
	return true
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
