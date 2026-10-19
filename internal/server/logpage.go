package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Log listings come in numbered pages: ?page=N&pageSize=M answers with
// {items, total}. Without page they keep the older ?before= cursor form.

type logPage struct {
	paged      bool
	page, size int
}

func readLogPage(r *http.Request) (logPage, error) {
	raw := r.URL.Query().Get("page")
	if raw == "" {
		return logPage{}, nil
	}
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 || page > 100000 {
		return logPage{}, errors.New("页码无效")
	}
	size, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || size < 1 {
		size = 20
	}
	return logPage{paged: true, page: page, size: min(size, 200)}, nil
}

func (p logPage) offset() int { return (p.page - 1) * p.size }

// rangeMs reads ?fromMs= and ?toMs= (inclusive, Unix milliseconds).
func rangeMs(r *http.Request) (from, to int64, err error) {
	from, to = -1, -1
	for _, side := range []struct {
		param string
		dst   *int64
	}{{"fromMs", &from}, {"toMs", &to}} {
		raw := r.URL.Query().Get(side.param)
		if raw == "" {
			continue
		}
		ms, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || ms < 0 || ms > 1<<50 {
			return 0, 0, errors.New("日期范围无效")
		}
		*side.dst = ms
	}
	return from, to, nil
}

// timeRange limits a millisecond time column to ?fromMs=..?toMs=.
func (q *logQuery) timeRange(r *http.Request, column string) error {
	from, to, err := rangeMs(r)
	if from >= 0 {
		q.where(column + ">=" + q.arg(from))
	}
	if to >= 0 {
		q.where(column + "<=" + q.arg(to))
	}
	return err
}

// idRange limits a time-ordered ID column to ?fromMs=..?toMs=. IDs start with
// their creation time in nanoseconds as 16 hex digits, so they compare like
// times; the upper bound is the start of the next millisecond, exclusive.
func (q *logQuery) idRange(r *http.Request, column string) error {
	from, to, err := rangeMs(r)
	if from >= 0 {
		q.where(column + ">=" + q.arg(fmt.Sprintf("%016x", from*1_000_000)))
	}
	if to >= 0 {
		q.where(column + "<" + q.arg(fmt.Sprintf("%016x", (to+1)*1_000_000)))
	}
	return err
}

// count is the number of rows the filters match, for the page total.
func (a *App) count(q *logQuery) (int, error) {
	filtered := q.filtered()
	from := strings.Index(filtered, " FROM ")
	if from < 0 {
		return 0, errors.New("log query without FROM")
	}
	var n int
	err := a.Store.DB.QueryRow("SELECT COUNT(*)"+filtered[from:], q.args...).Scan(&n)
	return n, err
}

// writeLogPage answers a paged listing with its items and total.
func (a *App) writeLogPage(w http.ResponseWriter, q *logQuery, items any) {
	total, err := a.count(q)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}
