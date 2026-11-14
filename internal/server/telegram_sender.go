package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	telegramQueueCapacity   = 200
	telegramMaxMessageRunes = 3500
	maxExpiryAlertRequeues  = 3
)

var (
	// Package-level knobs overridden only by unit tests; never exposed via API or env.
	telegramRetryDelays   = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}
	telegramMaxRetryAfter = 60 * time.Second
	telegramRateWindow    = time.Minute
	telegramMaxPerMinute  = 20
)

type alertStateRollback struct {
	key   string
	round int
}

type telegramNotice struct {
	event       string
	key         string
	text        string
	mergedCount int
	rollbacks   []alertStateRollback
}

type telegramSendResult struct {
	ok         bool
	statusCode int
	retryAfter time.Duration
	safeReason string
}

func truncateRunes(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	if maxRunes == 1 {
		return "…"
	}
	return string(runes[:maxRunes-1]) + "…"
}

func formatNoticeText(n telegramNotice) string {
	if n.mergedCount <= 0 {
		return truncateRunes(n.text, telegramMaxMessageRunes)
	}
	suffix := fmt.Sprintf("\n\n另有 %d 条同类告警", n.mergedCount)
	suffixRunes := utf8.RuneCountInString(suffix)
	if suffixRunes >= telegramMaxMessageRunes {
		return truncateRunes(suffix, telegramMaxMessageRunes)
	}
	body := truncateRunes(n.text, telegramMaxMessageRunes-suffixRunes)
	return body + suffix
}

// notify enqueues a Telegram notification without blocking or holding request locks.
func (a *App) notify(event, key, text string) {
	a.notifyStateful(event, key, text, nil)
}

func (a *App) notifyStateful(event, key, text string, rollbacks []alertStateRollback) {
	if a == nil {
		return
	}
	var evicted telegramNotice
	var hasEvicted bool

	a.tgMu.Lock()
	if a.tgStop != nil {
		select {
		case <-a.tgStop:
			a.tgMu.Unlock()
			return
		default:
		}
	}
	if len(a.tgQueue) >= telegramQueueCapacity {
		evicted = a.tgQueue[0]
		hasEvicted = len(evicted.rollbacks) > 0
		copy(a.tgQueue, a.tgQueue[1:])
		a.tgQueue[len(a.tgQueue)-1] = telegramNotice{}
		a.tgQueue = a.tgQueue[:len(a.tgQueue)-1]
		a.tgDropped++
	}
	a.tgQueue = append(a.tgQueue, telegramNotice{
		event:     event,
		key:       key,
		text:      text,
		rollbacks: rollbacks,
	})
	if !a.tgRunning {
		a.tgRunning = true
		a.tgIdle = make(chan struct{})
		idle := a.tgIdle
		go a.runTelegramSender(idle)
	}
	a.tgMu.Unlock()

	if hasEvicted {
		go a.rollbackFailedStatefulNotice(evicted)
	}
}

func (a *App) rollbackFailedStatefulNotice(item telegramNotice) {
	if a == nil || a.Store == nil || len(item.rollbacks) == 0 {
		return
	}
	nowMs := time.Now().UnixMilli()
	for _, rb := range item.rollbacks {
		if rb.round >= maxExpiryAlertRequeues {
			continue
		}
		nextStatus := fmt.Sprintf("retry:%d", rb.round+1)
		_, _ = a.Store.DB.Exec(
			`UPDATE mui_alert_state SET status=$1,updated_ms=$2 WHERE key=$3 AND status='sent'`,
			nextStatus, nowMs, rb.key,
		)
	}
}

// FlushTelegramForTest waits until the background sender drains all queued items.
func (a *App) FlushTelegramForTest(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		a.tgMu.Lock()
		running := a.tgRunning
		idle := a.tgIdle
		a.tgMu.Unlock()
		if !running || idle == nil {
			return true
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return false
		}
		select {
		case <-idle:
		case <-time.After(rem):
			return false
		}
	}
}

// CloseTelegram stops the background Telegram sender cleanly.
func (a *App) CloseTelegram() {
	a.tgMu.Lock()
	if a.tgStop != nil {
		select {
		case <-a.tgStop:
		default:
			close(a.tgStop)
		}
	}
	idle := a.tgIdle
	running := a.tgRunning
	a.tgMu.Unlock()
	if running && idle != nil {
		<-idle
	}
}

func (a *App) coalesceHeadLocked() {
	if len(a.tgQueue) <= 1 {
		return
	}
	head := a.tgQueue[0]
	kept := a.tgQueue[:1]
	for _, item := range a.tgQueue[1:] {
		if item.event == head.event {
			head.mergedCount += 1 + item.mergedCount
			head.rollbacks = append(head.rollbacks, item.rollbacks...)
		} else {
			kept = append(kept, item)
		}
	}
	kept[0] = head
	for i := len(kept); i < len(a.tgQueue); i++ {
		a.tgQueue[i] = telegramNotice{}
	}
	a.tgQueue = kept
}

func (a *App) telegramSleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	if a.tgStop == nil {
		<-timer.C
		return true
	}
	select {
	case <-timer.C:
		return true
	case <-a.tgStop:
		return false
	}
}

func (a *App) runTelegramSender(idle chan struct{}) {
	defer close(idle)
	var lastLoggedDrops uint64
	for {
		cfg, cfgErr := a.loadTelegramRuntimeConfig()
		if cfgErr == nil {
			if _, err := validateTelegramAPIBase(cfg.APIBase); err != nil {
				cfgErr = err
			}
		}

		a.tgMu.Lock()
		if a.tgStop != nil {
			select {
			case <-a.tgStop:
				a.tgQueue = nil
				a.tgRunning = false
				a.tgMu.Unlock()
				return
			default:
			}
		}
		if cfgErr != nil || !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
			a.tgQueue = nil
			a.tgRunning = false
			a.tgMu.Unlock()
			return
		}

		// Filter out notices for events that are currently disabled.
		kept := a.tgQueue[:0]
		for _, item := range a.tgQueue {
			if cfg.eventEnabled(item.event) {
				kept = append(kept, item)
			}
		}
		for i := len(kept); i < len(a.tgQueue); i++ {
			a.tgQueue[i] = telegramNotice{}
		}
		a.tgQueue = kept

		if a.tgDropped > lastLoggedDrops {
			delta := a.tgDropped - lastLoggedDrops
			lastLoggedDrops = a.tgDropped
			log.Printf("telegram queue overflow: dropped %d oldest alert(s)", delta)
		}

		if len(a.tgQueue) == 0 {
			a.tgRunning = false
			a.tgMu.Unlock()
			return
		}

		now := time.Now()
		windowStart := now.Add(-telegramRateWindow)
		validTimes := a.tgSentTimes[:0]
		for _, t := range a.tgSentTimes {
			if t.After(windowStart) {
				validTimes = append(validTimes, t)
			}
		}
		a.tgSentTimes = validTimes

		maxPerMin := max(1, telegramMaxPerMinute)
		if len(a.tgSentTimes) >= maxPerMin {
			a.coalesceHeadLocked()
			wait := a.tgSentTimes[0].Add(telegramRateWindow).Sub(now)
			a.tgMu.Unlock()
			if !a.telegramSleep(wait) {
				a.tgMu.Lock()
				a.tgQueue = nil
				a.tgRunning = false
				a.tgMu.Unlock()
				return
			}
			continue
		}

		// When this send hits the last slot in the current minute and more alerts
		// are waiting, coalesce same-event items immediately so the summary goes
		// out within the current minute's 20-message budget.
		if len(a.tgSentTimes)+len(a.tgQueue) > maxPerMin && len(a.tgSentTimes) == maxPerMin-1 {
			a.coalesceHeadLocked()
		}

		item := a.tgQueue[0]
		copy(a.tgQueue, a.tgQueue[1:])
		a.tgQueue[len(a.tgQueue)-1] = telegramNotice{}
		a.tgQueue = a.tgQueue[:len(a.tgQueue)-1]
		a.tgSentTimes = append(a.tgSentTimes, now)
		a.tgMu.Unlock()

		delivered, stopped := a.deliverTelegramWithRetry(cfg, formatNoticeText(item))
		if stopped {
			a.tgMu.Lock()
			a.tgQueue = nil
			a.tgRunning = false
			a.tgMu.Unlock()
			return
		}
		if !delivered {
			a.rollbackFailedStatefulNotice(item)
		}
	}
}

func (a *App) deliverTelegramWithRetry(cfg telegramRuntimeConfig, text string) (delivered bool, stopped bool) {
	delays := telegramRetryDelays
	for attempt := 0; ; attempt++ {
		ctx := context.Background()
		if a.tgStop != nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			stopDone := make(chan struct{})
			go func() {
				select {
				case <-a.tgStop:
					cancel()
				case <-stopDone:
				}
			}()
			res := a.sendTelegramOnce(ctx, cfg, text)
			close(stopDone)
			cancel()
			if res.ok {
				return true, false
			}
			select {
			case <-a.tgStop:
				return false, true
			default:
			}
			if attempt >= len(delays) {
				log.Printf("telegram send failed after %d retries (%s): %s", attempt, cfg.ChatID, res.safeReason)
				return false, false
			}
			wait := delays[attempt]
			if res.statusCode == http.StatusTooManyRequests && res.retryAfter > 0 {
				wait = min(res.retryAfter, telegramMaxRetryAfter)
			}
			if !a.telegramSleep(wait) {
				return false, true
			}
			continue
		}

		res := a.sendTelegramOnce(ctx, cfg, text)
		if res.ok {
			return true, false
		}
		if attempt >= len(delays) {
			log.Printf("telegram send failed after %d retries (%s): %s", attempt, cfg.ChatID, res.safeReason)
			return false, false
		}
		wait := delays[attempt]
		if res.statusCode == http.StatusTooManyRequests && res.retryAfter > 0 {
			wait = min(res.retryAfter, telegramMaxRetryAfter)
		}
		if !a.telegramSleep(wait) {
			return false, true
		}
	}
}

func (a *App) telegramHTTPClient() *http.Client {
	if a != nil && a.tgClient != nil {
		return a.tgClient
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func sanitizeTelegramText(s string, cfg telegramRuntimeConfig) string {
	s = strings.TrimSpace(s)
	if cfg.BotToken != "" {
		s = strings.ReplaceAll(s, cfg.BotToken, "[REDACTED]")
	}
	if cfg.APIBase != "" {
		s = strings.ReplaceAll(s, cfg.APIBase, "[REDACTED]")
	}
	s = strings.ReplaceAll(s, defaultTelegramAPIBase, "[REDACTED]")
	// Scrub any residual https:// or http:// URLs so upstream error strings never leak endpoints.
	for _, scheme := range []string{"https://", "http://"} {
		for {
			idx := strings.Index(s, scheme)
			if idx < 0 {
				break
			}
			end := idx + len(scheme)
			for end < len(s) && s[end] > ' ' && s[end] != '"' && s[end] != '\'' && s[end] != ')' && s[end] != ']' {
				end++
			}
			s = s[:idx] + "[REDACTED]" + s[end:]
		}
	}
	return truncateRunes(s, 300)
}

func (a *App) sendTelegramOnce(ctx context.Context, cfg telegramRuntimeConfig, text string) telegramSendResult {
	payload := map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     truncateRunes(text, telegramMaxMessageRunes),
		"disable_web_page_preview": true,
	}
	if cfg.ThreadID > 0 {
		payload["message_thread_id"] = cfg.ThreadID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return telegramSendResult{safeReason: "连接失败"}
	}
	endpoint := cfg.effectiveAPIBase() + "/bot" + cfg.BotToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		// Never surface net/url errors, which echo the input URL containing the bot token.
		return telegramSendResult{safeReason: "连接失败"}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.telegramHTTPClient().Do(req)
	if err != nil {
		// net/http wraps the full request URL (including bot token) in *url.Error; replace unconditionally.
		return telegramSendResult{safeReason: "连接失败"}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return telegramSendResult{statusCode: resp.StatusCode, safeReason: "连接失败"}
	}

	var tgResp struct {
		OK          *bool  `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.Unmarshal(raw, &tgResp)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && (tgResp.OK == nil || *tgResp.OK) {
		return telegramSendResult{ok: true, statusCode: resp.StatusCode}
	}

	var retryAfter time.Duration
	if resp.StatusCode == http.StatusTooManyRequests {
		if tgResp.Parameters.RetryAfter > 0 {
			retryAfter = time.Duration(tgResp.Parameters.RetryAfter) * time.Second
		} else if hdr := strings.TrimSpace(resp.Header.Get("Retry-After")); hdr != "" {
			if secs, convErr := strconv.Atoi(hdr); convErr == nil && secs > 0 {
				retryAfter = time.Duration(secs) * time.Second
			}
		}
	}

	reason := sanitizeTelegramText(tgResp.Description, cfg)
	if reason == "" {
		reason = "连接失败"
	}
	return telegramSendResult{
		ok:         false,
		statusCode: resp.StatusCode,
		retryAfter: retryAfter,
		safeReason: reason,
	}
}
