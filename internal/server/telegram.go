package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultTelegramAPIBase  = "https://api.telegram.org"
	telegramQueueCapacity   = 200
	telegramMaxMessageRunes = 3500
	maxExpiryAlertRequeues  = 3
)

var (
	// Package-level knobs overridden only by unit tests; never exposed via API or env.
	testAllowInsecureTelegramAPI = false
	telegramRetryDelays          = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}
	telegramMaxRetryAfter        = 60 * time.Second
	telegramRateWindow           = time.Minute
	telegramMaxPerMinute         = 20

	telegramNumericChatRe = regexp.MustCompile(`^-?[0-9]{1,20}$`)
	telegramChannelChatRe = regexp.MustCompile(`^@[A-Za-z0-9_]{5,32}$`)
	telegramBotTokenRe    = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,256}$`)
)

type TelegramServerOfflineEvent struct {
	Enabled        bool `json:"enabled"`
	OfflineMinutes int  `json:"offlineMinutes"`
}

type TelegramToggleEvent struct {
	Enabled bool `json:"enabled"`
}

type TelegramResourceEvent struct {
	Enabled   bool `json:"enabled"`
	Minutes   int  `json:"minutes"`
	Threshold int  `json:"threshold"`
}

type TelegramThresholdEvent struct {
	Enabled   bool `json:"enabled"`
	Threshold int  `json:"threshold"`
}

type TelegramTrafficReport struct {
	Daily   bool `json:"daily"`
	Weekly  bool `json:"weekly"`
	Monthly bool `json:"monthly"`
}

type TelegramEvents struct {
	ServerOffline        TelegramServerOfflineEvent `json:"serverOffline"`
	ApplyFailed          TelegramToggleEvent        `json:"applyFailed"`
	CertExpiring         TelegramToggleEvent        `json:"certExpiring"`
	SubscriptionExpiring TelegramToggleEvent        `json:"subscriptionExpiring"`
	ServerExpiring       TelegramToggleEvent        `json:"serverExpiring"`
	ServerRenewed        TelegramToggleEvent        `json:"serverRenewed"`
	TrafficLimit         TelegramThresholdEvent     `json:"trafficLimit"`
	TrafficReport        TelegramTrafficReport      `json:"trafficReport"`
	Resource             TelegramResourceEvent      `json:"resource"`
	Security             TelegramToggleEvent        `json:"security"`
}

type TelegramSettingsResponse struct {
	Enabled     bool           `json:"enabled"`
	BotTokenSet bool           `json:"botTokenSet"`
	ChatID      string         `json:"chatId"`
	ThreadID    int            `json:"threadId"`
	APIBase     string         `json:"apiBase"`
	Events      TelegramEvents `json:"events"`
}

type storedTelegramSettings struct {
	Enabled     bool           `json:"enabled"`
	BotTokenEnc string         `json:"botTokenEnc"`
	ChatID      string         `json:"chatId"`
	ThreadID    int            `json:"threadId"`
	APIBase     string         `json:"apiBase"`
	Events      TelegramEvents `json:"events"`
}

type telegramRuntimeConfig struct {
	Enabled  bool
	BotToken string
	ChatID   string
	ThreadID int
	APIBase  string
	Events   TelegramEvents
}

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

func defaultTelegramEvents() TelegramEvents {
	return TelegramEvents{
		ServerOffline:        TelegramServerOfflineEvent{Enabled: true, OfflineMinutes: 3},
		ApplyFailed:          TelegramToggleEvent{Enabled: true},
		CertExpiring:         TelegramToggleEvent{Enabled: true},
		SubscriptionExpiring: TelegramToggleEvent{Enabled: false},
		ServerExpiring:       TelegramToggleEvent{Enabled: true},
		ServerRenewed:        TelegramToggleEvent{Enabled: true},
		TrafficLimit:         TelegramThresholdEvent{Enabled: true, Threshold: 80},
		TrafficReport:        TelegramTrafficReport{Daily: false, Weekly: false, Monthly: false},
		Resource:             TelegramResourceEvent{Enabled: false, Minutes: 5, Threshold: 90},
		Security:             TelegramToggleEvent{Enabled: true},
	}
}

func defaultStoredTelegramSettings() storedTelegramSettings {
	return storedTelegramSettings{
		Events: defaultTelegramEvents(),
	}
}

func (c telegramRuntimeConfig) effectiveAPIBase() string {
	if c.APIBase != "" {
		return c.APIBase
	}
	return defaultTelegramAPIBase
}

func (c telegramRuntimeConfig) eventEnabled(event string) bool {
	switch event {
	case "serverOffline":
		return c.Events.ServerOffline.Enabled
	case "applyFailed":
		return c.Events.ApplyFailed.Enabled
	case "certExpiring":
		return c.Events.CertExpiring.Enabled
	case "subscriptionExpiring":
		return c.Events.SubscriptionExpiring.Enabled
	case "serverExpiring":
		return c.Events.ServerExpiring.Enabled
	case "serverRenewed":
		return c.Events.ServerRenewed.Enabled
	case "trafficLimit":
		return c.Events.TrafficLimit.Enabled
	case "trafficReport":
		return c.Events.TrafficReport.Daily || c.Events.TrafficReport.Weekly || c.Events.TrafficReport.Monthly
	case "resource":
		return c.Events.Resource.Enabled
	case "security":
		return c.Events.Security.Enabled
	default:
		return false
	}
}

func validateTelegramChatID(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if telegramNumericChatRe.MatchString(s) || telegramChannelChatRe.MatchString(s) {
		return s, nil
	}
	return "", errors.New("Chat ID 格式无效，应为数字（可带负号）或 @频道名")
}

func validateTelegramBotToken(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("Bot Token 格式无效")
	}
	if !telegramBotTokenRe.MatchString(s) {
		return "", errors.New("Bot Token 格式无效")
	}
	return s, nil
}

func validateTelegramAPIBase(raw string) (string, error) {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", nil
	}
	if len(s) > 500 {
		return "", errors.New("Telegram API 地址过长")
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("Telegram API 地址格式无效")
	}
	allowedScheme := u.Scheme == "https" || (testAllowInsecureTelegramAPI && u.Scheme == "http")
	if !allowedScheme {
		return "", errors.New("Telegram API 地址必须使用 https")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("Telegram API 地址不能包含认证信息、查询参数或片段")
	}
	return s, nil
}

func normalizeStoredTelegramEvents(ev *TelegramEvents) {
	if ev.ServerOffline.OfflineMinutes < 2 || ev.ServerOffline.OfflineMinutes > 60 {
		ev.ServerOffline.OfflineMinutes = 3
	}
	if ev.Resource.Minutes < 1 || ev.Resource.Minutes > 60 {
		ev.Resource.Minutes = 5
	}
	if ev.Resource.Threshold < 1 || ev.Resource.Threshold > 100 {
		ev.Resource.Threshold = 90
	}
	if ev.TrafficLimit.Threshold < 50 || ev.TrafficLimit.Threshold > 100 {
		ev.TrafficLimit.Threshold = 80
	}
}

func (s *Store) loadStoredTelegramSettings() (storedTelegramSettings, error) {
	cfg := defaultStoredTelegramSettings()
	var raw string
	err := s.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='telegram'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	normalizeStoredTelegramEvents(&cfg.Events)
	return cfg, nil
}

func (s *Store) saveStoredTelegramSettings(cfg storedTelegramSettings) error {
	_, err := s.DB.Exec(`INSERT INTO mui_settings(key,value) VALUES('telegram',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, Marshal(cfg))
	return err
}

func (a *App) loadTelegramRuntimeConfig() (telegramRuntimeConfig, error) {
	stored, err := a.Store.loadStoredTelegramSettings()
	if err != nil {
		return telegramRuntimeConfig{}, err
	}
	var token string
	if stored.BotTokenEnc != "" {
		token, err = a.Store.Decrypt(stored.BotTokenEnc)
		if err != nil {
			// Do not include ciphertext or underlying details in logs.
			log.Printf("telegram settings: failed to decrypt bot token")
			return telegramRuntimeConfig{}, errors.New("failed to decrypt bot token")
		}
	}
	return telegramRuntimeConfig{
		Enabled:  stored.Enabled,
		BotToken: token,
		ChatID:   stored.ChatID,
		ThreadID: stored.ThreadID,
		APIBase:  stored.APIBase,
		Events:   stored.Events,
	}, nil
}

func telegramResponseFromStored(stored storedTelegramSettings) TelegramSettingsResponse {
	return TelegramSettingsResponse{
		Enabled:     stored.Enabled,
		BotTokenSet: stored.BotTokenEnc != "",
		ChatID:      stored.ChatID,
		ThreadID:    stored.ThreadID,
		APIBase:     stored.APIBase,
		Events:      stored.Events,
	}
}

type telegramEventsInput struct {
	ServerOffline *struct {
		Enabled        *bool `json:"enabled"`
		OfflineMinutes *int  `json:"offlineMinutes"`
	} `json:"serverOffline"`
	ApplyFailed *struct {
		Enabled *bool `json:"enabled"`
	} `json:"applyFailed"`
	CertExpiring *struct {
		Enabled *bool `json:"enabled"`
	} `json:"certExpiring"`
	SubscriptionExpiring *struct {
		Enabled *bool `json:"enabled"`
	} `json:"subscriptionExpiring"`
	ServerExpiring *struct {
		Enabled *bool `json:"enabled"`
	} `json:"serverExpiring"`
	ServerRenewed *struct {
		Enabled *bool `json:"enabled"`
	} `json:"serverRenewed"`
	TrafficLimit *struct {
		Enabled   *bool `json:"enabled"`
		Threshold *int  `json:"threshold"`
	} `json:"trafficLimit"`
	TrafficReport *struct {
		Daily   *bool `json:"daily"`
		Weekly  *bool `json:"weekly"`
		Monthly *bool `json:"monthly"`
	} `json:"trafficReport"`
	Resource *struct {
		Enabled   *bool `json:"enabled"`
		Minutes   *int  `json:"minutes"`
		Threshold *int  `json:"threshold"`
	} `json:"resource"`
	Security *struct {
		Enabled *bool `json:"enabled"`
	} `json:"security"`
}

func applyTelegramEventsInput(base TelegramEvents, in *telegramEventsInput) (TelegramEvents, error) {
	out := base
	if in == nil {
		return out, nil
	}
	if in.ServerOffline != nil {
		if in.ServerOffline.Enabled != nil {
			out.ServerOffline.Enabled = *in.ServerOffline.Enabled
		}
		if in.ServerOffline.OfflineMinutes != nil {
			m := *in.ServerOffline.OfflineMinutes
			if m < 2 || m > 60 {
				return out, errors.New("服务器离线时长阈值需在 2–60 分钟之间")
			}
			out.ServerOffline.OfflineMinutes = m
		}
	}
	if in.ApplyFailed != nil && in.ApplyFailed.Enabled != nil {
		out.ApplyFailed.Enabled = *in.ApplyFailed.Enabled
	}
	if in.CertExpiring != nil && in.CertExpiring.Enabled != nil {
		out.CertExpiring.Enabled = *in.CertExpiring.Enabled
	}
	if in.SubscriptionExpiring != nil && in.SubscriptionExpiring.Enabled != nil {
		out.SubscriptionExpiring.Enabled = *in.SubscriptionExpiring.Enabled
	}
	if in.ServerExpiring != nil && in.ServerExpiring.Enabled != nil {
		out.ServerExpiring.Enabled = *in.ServerExpiring.Enabled
	}
	if in.ServerRenewed != nil && in.ServerRenewed.Enabled != nil {
		out.ServerRenewed.Enabled = *in.ServerRenewed.Enabled
	}
	if in.TrafficLimit != nil {
		if in.TrafficLimit.Enabled != nil {
			out.TrafficLimit.Enabled = *in.TrafficLimit.Enabled
		}
		if in.TrafficLimit.Threshold != nil {
			t := *in.TrafficLimit.Threshold
			if t < 50 || t > 100 {
				return out, errors.New("流量告警阈值需在 50–100% 之间")
			}
			out.TrafficLimit.Threshold = t
		}
	}
	if in.TrafficReport != nil {
		if in.TrafficReport.Daily != nil {
			out.TrafficReport.Daily = *in.TrafficReport.Daily
		}
		if in.TrafficReport.Weekly != nil {
			out.TrafficReport.Weekly = *in.TrafficReport.Weekly
		}
		if in.TrafficReport.Monthly != nil {
			out.TrafficReport.Monthly = *in.TrafficReport.Monthly
		}
	}
	if in.Resource != nil {
		if in.Resource.Enabled != nil {
			out.Resource.Enabled = *in.Resource.Enabled
		}
		if in.Resource.Minutes != nil {
			m := *in.Resource.Minutes
			if m < 1 || m > 60 {
				return out, errors.New("资源持续时长需在 1–60 分钟之间")
			}
			out.Resource.Minutes = m
		}
		if in.Resource.Threshold != nil {
			t := *in.Resource.Threshold
			if t < 1 || t > 100 {
				return out, errors.New("资源使用率阈值需在 1–100% 之间")
			}
			out.Resource.Threshold = t
		}
	}
	if in.Security != nil && in.Security.Enabled != nil {
		out.Security.Enabled = *in.Security.Enabled
	}
	return out, nil
}

func (a *App) telegramSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		stored, err := a.Store.loadStoredTelegramSettings()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, telegramResponseFromStored(stored))
		return
	}

	var in struct {
		Enabled  *bool                `json:"enabled"`
		BotToken *string              `json:"botToken"`
		ChatID   *string              `json:"chatId"`
		ThreadID *int                 `json:"threadId"`
		APIBase  *string              `json:"apiBase"`
		Events   *telegramEventsInput `json:"events"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	stored, err := a.Store.loadStoredTelegramSettings()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}

	if in.Enabled != nil {
		stored.Enabled = *in.Enabled
	}
	if in.BotToken != nil {
		if *in.BotToken == "" {
			stored.BotTokenEnc = ""
		} else {
			cleanToken, err := validateTelegramBotToken(*in.BotToken)
			if err != nil {
				errorJSON(w, 400, err.Error())
				return
			}
			sealed, err := a.Store.Encrypt(cleanToken)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
			stored.BotTokenEnc = sealed
		}
	}
	if in.ChatID != nil {
		cleanChat, err := validateTelegramChatID(*in.ChatID)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		stored.ChatID = cleanChat
	}
	if in.ThreadID != nil {
		if *in.ThreadID < 0 {
			errorJSON(w, 400, "话题 ID 需为正整数")
			return
		}
		stored.ThreadID = *in.ThreadID
	}
	if in.APIBase != nil {
		cleanBase, err := validateTelegramAPIBase(*in.APIBase)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		stored.APIBase = cleanBase
	}
	nextEvents, err := applyTelegramEventsInput(stored.Events, in.Events)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	stored.Events = nextEvents

	if stored.Enabled {
		if stored.BotTokenEnc == "" {
			errorJSON(w, 400, "启用 Telegram 告警前请填写 Bot Token")
			return
		}
		if stored.ChatID == "" {
			errorJSON(w, 400, "启用 Telegram 告警前请填写 Chat ID")
			return
		}
	}

	if err := a.Store.saveStoredTelegramSettings(stored); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	detail := fmt.Sprintf("enabled=%t tokenSet=%t chatId=%s threadId=%d apiBase=%s",
		stored.Enabled, stored.BotTokenEnc != "", stored.ChatID, stored.ThreadID, stored.APIBase)
	a.auditRequest(r, "settings.telegram", "", detail)
	writeJSON(w, 200, telegramResponseFromStored(stored))
}

func (a *App) telegramTest(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadTelegramRuntimeConfig()
	if err != nil {
		errorJSON(w, 500, "无法读取 Telegram 配置")
		return
	}
	if cfg.BotToken == "" || cfg.ChatID == "" {
		errorJSON(w, 400, "请先保存 Bot Token 和 Chat ID")
		return
	}
	// Re-validate stored APIBase before dialling so a tampered DB row cannot bypass HTTPS rules.
	if _, err := validateTelegramAPIBase(cfg.APIBase); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	text := fmt.Sprintf("[MUI] 测试通知\nTelegram 告警通道正常。\n时间：%s", formatAlertTime(time.Now()))
	// Release a.mu (acquired by a.require for POST) while making the outbound HTTP call.
	a.mu.Unlock()
	res := a.sendTelegramOnce(r.Context(), cfg, text)
	a.mu.Lock()
	if !res.ok {
		writeJSON(w, 502, map[string]string{"error": res.safeReason})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
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
