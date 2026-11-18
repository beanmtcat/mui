package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const defaultTelegramAPIBase = "https://api.telegram.org"

var (
	// Package-level knobs overridden only by unit tests; never exposed via API or env.
	testAllowInsecureTelegramAPI = false

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
	RelayState           TelegramToggleEvent        `json:"relayState"`
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

func defaultTelegramEvents() TelegramEvents {
	return TelegramEvents{
		RelayState:           TelegramToggleEvent{Enabled: true},
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
	case "relayState":
		return c.Events.RelayState.Enabled
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
	RelayState *struct {
		Enabled *bool `json:"enabled"`
	} `json:"relayState"`
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
	if in.RelayState != nil && in.RelayState.Enabled != nil {
		out.RelayState.Enabled = *in.RelayState.Enabled
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
