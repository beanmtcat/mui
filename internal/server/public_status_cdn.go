package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mui/internal/shared"
)

const (
	publicCDNGroupName  = "CDN"
	publicCDNCacheCtrl  = "public, max-age=15"
	maxJSCallbackLength = 64
)

// PublicCDNServerItem is the compact public status and latest latency summary for one CDN node.
type PublicCDNServerItem struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Country  string     `json:"country"`
	Region   string     `json:"region,omitempty"`
	City     string     `json:"city,omitempty"`
	Online   bool       `json:"online"`
	Ms       *int       `json:"ms"`
	Loss     *float64   `json:"loss"`
	TestedAt *time.Time `json:"testedAt,omitempty"`
}

// PublicCDNStatusResponse is the payload emitted by /api/public/cdn.json and /api/public/cdn.js.
type PublicCDNStatusResponse struct {
	GeneratedAt time.Time             `json:"generatedAt"`
	ShowPing    bool                  `json:"showPing"`
	Total       int                   `json:"total"`
	Online      int                   `json:"online"`
	Servers     []PublicCDNServerItem `json:"servers"`
}

// Reject JS keywords and browser/global identifiers so optional JSONP callbacks
// cannot invoke built-ins or reserved syntax if reflected in a script tag.
var forbiddenJSCallbacks = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true,
	"continue": true, "debugger": true, "default": true, "delete": true, "do": true,
	"else": true, "enum": true, "export": true, "extends": true, "false": true,
	"finally": true, "for": true, "function": true, "if": true, "import": true,
	"in": true, "instanceof": true, "let": true, "new": true, "null": true,
	"return": true, "super": true, "switch": true, "this": true, "throw": true,
	"true": true, "try": true, "typeof": true, "var": true, "void": true,
	"while": true, "with": true, "yield": true, "await": true,
	"eval": true, "Function": true, "Object": true, "Array": true, "String": true,
	"Number": true, "Boolean": true, "Symbol": true, "BigInt": true, "RegExp": true,
	"Error": true, "Promise": true, "Proxy": true, "Reflect": true, "Date": true,
	"JSON": true, "Math": true, "Intl": true, "WebAssembly": true, "Worker": true,
	"SharedWorker": true, "XMLHttpRequest": true, "WebSocket": true, "EventSource": true,
	"BroadcastChannel": true, "Notification": true, "Audio": true, "Image": true,
	"Option": true, "Request": true, "Response": true, "Headers": true, "URL": true,
	"Blob": true, "File": true, "FormData": true, "setTimeout": true, "setInterval": true,
	"clearTimeout": true, "clearInterval": true, "requestAnimationFrame": true,
	"cancelAnimationFrame": true, "queueMicrotask": true, "structuredClone": true,
	"atob": true, "btoa": true, "fetch": true, "importScripts": true,
	"alert": true, "confirm": true, "prompt": true, "open": true, "close": true,
	"print": true, "stop": true, "focus": true, "blur": true,
	"scroll": true, "scrollTo": true, "scrollBy": true, "moveTo": true, "moveBy": true,
	"resizeTo": true, "resizeBy": true, "postMessage": true, "dispatchEvent": true,
	"addEventListener": true, "removeEventListener": true, "getSelection": true,
	"find": true, "reportError": true, "createImageBitmap": true, "caches": true,
	"crypto": true, "document": true, "window": true, "self": true, "top": true,
	"parent": true, "frames": true, "globalThis": true, "location": true,
	"history": true, "navigator": true,
}

// validPublicJSCallback restricts JSONP callbacks to a single safe ASCII identifier.
func validPublicJSCallback(raw string) bool {
	if len(raw) == 0 || len(raw) > maxJSCallbackLength {
		return false
	}
	c0 := raw[0]
	if !((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_' || c0 == '$') {
		return false
	}
	for i := 1; i < len(raw); i++ {
		c := raw[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '$') {
			return false
		}
	}
	return !forbiddenJSCallbacks[raw]
}

// formatPublicCDNScript wraps compact JSON bytes in an IIFE that publishes
// window.__MUI_CDN_STATUS__, dispatches mui:cdn-status, and invokes an optional callback.
func formatPublicCDNScript(jsonBody []byte, callback string) []byte {
	var b strings.Builder
	b.Grow(len(jsonBody) + 256)
	b.WriteString(`/**/;(function(d){if(typeof window!=="undefined"){window.__MUI_CDN_STATUS__=d;if(typeof window.dispatchEvent==="function"&&typeof CustomEvent==="function"){window.dispatchEvent(new CustomEvent("mui:cdn-status",{detail:d}));}}`)
	if callback != "" {
		b.WriteString(`if(typeof `)
		b.WriteString(callback)
		b.WriteString(`==="function"){`)
		b.WriteString(callback)
		b.WriteString(`(d);}else if(typeof window!=="undefined"&&typeof window["`)
		b.WriteString(callback)
		b.WriteString(`"]==="function"){window["`)
		b.WriteString(callback)
		b.WriteString(`"](d);}`)
	}
	b.WriteString(`})(`)
	b.Write(jsonBody)
	b.WriteString(");\n")
	return []byte(b.String())
}

// buildPublicCDNStatusSnapshot aggregates visible CDN servers and their latest ping summary.
func (a *App) buildPublicCDNStatusSnapshot(cfg storedStatusPageSettings, now time.Time) ([]byte, error) {
	allServers, err := a.Store.Servers()
	if err != nil {
		return nil, err
	}
	allVisible := visiblePublicServers(allServers)
	cdnServers := make([]shared.Server, 0, len(allVisible))
	for _, s := range allVisible {
		if strings.EqualFold(strings.TrimSpace(s.Group), publicCDNGroupName) {
			cdnServers = append(cdnServers, s)
		}
	}
	sortPublicServers(cdnServers)

	var pingMap publicPingSummary
	if cfg.ShowPing && len(cdnServers) > 0 {
		// Pass allVisible rather than cdnServers because statusPingSummary caches by whole visible set.
		pingMap, err = a.cachedPublicPingSummary(allVisible, now)
		if err != nil {
			return nil, err
		}
	}

	samples := a.copyLatestMonitorSamples()
	items := make([]PublicCDNServerItem, 0, len(cdnServers))
	onlineCount := 0
	for _, s := range cdnServers {
		entry, hasSample := samples[s.ID]
		online := publicServerOnline(s, entry, hasSample, now)
		if online {
			onlineCount++
		}

		var msPtr *int
		var lossPtr *float64
		var testedAt *time.Time
		if cfg.ShowPing {
			if buckets := pingMap.buckets[s.ID]; len(buckets) > 0 {
				latest := buckets[len(buckets)-1]
				lossVal := latest.Loss
				lossPtr = &lossVal
				atVal := latest.At
				testedAt = &atVal
				if latest.Ms >= 0 {
					msVal := latest.Ms
					msPtr = &msVal
				}
			}
		}

		items = append(items, PublicCDNServerItem{
			ID:       a.Store.Fingerprint("status-page", s.ID),
			Name:     publicDisplayName(s),
			Country:  strings.ToUpper(strings.TrimSpace(s.Country)),
			Region:   strings.TrimSpace(s.Region),
			City:     strings.TrimSpace(s.City),
			Online:   online,
			Ms:       msPtr,
			Loss:     lossPtr,
			TestedAt: testedAt,
		})
	}

	return json.Marshal(PublicCDNStatusResponse{
		GeneratedAt: now,
		ShowPing:    cfg.ShowPing,
		Total:       len(items),
		Online:      onlineCount,
		Servers:     items,
	})
}

func (a *App) cachedPublicCDNStatusBytes(cfg storedStatusPageSettings) ([]byte, error) {
	return a.cachedPublicSnapshot("cdn", &a.statusCDNBody, &a.statusCDNExpires, nil, func(now time.Time) ([]byte, error) {
		return a.buildPublicCDNStatusSnapshot(cfg, now)
	})
}

func parsePublicCDNCallback(rawQuery string) (string, bool) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		if strings.HasPrefix(rawQuery, "callback=") || strings.Contains(rawQuery, "&callback=") {
			return "", false
		}
	}
	cbs, has := values["callback"]
	if !has {
		return "", true
	}
	if len(cbs) != 1 || !validPublicJSCallback(cbs[0]) {
		return "", false
	}
	return cbs[0], true
}

func (a *App) servePublicCDNStatus(w http.ResponseWriter, r *http.Request, asScript bool) {
	cfg, ok := a.checkPublicStatusGate(w, r)
	if !ok {
		return
	}
	var callback string
	if asScript {
		var cbOK bool
		callback, cbOK = parsePublicCDNCallback(r.URL.RawQuery)
		if !cbOK {
			errorJSON(w, http.StatusBadRequest, "invalid callback")
			return
		}
	}

	jsonBody, err := a.cachedPublicCDNStatusBytes(cfg)
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Cache-Control", publicCDNCacheCtrl)
	if asScript {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(formatPublicCDNScript(jsonBody, callback))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonBody)
}

func (a *App) publicCDNStatusJS(w http.ResponseWriter, r *http.Request) {
	a.servePublicCDNStatus(w, r, true)
}

func (a *App) publicCDNStatusJSON(w http.ResponseWriter, r *http.Request) {
	a.servePublicCDNStatus(w, r, false)
}
