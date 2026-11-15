package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func makeTestPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 32, G: 120, B: 200, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeTestJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, G: 80, B: 40, A: 255})
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeTestGIF(t *testing.T) []byte {
	t.Helper()
	pal := color.Palette{color.Black, color.White}
	img := image.NewPaletted(image.Rect(0, 0, 2, 2), pal)
	var buf bytes.Buffer
	if err := gif.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeTestWebPVP8(w, h int) []byte {
	var vp8 [14]byte
	// frameTag: keyframe (bit0=0), version 0, showFrame=1, firstPartitionSize=1
	tag := uint32((1 << 4) | (1 << 5))
	vp8[0] = byte(tag)
	vp8[1] = byte(tag >> 8)
	vp8[2] = byte(tag >> 16)
	vp8[3], vp8[4], vp8[5] = 0x9d, 0x01, 0x2a
	binary.LittleEndian.PutUint16(vp8[6:8], uint16(w))
	binary.LittleEndian.PutUint16(vp8[8:10], uint16(h))

	var out bytes.Buffer
	out.WriteString("RIFF")
	_ = binary.Write(&out, binary.LittleEndian, uint32(4+8+len(vp8)))
	out.WriteString("WEBP")
	out.WriteString("VP8 ")
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(vp8)))
	out.Write(vp8[:])
	return out.Bytes()
}

func makeTestWebPVP8L(w, h int) []byte {
	var vp8l [6]byte
	vp8l[0] = 0x2f
	bits := uint32(w-1) | (uint32(h-1) << 14)
	binary.LittleEndian.PutUint32(vp8l[1:5], bits)

	var out bytes.Buffer
	out.WriteString("RIFF")
	_ = binary.Write(&out, binary.LittleEndian, uint32(4+8+len(vp8l)))
	out.WriteString("WEBP")
	out.WriteString("VP8L")
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(vp8l)))
	out.Write(vp8l[:])
	return out.Bytes()
}

func makeTestWebPVP8X(w, h int) []byte {
	var vp8x [10]byte
	vp8x[0] = 0x10 // Alpha flag
	w1 := uint32(w - 1)
	h1 := uint32(h - 1)
	vp8x[4], vp8x[5], vp8x[6] = byte(w1), byte(w1>>8), byte(w1>>16)
	vp8x[7], vp8x[8], vp8x[9] = byte(h1), byte(h1>>8), byte(h1>>16)

	var vp8l [6]byte
	vp8l[0] = 0x2f
	bits := uint32(w-1) | (uint32(h-1) << 14)
	binary.LittleEndian.PutUint32(vp8l[1:5], bits)

	var out bytes.Buffer
	out.WriteString("RIFF")
	_ = binary.Write(&out, binary.LittleEndian, uint32(4+(8+len(vp8x))+(8+len(vp8l))))
	out.WriteString("WEBP")
	out.WriteString("VP8X")
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(vp8x)))
	out.Write(vp8x[:])
	out.WriteString("VP8L")
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(vp8l)))
	out.Write(vp8l[:])
	return out.Bytes()
}

func doAdminRaw(p *testMui, method, path string, raw []byte, headers map[string]string) *httptest.ResponseRecorder {
	p.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if p.cookie != nil {
		req.AddCookie(p.cookie)
	}
	if strings.HasPrefix(path, "/api/") {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	return rec
}

func TestStatusAssetsMigrationDDLByDriver(t *testing.T) {
	sqliteDDL := statusAssetsTableDDL("sqlite3")
	if !strings.Contains(sqliteDDL, "mui_status_assets") || !strings.Contains(sqliteDDL, "data BLOB NOT NULL") {
		t.Fatalf("unexpected sqlite DDL: %s", sqliteDDL)
	}
	pgDDL := statusAssetsTableDDL("pgx")
	if !strings.Contains(pgDDL, "mui_status_assets") || !strings.Contains(pgDDL, "data BYTEA NOT NULL") {
		t.Fatalf("unexpected postgres DDL: %s", pgDDL)
	}
}

func TestStatusBackgroundUploadValidationAndLifecycle(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	statusMux := p.app.StatusHandler()

	// 1. Auth & CSRF enforcement on admin background endpoints.
	unauthReq := httptest.NewRequest(http.MethodPut, "/api/settings/status-page/background", bytes.NewReader(makeTestPNG(t, 4, 4)))
	unauthReq.Header.Set("X-Requested-With", "XMLHttpRequest")
	unauthRec := httptest.NewRecorder()
	p.handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PUT background = %d, want 401", unauthRec.Code)
	}
	noCSRFReq := httptest.NewRequest(http.MethodPut, "/api/settings/status-page/background", bytes.NewReader(makeTestPNG(t, 4, 4)))
	noCSRFReq.AddCookie(p.cookie)
	noCSRFRec := httptest.NewRecorder()
	p.handler.ServeHTTP(noCSRFRec, noCSRFReq)
	if noCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header PUT background = %d, want 403", noCSRFRec.Code)
	}

	// 2. Oversized payload (> 3 MiB) returns 413.
	oversized := make([]byte, maxStatusBackgroundBytes+1)
	rec := doAdminRaw(p, http.MethodPut, "/api/settings/status-page/background", oversized, map[string]string{
		"Content-Type": "image/png",
	})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}

	// 2. Disguised text, SVG, GIF, truncated image, and oversized dimensions (> 6000px) are rejected.
	invalidPayloads := []struct {
		name string
		mime string
		data []byte
	}{
		{"plain-text", "image/png", []byte("not really a png image at all")},
		{"svg-tag", "image/webp", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)},
		{"svg-xml", "image/jpeg", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`)},
		{"gif89a", "image/png", makeTestGIF(t)},
		{"truncated-png", "image/png", makeTestPNG(t, 4, 4)[:16]},
		{"truncated-jpeg", "image/jpeg", makeTestJPEG(t, 4, 4)[:16]},
		{"webp-too-wide", "image/webp", makeTestWebPVP8(6001, 100)},
		{"png-too-tall", "image/png", makeTestPNG(t, 1, 6001)},
	}
	for _, tc := range invalidPayloads {
		r := doAdminRaw(p, http.MethodPut, "/api/settings/status-page/background", tc.data, map[string]string{
			"Content-Type": tc.mime,
		})
		if r.Code != http.StatusBadRequest {
			t.Fatalf("%s upload status = %d, want 400 (body=%s)", tc.name, r.Code, r.Body.String())
		}
	}

	// 3. Valid JPEG, PNG, and WebP (VP8 / VP8L / VP8X) succeed.
	validImages := []struct {
		name     string
		sentMime string
		wantMime string
		data     []byte
	}{
		{"jpeg", "application/octet-stream", "image/jpeg", makeTestJPEG(t, 8, 6)},
		{"png", "image/png", "image/png", makeTestPNG(t, 10, 8)},
		{"webp-vp8", "image/webp", "image/webp", makeTestWebPVP8(12, 8)},
		{"webp-vp8l", "image/webp", "image/webp", makeTestWebPVP8L(14, 10)},
		{"webp-vp8x", "image/webp", "image/webp", makeTestWebPVP8X(16, 12)},
	}

	var lastVersion string
	var lastBytes []byte
	var lastMime string
	for _, tc := range validImages {
		r := doAdminRaw(p, http.MethodPut, "/api/settings/status-page/background", tc.data, map[string]string{
			"Content-Type": tc.sentMime,
		})
		if r.Code != http.StatusOK {
			t.Fatalf("%s upload failed: %d %s", tc.name, r.Code, r.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["backgroundSet"] != true || out["backgroundVersion"] == "" {
			t.Fatalf("%s unexpected upload response: %v", tc.name, out)
		}
		lastVersion = out["backgroundVersion"].(string)
		lastBytes = tc.data
		lastMime = tc.wantMime

		// Admin preview endpoint returns stored bytes and real mime.
		prev := doAdminRaw(p, http.MethodGet, "/api/settings/status-page/background", nil, nil)
		if prev.Code != http.StatusOK || prev.Header().Get("Content-Type") != tc.wantMime || !bytes.Equal(prev.Body.Bytes(), tc.data) {
			t.Fatalf("%s admin preview mismatch: code=%d type=%q len=%d", tc.name, prev.Code, prev.Header().Get("Content-Type"), prev.Body.Len())
		}
	}

	// Background must not be stuffed inside mui_settings status_page JSON.
	var settingsJSON string
	if err := p.store.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='status_page'`).Scan(&settingsJSON); err == nil {
		if strings.Contains(settingsJSON, lastVersion) || strings.Contains(settingsJSON, "RIFF") {
			t.Fatalf("status_page settings JSON unexpectedly contains asset data: %s", settingsJSON)
		}
	}

	// Verify audit action settings.status_background recorded.
	var auditCount int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_audit WHERE action='settings.status_background'`).Scan(&auditCount); err != nil || auditCount != len(validImages) {
		t.Fatalf("expected %d settings.status_background audit rows, got %d (%v)", len(validImages), auditCount, err)
	}

	// 4. While status page is disabled, public background endpoint returns 404.
	if r := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.40:1234"); r.Code != http.StatusNotFound {
		t.Fatalf("disabled GET /api/public/background = %d, want 404", r.Code)
	}

	// Enable status page with custom opacity & blur.
	code, _, _ := p.do(http.MethodPut, "/api/settings/status-page", map[string]any{
		"enabled":        true,
		"title":          "背景测试状态页",
		"cardOpacity":    72,
		"backgroundBlur": 8,
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("enable status page: %d", code)
	}

	// GET /api/settings/status-page reports backgroundSet=true and backgroundVersion.
	code, settingsOut, _ := p.do(http.MethodGet, "/api/settings/status-page", nil, nil)
	if code != http.StatusOK || settingsOut["backgroundSet"] != true || settingsOut["backgroundVersion"] != lastVersion ||
		settingsOut["cardOpacity"] != float64(72) || settingsOut["backgroundBlur"] != float64(8) {
		t.Fatalf("unexpected settings response: %d %v", code, settingsOut)
	}

	// Public status response includes top-level background object.
	statusRec := statusServe(statusMux, http.MethodGet, "/api/public/status", nil, "198.51.100.40:1234")
	if statusRec.Code != http.StatusOK {
		t.Fatalf("GET /api/public/status = %d %s", statusRec.Code, statusRec.Body.String())
	}
	var rawStatus map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &rawStatus); err != nil {
		t.Fatal(err)
	}
	assertOnlyAllowedKeys(t, "status-with-bg", rawStatus, "title", "description", "showTraffic", "showPing", "generatedAt", "background", "servers")
	bgMap, ok := rawStatus["background"].(map[string]any)
	if !ok {
		t.Fatalf("expected background object in status response, got %#v", rawStatus["background"])
	}
	assertOnlyAllowedKeys(t, "status.background", bgMap, "version", "cardOpacity", "blur")
	if bgMap["version"] != lastVersion || bgMap["cardOpacity"] != float64(72) || bgMap["blur"] != float64(8) {
		t.Fatalf("unexpected background object: %v", bgMap)
	}

	// Reset cache & read counter to prove public background endpoint loads once from DB and caches in memory.
	p.app.invalidatePublicStatusCache()
	p.store.statusAssetReads.Store(0)

	bgRec := statusServe(statusMux, http.MethodGet, "/api/public/background?v="+lastVersion, nil, "198.51.100.40:1234")
	if bgRec.Code != http.StatusOK {
		t.Fatalf("GET /api/public/background = %d %s", bgRec.Code, bgRec.Body.String())
	}
	if bgRec.Header().Get("Content-Type") != lastMime {
		t.Fatalf("Content-Type = %q, want %q", bgRec.Header().Get("Content-Type"), lastMime)
	}
	if bgRec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", bgRec.Header().Get("X-Content-Type-Options"))
	}
	if bgRec.Header().Get("Cache-Control") != "public, max-age=86400, immutable" {
		t.Fatalf("Cache-Control = %q", bgRec.Header().Get("Cache-Control"))
	}
	etagHdr := bgRec.Header().Get("ETag")
	if etagHdr == "" {
		t.Fatal("expected non-empty ETag header")
	}
	if !bytes.Equal(bgRec.Body.Bytes(), lastBytes) {
		t.Fatal("public background bytes do not match uploaded image")
	}

	// If-None-Match returns 304 and empty body.
	notModRec := statusServe(statusMux, http.MethodGet, "/api/public/background", map[string]string{
		"If-None-Match": etagHdr,
	}, "198.51.100.40:1234")
	if notModRec.Code != http.StatusNotModified || notModRec.Body.Len() != 0 {
		t.Fatalf("If-None-Match status=%d bodyLen=%d, want 304 empty", notModRec.Code, notModRec.Body.Len())
	}

	// Repeated requests hit in-memory cache rather than DB.
	for i := 0; i < 5; i++ {
		if r := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.40:1234"); r.Code != http.StatusOK {
			t.Fatalf("cached GET failed on iter %d: %d", i, r.Code)
		}
	}
	if reads := p.store.statusAssetReads.Load(); reads != 1 {
		t.Fatalf("expected exactly 1 DB read before cache hits, got %d", reads)
	}

	// 5. Isolation: main mux returns 404 for /api/public/background;
	// status mux returns 404 for admin background paths and non-GET /api/public/background.
	if c, _, _ := p.do(http.MethodGet, "/api/public/background", nil, nil); c != http.StatusNotFound {
		t.Fatalf("main mux GET /api/public/background = %d, want 404", c)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/settings/status-page/background"},
		{http.MethodPut, "/api/settings/status-page/background"},
		{http.MethodDelete, "/api/settings/status-page/background"},
		{http.MethodPut, "/api/public/background"},
		{http.MethodDelete, "/api/public/background"},
		{http.MethodPost, "/api/public/background"},
	} {
		if r := statusServe(statusMux, tc.method, tc.path, nil, "198.51.100.41:1234"); r.Code != http.StatusNotFound {
			t.Fatalf("status mux %s %s = %d, want 404", tc.method, tc.path, r.Code)
		}
	}

	// 6. Disabling and re-enabling status page keeps background intact.
	code, _, _ = p.do(http.MethodPut, "/api/settings/status-page", map[string]any{"enabled": false}, nil)
	if code != http.StatusOK {
		t.Fatalf("disable status page: %d", code)
	}
	if r := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.40:1234"); r.Code != http.StatusNotFound {
		t.Fatalf("disabled GET /api/public/background = %d, want 404", r.Code)
	}
	code, _, _ = p.do(http.MethodPut, "/api/settings/status-page", map[string]any{"enabled": true}, nil)
	if code != http.StatusOK {
		t.Fatalf("re-enable status page: %d", code)
	}
	if r := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.40:1234"); r.Code != http.StatusOK {
		t.Fatalf("re-enabled GET /api/public/background = %d, want 200", r.Code)
	}

	// 7. DELETE /api/settings/status-page/background deletes background cleanly.
	delRec := doAdminRaw(p, http.MethodDelete, "/api/settings/status-page/background", nil, nil)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE background = %d %s", delRec.Code, delRec.Body.String())
	}
	if r := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.40:1234"); r.Code != http.StatusNotFound {
		t.Fatalf("post-delete GET /api/public/background = %d, want 404", r.Code)
	}
	code, settingsAfterDel, _ := p.do(http.MethodGet, "/api/settings/status-page", nil, nil)
	if code != http.StatusOK || settingsAfterDel["backgroundSet"] != false || settingsAfterDel["backgroundVersion"] != "" {
		t.Fatalf("post-delete settings = %d %v", code, settingsAfterDel)
	}
	statusAfterDel := statusServe(statusMux, http.MethodGet, "/api/public/status", nil, "198.51.100.40:1234")
	var statusObjAfterDel map[string]any
	if err := json.Unmarshal(statusAfterDel.Body.Bytes(), &statusObjAfterDel); err != nil {
		t.Fatal(err)
	}
	if _, exists := statusObjAfterDel["background"]; exists {
		t.Fatalf("expected background field omitted after DELETE, got %v", statusObjAfterDel["background"])
	}
}

func TestStatusPageSettingsOpacityBlurValidationAndRateLimit(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	statusMux := p.app.StatusHandler()

	// Invalid ranges rejected with 400.
	for _, tc := range []map[string]any{
		{"cardOpacity": 39},
		{"cardOpacity": 101},
		{"backgroundBlur": -1},
		{"backgroundBlur": 21},
	} {
		code, _, _ := p.do(http.MethodPut, "/api/settings/status-page", tc, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("range %v status = %d, want 400", tc, code)
		}
	}

	// Boundary values accepted.
	for _, tc := range []map[string]any{
		{"enabled": true, "cardOpacity": 40, "backgroundBlur": 0},
		{"cardOpacity": 100, "backgroundBlur": 20},
	} {
		code, _, _ := p.do(http.MethodPut, "/api/settings/status-page", tc, nil)
		if code != http.StatusOK {
			t.Fatalf("valid range %v status = %d, want 200", tc, code)
		}
	}

	// Rate limiting applies cleanly to GET /api/public/background.
	up := doAdminRaw(p, http.MethodPut, "/api/settings/status-page/background", makeTestPNG(t, 4, 4), map[string]string{"Content-Type": "image/png"})
	if up.Code != http.StatusOK {
		t.Fatalf("upload png: %d", up.Code)
	}
	limited := false
	for i := 0; i < 125; i++ {
		rec := statusServe(statusMux, http.MethodGet, "/api/public/background", nil, "198.51.100.99:9000")
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("expected 429 rate limit on repeated GET /api/public/background")
	}

	// Unconfigured listener returns 404 on /api/public/background even if DB row exists.
	t.Setenv("MUI_STATUS_LISTEN", "")
	pUnconf := newTestMui(t)
	r := doAdminRaw(pUnconf, http.MethodPut, "/api/settings/status-page/background", makeTestPNG(t, 4, 4), map[string]string{"Content-Type": "image/png"})
	if r.Code != http.StatusOK {
		t.Fatalf("upload on unconfigured listener: %d", r.Code)
	}
	if c, _, _ := pUnconf.do(http.MethodPut, "/api/settings/status-page", map[string]any{"enabled": true}, nil); c != http.StatusOK {
		t.Fatalf("enable unconfigured: %d", c)
	}
	if rec := statusServe(pUnconf.app.StatusHandler(), http.MethodGet, "/api/public/background", nil, "198.51.100.55:1234"); rec.Code != http.StatusNotFound {
		t.Fatalf("unconfigured GET /api/public/background = %d, want 404", rec.Code)
	}
}
