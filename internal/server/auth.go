package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type rateBucket struct {
	Count int
	Reset time.Time
}

func (a *App) trustedProxy(ip net.IP) bool {
	for _, network := range a.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the address rate limits are keyed on. X-Forwarded-For is only
// believed when the connection comes from a configured proxy, and then the
// right-most address that is not itself a proxy is used: anything further
// left is supplied by the client.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip == nil || !a.trustedProxy(ip) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			break
		}
		if !a.trustedProxy(ip) {
			return ip.String()
		}
	}
	return host
}

// carrierGradeNAT is RFC 6598 shared address space. IsPrivate does not cover
// it, but a host behind CGNAT cannot be reached at such an address.
var carrierGradeNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// publicUnicast reports whether ip can stand for a server's public address.
func publicUnicast(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !carrierGradeNAT.Contains(ip)
}

func (a *App) auditRequest(r *http.Request, action, target, detail string) {
	a.Store.AuditWithIP(action, target, detail, a.clientIP(r))
}

// rateCount adds `add` events to the client's one-minute bucket for this scope
// and returns the total. Pass 0 to read without counting.
func (a *App) rateCount(r *http.Request, scope string, add int) int {
	key := scope + ":" + rateKey(a.clientIP(r))
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	now := time.Now()
	bucket, known := a.rates[key]
	if !known && len(a.rates) >= maxRateBuckets {
		// Sweep expired buckets at most once a second, not on every request.
		if now.Sub(a.ratePurge) > time.Second {
			a.ratePurge = now
			for k, v := range a.rates {
				if now.After(v.Reset) {
					delete(a.rates, k)
				}
			}
		}
		// Still full of live buckets: many addresses within one minute.
		// They share one bucket per scope, so the table stops growing and
		// the flood is limited as a whole instead of getting a fresh
		// allowance for every new address.
		if len(a.rates) >= maxRateBuckets {
			key = scope + ":overflow"
			bucket = a.rates[key]
		}
	}
	if now.After(bucket.Reset) {
		bucket = rateBucket{Reset: now.Add(time.Minute)}
	}
	bucket.Count += add
	if add > 0 {
		a.rates[key] = bucket
	}
	return bucket.Count
}

const maxRateBuckets = 10000

// rateKey groups an IPv6 client by its /64: one host is usually given a
// whole /64 and could otherwise rotate addresses to get fresh allowances.
func rateKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

func (a *App) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("mui_session")
		if err != nil {
			errorJSON(w, 401, "请先登录")
			return
		}
		var expiry, lastSeen int64
		err = a.Store.DB.QueryRow(`SELECT expires_at,last_seen_at FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value)).Scan(&expiry, &lastSeen)
		if err != nil || expiry < time.Now().Unix() {
			errorJSON(w, 401, "会话已过期")
			return
		}
		now := time.Now().Unix()
		// Sessions also expire after 24 hours without any activity. Rows
		// written before last_seen_at existed carry 0 and are treated as
		// freshly used once.
		if lastSeen > 0 && now-lastSeen > 24*3600 {
			_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value))
			errorJSON(w, 401, "会话已过期")
			return
		}
		if lastSeen == 0 || now-lastSeen >= 60 {
			_, _ = a.Store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, now, Hash(c.Value))
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			a.mu.Lock()
			defer a.mu.Unlock()
		}
		next(w, r)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	// Only failures count, and only against the address they came from, so a
	// stranger guessing passwords cannot lock the administrator out.
	if a.rateCount(r, "login", 0) >= 10 {
		errorJSON(w, 429, "登录尝试过于频繁，请稍后再试")
		return
	}
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, totp, err := a.adminCredentials()
	if err != nil {
		errorJSON(w, 500, "admin unavailable")
		return
	}
	select {
	case a.logins <- struct{}{}:
	case <-time.After(5 * time.Second):
		errorJSON(w, 429, "登录请求过多，请稍后再试")
		return
	case <-r.Context().Done():
		return
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password))
	<-a.logins
	if passwordErr != nil {
		a.rateCount(r, "login", 1)
		errorJSON(w, 401, "密码或验证码错误")
		return
	}
	if totp != "" && !a.checkTOTP(r, totp, in.Code) {
		a.rateCount(r, "login", 1)
		errorJSON(w, 401, "密码或验证码错误")
		return
	}
	token := Token()
	expiry := time.Now().Add(7 * 24 * time.Hour)
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE expires_at<$1`, time.Now().Unix())
	_, err = a.Store.DB.Exec(`INSERT INTO mui_sessions(token_hash,expires_at) VALUES($1,$2)`, Hash(token), expiry.Unix())
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mui_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil || strings.HasPrefix(a.publicURLForRequest(r), "https://"), SameSite: http.SameSiteStrictMode, Expires: expiry})
	writeJSON(w, 200, map[string]any{"ok": true, "totpEnabled": totp != ""})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("mui_session")
	if c != nil {
		_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "mui_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) me(w http.ResponseWriter, r *http.Request) {
	_, secret, _ := a.adminCredentials()
	writeJSON(w, 200, map[string]any{"authenticated": true, "totpEnabled": secret != ""})
}

// adminCredentials returns the password hash and the TOTP secret ("" when
// two-factor is off). The secret is stored encrypted; a value written before
// that was introduced is still read as is.
func (a *App) adminCredentials() (hash, totp string, err error) {
	if err = a.Store.DB.QueryRow(`SELECT password_hash,totp_secret FROM mui_admin WHERE id=1`).Scan(&hash, &totp); err != nil {
		return "", "", err
	}
	if sealed, ok := strings.CutPrefix(totp, "enc:"); ok {
		totp, err = a.Store.Decrypt(sealed)
	}
	return hash, totp, err
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, _, err := a.adminCredentials()
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		errorJSON(w, 403, "当前密码错误")
		return
	}
	if len(in.New) < 12 || len(in.New) > 72 {
		errorJSON(w, 400, "新密码需为 12-72 个字符")
		return
	}
	next, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET password_hash=$1 WHERE id=1`, string(next)); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Every other session was opened with the old password.
	c, _ := r.Cookie("mui_session")
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash<>$1`, Hash(c.Value))
	a.auditRequest(r, "admin.password", "admin", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, totp, err := a.adminCredentials()
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil || (totp != "" && !verifyTOTP(totp, in.Code)) {
		errorJSON(w, 403, "密码或验证码错误")
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET totp_secret='' WHERE id=1`); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "admin.totp.disable", "admin", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// checkTOTP verifies a login code for a caller who has already proven the
// password. Five wrong codes in a row lock the second factor for five minutes
// whatever address they come from, and a code is accepted only once. The
// replay state lives in the database, so a restart does not make a used code
// valid again.
func (a *App) checkTOTP(r *http.Request, secret, code string) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	lastStep, failures, lockedUntil, err := a.Store.TOTPState()
	if err != nil {
		log.Printf("totp state: %v", err)
		return false
	}
	if time.Now().Before(lockedUntil) {
		return false
	}
	step, ok := totpStep(secret, code)
	if ok && step > lastStep {
		if err := a.Store.SetTOTPState(step, 0, time.Time{}); err != nil {
			log.Printf("totp state: %v", err)
			return false
		}
		return true
	}
	failures++
	locked := time.Time{}
	if failures >= 5 {
		failures, locked = 0, time.Now().Add(5*time.Minute)
		a.auditRequest(r, "admin.totp.lock", "admin", "5 consecutive wrong codes")
	}
	if err := a.Store.SetTOTPState(lastStep, failures, locked); err != nil {
		log.Printf("totp state: %v", err)
		return false
	}
	return false
}

func verifyTOTP(secret, code string) bool {
	_, ok := totpStep(secret, code)
	return ok
}

// totpStep returns the 30-second step the code belongs to, within one step of now.
func totpStep(secret, code string) (uint64, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	for offset := -1; offset <= 1; offset++ {
		step := uint64(time.Now().Unix()/30 + int64(offset))
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, step)
		mac := hmac.New(sha1.New, key)
		mac.Write(buf)
		sum := mac.Sum(nil)
		i := int(sum[len(sum)-1] & 0xf)
		value := binary.BigEndian.Uint32(sum[i:i+4]) & 0x7fffffff
		if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%06d", value%1000000)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func (a *App) totpSetup(w http.ResponseWriter, r *http.Request) {
	_, secret, _ := a.adminCredentials()
	if secret != "" {
		errorJSON(w, 409, "已启用 TOTP")
		return
	}
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	// Pending enrollment is tied to the current session and expires with it.
	// The pending secret is encrypted like the enabled one.
	c, _ := r.Cookie("mui_session")
	sealed, err := a.Store.Encrypt(secret)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	_, _ = a.Store.DB.Exec(`INSERT INTO mui_totp_pending(session_hash,secret) VALUES($1,$2) ON CONFLICT(session_hash) DO UPDATE SET secret=excluded.secret`, Hash(c.Value), "enc:"+sealed)
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": "otpauth://totp/MUI:admin?secret=" + secret + "&issuer=MUI"})
}

func (a *App) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, _ := r.Cookie("mui_session")
	var secret string
	if a.Store.DB.QueryRow(`SELECT secret FROM mui_totp_pending WHERE session_hash=$1`, Hash(c.Value)).Scan(&secret) != nil {
		errorJSON(w, 400, "验证码错误")
		return
	}
	// Pending secrets written before encryption was introduced are plain.
	if sealed, ok := strings.CutPrefix(secret, "enc:"); ok {
		clear, err := a.Store.Decrypt(sealed)
		if err != nil {
			errorJSON(w, 400, "验证码错误")
			return
		}
		secret = clear
	}
	if !verifyTOTP(secret, in.Code) {
		errorJSON(w, 400, "验证码错误")
		return
	}
	sealed, err := a.Store.Encrypt(secret)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET totp_secret=$1 WHERE id=1`, "enc:"+sealed); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Only this session's pending enrollment is consumed; other sessions'
	// pending enrollments stay untouched.
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_totp_pending WHERE session_hash=$1`, Hash(c.Value))
	writeJSON(w, 200, map[string]bool{"ok": true})
}
