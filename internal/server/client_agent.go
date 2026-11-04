package server

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxUserAgent = 256

// The User-Agent is whatever the client chose to send, so it is kept short
// and printable, and only ever shown as a hint, never trusted.
func cleanUserAgent(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(ua))
	for len(ua) > maxUserAgent {
		_, size := utf8.DecodeLastRuneInString(ua)
		ua = ua[:len(ua)-size]
	}
	return ua
}

// Order matters: wrappers name the core they embed (Stash says Clash, the
// sing-box apps say sing-box), so the more specific pattern comes first.
var clientPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`Surge (iOS|Mac)/(\S+)`), "Surge $1 $2"},
	{regexp.MustCompile(`^Surge/(\S+)`), "Surge $1"},
	{regexp.MustCompile(`(?i)^Stash/(\S+)`), "Stash $1"},
	{regexp.MustCompile(`(?i)^Shadowrocket/(\S+)`), "Shadowrocket $1"},
	{regexp.MustCompile(`(?i)^Quantumult X/(\S+)`), "Quantumult X $1"},
	{regexp.MustCompile(`(?i)^Loon/(\S+)`), "Loon $1"},
	{regexp.MustCompile(`(?i)^Egern/(\S+)`), "Egern $1"},
	{regexp.MustCompile(`^SFI/(\S+)`), "sing-box iOS $1"},
	{regexp.MustCompile(`^SFM/(\S+)`), "sing-box macOS $1"},
	{regexp.MustCompile(`^SFT/(\S+)`), "sing-box tvOS $1"},
	{regexp.MustCompile(`^SFA/(\S+)`), "sing-box Android $1"},
	{regexp.MustCompile(`(?i)Hiddify\w*/v?(\S+)`), "Hiddify $1"},
	{regexp.MustCompile(`(?i)NekoBox/(\S+)`), "NekoBox $1"},
	{regexp.MustCompile(`(?i)^karing/(\S+)`), "Karing $1"},
	{regexp.MustCompile(`(?i)^sing-box[/ ]v?(\S+)`), "sing-box $1"},
	{regexp.MustCompile(`(?i)clash-verge/v?(\S+)`), "Clash Verge $1"},
	{regexp.MustCompile(`(?i)FlClash/v?(\S+)`), "FlClash $1"},
	{regexp.MustCompile(`(?i)ClashMetaForAndroid/(\S+)`), "Clash Meta for Android $1"},
	{regexp.MustCompile(`(?i)ClashX(?: Pro| Meta)?/(\S+)`), "ClashX $1"},
	{regexp.MustCompile(`(?i)Clash ?for ?Windows/(\S+)`), "Clash for Windows $1"},
	{regexp.MustCompile(`(?i)^mihomo/v?(\S+)`), "mihomo $1"},
	{regexp.MustCompile(`(?i)^clash\.meta/v?(\S+)`), "Clash.Meta $1"},
	{regexp.MustCompile(`(?i)^clash`), "Clash"},
	{regexp.MustCompile(`(?i)^v2rayNG/(\S+)`), "v2rayNG $1"},
	{regexp.MustCompile(`(?i)^v2rayN/(\S+)`), "v2rayN $1"},
	{regexp.MustCompile(`(?i)subconverter`), "订阅转换服务"},
	{regexp.MustCompile(`^curl/(\S+)`), "curl $1"},
	{regexp.MustCompile(`^Wget/(\S+)`), "Wget $1"},
	{regexp.MustCompile(`^(Go-http-client|python-requests|okhttp)/`), "程序请求 $1"},
	{regexp.MustCompile(`^Mozilla/`), "浏览器"},
}

// clientName turns a User-Agent into a readable software name, or "" when
// it is not one we recognise.
func clientName(ua string) string {
	if decoded, err := url.PathUnescape(ua); err == nil {
		ua = decoded // Quantumult X sends "Quantumult%20X/1.4".
	}
	for _, pattern := range clientPatterns {
		if match := pattern.re.FindStringSubmatchIndex(ua); match != nil {
			return strings.TrimSpace(string(pattern.re.ExpandString(nil, pattern.name, ua, match)))
		}
	}
	return ""
}
