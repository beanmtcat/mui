package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func parsePublicURLs(raw string) ([]*url.URL, error) {
	items := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(items) == 0 {
		return nil, errors.New("MUI_PUBLIC_URL must contain at least one HTTP(S) URL")
	}
	urls := make([]*url.URL, 0, len(items))
	seen := map[string]string{}
	for _, item := range items {
		u, err := url.Parse(item)
		if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(item, "#") || u.Opaque != "" {
			return nil, fmt.Errorf("MUI_PUBLIC_URL contains an invalid HTTP(S) URL: %q", item)
		}
		u.Host = canonicalPublicHost(u.Host, u.Scheme)
		if u.Host == "" {
			return nil, fmt.Errorf("MUI_PUBLIC_URL contains an invalid host: %q", item)
		}
		u.Path, u.RawPath = strings.TrimRight(u.Path, "/"), strings.TrimRight(u.RawPath, "/")
		origin := u.Scheme + "://" + u.Host
		if previous, exists := seen[origin]; exists {
			if previous != u.String() {
				return nil, fmt.Errorf("MUI_PUBLIC_URL contains different base paths for %s", origin)
			}
			continue
		}
		seen[origin] = u.String()
		urls = append(urls, u)
	}
	return urls, nil
}

// Host and port comparison is case-insensitive and treats explicit default
// ports as the same origin. Invalid authorities never match configured URLs.
func canonicalPublicHost(host, scheme string) string {
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(host, "#\\") {
		return ""
	}
	name, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
	}
	if port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(name, port)
	}
	if strings.Contains(name, ":") {
		return "[" + name + "]"
	}
	return name
}

func parseRequestOrigin(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") {
		return nil
	}
	u.Host = canonicalPublicHost(u.Host, u.Scheme)
	if u.Host == "" {
		return nil
	}
	return u
}

func (a *App) originAllowed(r *http.Request, raw string) bool {
	origin := parseRequestOrigin(raw)
	if origin == nil {
		return false
	}
	for _, configured := range a.publicURLs {
		if origin.Scheme == configured.Scheme && origin.Host == configured.Host {
			return true
		}
	}
	// Retain same-host access for local Vite development and direct deployments.
	return canonicalPublicHost(r.Host, origin.Scheme) == origin.Host
}

func (a *App) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && a.trustedProxy(ip) && r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// Only configured URLs may appear in generated commands and subscription links.
// Never use an arbitrary Host or X-Forwarded-Host as a public URL.
func (a *App) publicURLForRequest(r *http.Request) string {
	scheme := a.requestScheme(r)
	var hostMatch *url.URL
	for _, configured := range a.publicURLs {
		if canonicalPublicHost(r.Host, configured.Scheme) == configured.Host {
			if configured.Scheme == scheme {
				return configured.String()
			}
			if hostMatch == nil {
				hostMatch = configured
			}
		}
	}
	if hostMatch != nil {
		return hostMatch.String()
	}
	// Some proxies rewrite Host. A configured browser Origin still identifies
	// the public entry point without trusting arbitrary forwarding headers.
	if origin := parseRequestOrigin(r.Header.Get("Origin")); origin != nil {
		for _, configured := range a.publicURLs {
			if configured.Scheme == origin.Scheme && configured.Host == origin.Host {
				return configured.String()
			}
		}
	}
	return a.PublicURL
}
