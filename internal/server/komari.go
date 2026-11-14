package server

import "net/http"

// agentKomari is retained for Agents 0.6.30 and older, which poll
// GET /agent/komari every 5 minutes and remain idle when given empty values.
func (a *App) agentKomari(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{
		"endpoint": "",
		"token":    "",
		"ipv4":     "",
		"ipv6":     "",
	})
}
