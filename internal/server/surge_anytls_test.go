package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestSurgeAnyTLSDirectAndRouteSubscriptions(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	certPEM, keyPEM := makeTestCertificate(t, false, nil, 30)
	cert := shared.Certificate{ID: ID(), Domain: "example.com", PEM: certPEM, Key: keyPEM, ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := p.store.PutCertificate(cert); err != nil {
		t.Fatal(err)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": l.exit, "name": "直连 AnyTLS", "protocol": "anytls", "port": 50443, "tlsName": "example.com", "certificateId": cert.ID, "password": "original-node-password", "enabled": true, "direct": true}, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	nodeID := node["id"].(string)
	code, route := l.route(map[string]any{"name": "链路 AnyTLS", "entryServerId": l.entry, "nodeId": nodeID, "enabled": true})
	if code != 201 {
		t.Fatal(code, route)
	}
	body := map[string]any{"name": "Surge AnyTLS", "format": "surge", "surgeTemplateId": "default", "nodeIds": []string{nodeID}, "routeIds": []string{route["id"].(string)}, "enabled": true}
	code, sub, _ := p.do("POST", "/api/subscriptions", body, nil)
	if code != 201 {
		t.Fatal("Surge must accept AnyTLS nodes and routes", code, sub)
	}
	if sub["surgeTemplateId"] != nil && sub["surgeTemplateId"] != "" {
		t.Fatal("default template ID was not normalised on creation", sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, _ := p.fetch(path); code != 503 {
		t.Fatal("unapplied credentials were offered", code)
	}
	l.applyAll()
	body["name"] = "Surge AnyTLS edited"
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("Surge edit rejected AnyTLS", code, out)
	}
	l.applyAll()
	code, content := p.fetch(path)
	if code != 200 {
		t.Fatal(code, content)
	}
	n, _ := p.store.Node(nodeID)
	user := p.store.SubscriptionUser(n, sub["id"].(string))
	for _, want := range []string{
		fmt.Sprintf("直连 AnyTLS = anytls, 198.51.100.4, 50443, password=%s, sni=example.com", user.Password),
		fmt.Sprintf("链路 AnyTLS = anytls, entry.example.com, 50443, password=%s, sni=example.com", user.Password),
	} {
		if !strings.Contains(content, want) {
			t.Fatal("entry address, subscription password or landing SNI lost", content)
		}
	}
	if strings.Contains(content, "original-node-password") || strings.Contains(content, "skip-cert-verify") {
		t.Fatal("base password exported or verification disabled")
	}
	if code, preview, _ := p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/preview", nil, nil); code != 200 || preview["content"] != content || len(preview["excluded"].([]any)) != 0 {
		t.Fatal("preview differs from download", code, preview)
	}
	code, profile := p.fetch(path + "?profile=1")
	if code != 200 {
		t.Fatal(code, profile)
	}
	for _, want := range []string{
		"#!MANAGED-CONFIG https://mui.example.test" + path + "?profile=1 interval=43200 strict=false\n",
		strings.TrimSuffix(content, "\n"),
		"节点选择 = select, 自动选择, 故障转移, 直连 AnyTLS, 链路 AnyTLS, DIRECT",
		"FINAL,漏网之鱼,dns-failed",
	} {
		if !strings.Contains(profile, want) {
			t.Fatal("profile lacks", want, profile)
		}
	}
	if !strings.HasPrefix(profile, "#!MANAGED-CONFIG ") || strings.Contains(profile, "{{") {
		t.Fatal("MANAGED-CONFIG must be the first line and every placeholder filled", profile)
	}
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": "[Proxy]\n{{PROXIES}}\n[Rule]\nGEOIP,CN,DIRECT"}, nil); code != 400 {
		t.Fatal("a template without FINAL was saved", code, out)
	}
	custom := "#!MANAGED-CONFIG https://elsewhere.example/x\r\n[Proxy]\r\n{{PROXIES}}\r\n[Proxy Group]\r\n出口 = select, {{PROXY_NAMES}}\r\n[Rule]\r\nFINAL,出口\r\n"
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": custom}, nil); code != 200 || out["custom"] != true {
		t.Fatal(code, out)
	}
	if _, profile = p.fetch(path + "?profile=1"); !strings.Contains(profile, "出口 = select, 直连 AnyTLS, 链路 AnyTLS\n") ||
		strings.Contains(profile, "elsewhere") || strings.Contains(profile, "\r") || strings.Contains(profile, "漏网之鱼") {
		t.Fatal("custom template not applied", profile)
	}
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": ""}, nil); code != 200 || out["custom"] != false || out["template"] != shared.DefaultSurgeProfileTemplate {
		t.Fatal("clearing the template must restore the default", code, out)
	}
	firstTemplate := "[Proxy]\n{{PROXIES}}\n[Proxy Group]\n出口甲 = select, {{PROXY_NAMES}}\n[Rule]\nFINAL,出口甲\n"
	secondTemplate := "[Proxy]\n{{PROXIES}}\n[Proxy Group]\n出口乙 = select, {{PROXY_NAMES}}\n[Rule]\nFINAL,出口乙\n"
	code, first, _ := p.do("POST", "/api/surge-templates", map[string]any{"name": "甲", "template": firstTemplate}, nil)
	if code != 201 {
		t.Fatal("create first Surge template", code, first)
	}
	if code, _, _ := p.do("POST", "/api/surge-templates", map[string]any{"name": "无效", "template": "[Proxy]\n{{PROXIES}}"}, nil); code != 400 {
		t.Fatal("invalid Surge template was saved", code)
	}
	code, second, _ := p.do("POST", "/api/surge-templates", map[string]any{"name": "乙", "template": secondTemplate}, nil)
	if code != 201 {
		t.Fatal("create second Surge template", code, second)
	}
	for _, duplicate := range []string{"甲", "默认模板"} {
		if code, _, _ := p.do("POST", "/api/surge-templates", map[string]any{"name": duplicate, "template": firstTemplate}, nil); code != 400 {
			t.Fatal("duplicate Surge template name accepted", duplicate, code)
		}
	}
	if code, _, _ := p.do("PATCH", "/api/surge-templates/"+second["id"].(string), map[string]any{"name": "甲", "template": secondTemplate}, nil); code != 400 {
		t.Fatal("duplicate Surge template rename accepted", code)
	}
	if code, out, _ := p.do("PATCH", "/api/surge-templates/default", map[string]any{"name": "默认模板", "template": shared.DefaultSurgeProfileTemplate}, nil); code != 200 || out["custom"] != nil {
		t.Fatal("unchanged built-in template was marked custom", code, out)
	}
	var storedDefault string
	if err := p.store.DB.QueryRow(`SELECT template FROM mui_surge_templates WHERE id='default'`).Scan(&storedDefault); err != nil || storedDefault != "" {
		t.Fatal("built-in default was frozen in database", storedDefault, err)
	}
	if code, out, _ := p.do("PATCH", "/api/surge-templates/default", map[string]any{"name": "默认模板", "template": firstTemplate}, nil); code != 200 || out["custom"] != true {
		t.Fatal("custom default template not marked", code, out)
	}
	if templates, err := p.store.SurgeTemplates(); err != nil || len(templates) == 0 || !templates[0].Custom {
		t.Fatal("template list omitted the custom marker", templates, err)
	}
	if code, out, _ := p.do("PATCH", "/api/surge-templates/default", map[string]any{"name": "默认模板", "template": ""}, nil); code != 200 || out["custom"] != nil {
		t.Fatal("restored default template still marked custom", code, out)
	}
	body["surgeTemplateId"] = first["id"]
	var jobsBefore, jobsAfter int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations`).Scan(&jobsBefore); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("assign first template", code, out)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations`).Scan(&jobsAfter); err != nil || jobsAfter != jobsBefore {
		t.Fatalf("template-only change queued node apply: before %d, after %d, err %v", jobsBefore, jobsAfter, err)
	}
	if code, profile = p.fetch(path + "?profile=1"); code != 200 || !strings.Contains(profile, "出口甲 = select,") || strings.Contains(profile, "出口乙 = select,") {
		t.Fatal("first template not selected", code, profile)
	}
	body["surgeTemplateId"] = "missing-template"
	if code, _, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 400 {
		t.Fatal("subscription accepted missing template", code)
	}
	body["surgeTemplateId"] = first["id"]
	if code, content = p.fetch(path); code != 200 || strings.Contains(content, "出口甲") {
		t.Fatal("node list changed with profile template", code, content)
	}
	body["surgeTemplateId"] = second["id"]
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("switch template", code, out)
	}
	if code, profile = p.fetch(path + "?profile=1"); code != 200 || !strings.Contains(profile, "出口乙 = select,") || strings.Contains(profile, "出口甲 = select,") {
		t.Fatal("second template not selected", code, profile)
	}
	if code, _, _ := p.do("DELETE", "/api/surge-templates/"+second["id"].(string), nil, nil); code != 409 {
		t.Fatal("referenced template was deleted", code)
	}
	body["surgeTemplateId"] = ""
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("restore default template", code, out)
	}
	if code, _, _ := p.do("DELETE", "/api/surge-templates/"+second["id"].(string), nil, nil); code != 200 {
		t.Fatal("unused template not deleted", code)
	}
	// Expiry polling must not reapply credentials after a profile-only edit.
	body["expiresAt"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("expire subscription", code, out)
	}
	if err := p.app.syncExpiredSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations`).Scan(&jobsBefore); err != nil {
		t.Fatal(err)
	}
	body["surgeTemplateId"] = first["id"]
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("switch template on expired subscription", code, out)
	}
	if err := p.app.syncExpiredSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations`).Scan(&jobsAfter); err != nil || jobsAfter != jobsBefore {
		t.Fatalf("expired template-only change queued apply: before %d, after %d, err %v", jobsBefore, jobsAfter, err)
	}
	var appliedCount int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, sub["id"].(string)).Scan(&appliedCount); err != nil || appliedCount != 1 {
		t.Fatal("template-only change cleared expiry marker", appliedCount, err)
	}
	body["surgeTemplateId"] = "default"
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 || (out["surgeTemplateId"] != nil && out["surgeTemplateId"] != "") {
		t.Fatal("default template ID was not normalised on update", code, out)
	}
}
