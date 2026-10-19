package shared

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestOfflineBundleIntegrity(t *testing.T) {
	_, bundle := signedTestBundle(t)
	if err := bundle.Verify(); err != nil {
		t.Fatal(err)
	}
	changed := bundle
	changed.Revision++
	if changed.Verify() == nil {
		t.Fatal("tampered config passed")
	}
}

func TestOfflineBundleRejectsTrailingContent(t *testing.T) {
	_, bundle := signedTestBundle(t)
	for _, suffix := range []string{"}", "]", "{}", "[]", "null", "123", `"extra"`, "true", "garbage"} {
		t.Run(suffix, func(t *testing.T) {
			raw := append(append([]byte(nil), bundle.Raw()...), []byte(suffix)...)
			if _, err := ParseOfflineBundle(raw); err == nil {
				t.Fatal("invalid trailing content passed signature validation")
			}
			if _, err := canonicalJSON(raw, "signature"); err == nil {
				t.Fatal("canonicalization ignored trailing content")
			}
		})
	}
	parsed, err := ParseOfflineBundle(append(bundle.Raw(), []byte(" \n\t\r")...))
	if err != nil || parsed.Digest() != bundle.Digest() {
		t.Fatalf("trailing whitespace must remain valid: %v", err)
	}
}

func signedTestBundle(t *testing.T) (ed25519.PrivateKey, OfflineBundle) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	b := OfflineBundle{ExportID: "export", ServerID: "entry", Revision: 3,
		Forwards: []ForwardRule{{ID: "f", ServerID: "entry", Name: "<a&b>", Network: "tcp", Port: 50001, Targets: []ForwardTarget{{Host: "10.0.0.2", Port: 443}}, FirewallPolicy: "manual", Enabled: true}}}
	b.Sign(key)
	return key, b
}

// The browser saves the export with JSON.stringify: other whitespace and no
// < escapes. The same value must verify and give the same digest.
func TestOfflineBundleSurvivesReformatting(t *testing.T) {
	_, b := signedTestBundle(t)
	var value any
	if err := json.Unmarshal(b.Raw(), &value); err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	enc := json.NewEncoder(&pretty)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pretty.Bytes(), b.Raw()) || !bytes.Contains(pretty.Bytes(), []byte("<a&b>")) {
		t.Fatal("the test needs a differently formatted file")
	}
	parsed, err := ParseOfflineBundle(pretty.Bytes())
	if err != nil {
		t.Fatalf("reformatted file: %v", err)
	}
	if parsed.Digest() != b.Digest() {
		t.Fatal("formatting changed the digest")
	}
}

// A newer panel may write fields this build does not know. They are covered
// by the signature, kept in the stored file and compared, but ignored.
func TestOfflineBundleUnknownFields(t *testing.T) {
	key, b := signedTestBundle(t)
	var doc map[string]any
	_ = json.Unmarshal(b.Raw(), &doc)
	doc["futureField"] = map[string]any{"x": 1}
	doc["forwards"].([]any)[0].(map[string]any)["futureRuleField"] = "y"
	doc["signature"] = ""
	unsigned, _ := json.Marshal(doc)
	canonical, err := canonicalJSON(unsigned, "signature")
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("mui-offline-config-v2\n"), canonical...)))
	newer, _ := json.Marshal(doc)
	parsed, err := ParseOfflineBundle(newer)
	if err != nil {
		t.Fatalf("a newer panel's file: %v", err)
	}
	if !bytes.Equal(parsed.Raw(), newer) {
		t.Fatal("the stored file must stay as received")
	}
	got, _ := parsed.CanonicalForwards()
	old, _ := b.CanonicalForwards()
	if bytes.Equal(got, old) || !bytes.Contains(got, []byte("futureRuleField")) {
		t.Fatal("comparisons must see fields this build does not know")
	}
	tampered := bytes.Replace(newer, []byte(`"y"`), []byte(`"z"`), 1)
	if _, err := ParseOfflineBundle(tampered); err == nil {
		t.Fatal("a changed unknown field passed")
	}
}

func TestOfflineBundleAgentVersion(t *testing.T) {
	_, b := signedTestBundle(t)
	for version, ok := range map[string]bool{"0.6.7": true, "0.6.7-dev": true, "0.7.0": true, "1.0.0": true, "0.6.6": false, "0.5.9": false, "dev": false} {
		if err := b.CheckAgentVersion(version); (err == nil) != ok {
			t.Fatalf("%s: %v", version, err)
		}
	}
}
