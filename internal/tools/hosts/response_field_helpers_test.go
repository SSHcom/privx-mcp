package hosts

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
)

func TestSelectHostFields_DefaultsOnly(t *testing.T) {
	host := map[string]any{
		"id":          "h1",
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"disabled":    "FALSE",
		"extra":       "dropped",
		"services": []any{
			map[string]any{"service": "SSH", "address": "10.0.0.1", "status": "ok", "port": float64(22)},
			map[string]any{"service": "RDP", "address": "10.0.0.1", "status": "bad", "port": float64(3389)},
		},
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}, "source": "local"},
			"not-a-map",
		},
	}
	out := SelectHostFields(host, ProjectionFromParams(nil))
	if _, ok := out["extra"]; ok {
		t.Error("extra field should be dropped")
	}
	if out["id"] != "h1" {
		t.Errorf("id = %v", out["id"])
	}
	svcs, ok := out["services"].([]any)
	if !ok || len(svcs) != 2 {
		t.Fatalf("services = %v", out["services"])
	}
	svc, ok := svcs[0].(map[string]any)
	if !ok {
		t.Fatalf("service not a map: %T", svcs[0])
	}
	if svc["service"] != "SSH" {
		t.Errorf("service.service = %v", svc["service"])
	}
	if _, ok := svc["port"]; ok {
		t.Error("port should not be projected by default service fields")
	}
	prins, ok := out["principals"].([]any)
	if !ok || len(prins) != 1 {
		t.Fatalf("principals = %v", out["principals"])
	}
	prin, ok := prins[0].(map[string]any)
	if !ok {
		t.Fatalf("principal not a map: %T", prins[0])
	}
	if prin["principal"] != "root" {
		t.Errorf("principal = %v", prin["principal"])
	}
	if _, ok := prin["source"]; ok {
		t.Error("source should not be projected by default principal fields")
	}
}

func TestSelectHostFields_ExtraFields(t *testing.T) {
	host := map[string]any{"id": "h1", "organization": "acme"}
	out := SelectHostFields(host, Projection{Root: []string{"id", "organization", "nope"}})
	if out["id"] != "h1" {
		t.Errorf("id = %v", out["id"])
	}
	if out["organization"] != "acme" {
		t.Errorf("organization = %v", out["organization"])
	}
	if _, ok := out["nope"]; ok {
		t.Error("unknown field should be skipped")
	}
}

func TestSelectHostFields_AbsentRootOmitted(t *testing.T) {
	out := SelectHostFields(map[string]any{"id": "h1"}, Projection{Root: []string{"id", "common_name"}})
	if out["id"] != "h1" {
		t.Errorf("id = %v", out["id"])
	}
	if _, ok := out["common_name"]; ok {
		t.Error("missing common_name should be omitted")
	}
}

func TestSelectHostFields_NonMapArrayItems(t *testing.T) {
	host := map[string]any{"services": []any{"not-a-map", 42, nil}}
	out := SelectHostFields(host, Projection{Root: []string{"services"}, Services: []string{"service"}})
	svcs, ok := out["services"].([]any)
	if !ok {
		t.Fatalf("services = %v", out["services"])
	}
	if len(svcs) != 0 {
		t.Errorf("expected 0 projected items, got %d", len(svcs))
	}
}

func TestRedactSensitiveHostFields(t *testing.T) {
	host := map[string]any{
		"id":                        "h1",
		"common_name":               "web1",
		"host_certificate_raw":      "MIIC...",
		"host_certificate":          map[string]any{"subject": "CN=web1"},
		"ssh_host_public_keys":      []any{map[string]any{"key": "ssh-ed25519 AAAA"}},
		"password_rotation":         map[string]any{"protocol": "SSH"},
		"password_rotation_enabled": true,
		"services": []any{
			map[string]any{
				"service":                   "SSH",
				"address":                   "10.0.0.1",
				"auth_type":                 "AUTOMATIC",
				"password_field_name":       "pwd",
				"use_for_password_rotation": true,
				"certificate_template":      "default",
				"db": map[string]any{
					"protocol":                      "postgres",
					"tls_certificate_validation":    "ENABLED",
					"tls_certificate_trust_anchors": "-----BEGIN CERTIFICATE-----",
				},
			},
		},
		"principals": []any{
			map[string]any{
				"principal":                 "admin",
				"roles":                     []any{"r1"},
				"passphrase":                "******************",
				"rotate":                    true,
				"use_for_password_rotation": true,
			},
		},
	}

	out := RedactSensitiveHostFields(host)
	for _, field := range []string{
		"host_certificate_raw",
		"host_certificate",
		"ssh_host_public_keys",
		"password_rotation",
		"password_rotation_enabled",
	} {
		if _, ok := out[field]; ok {
			t.Errorf("root field %q should be redacted", field)
		}
	}
	if out["id"] != "h1" || out["common_name"] != "web1" {
		t.Errorf("non-sensitive root fields should remain: %v", out)
	}

	svc := out["services"].([]any)[0].(map[string]any)
	for _, field := range []string{"use_for_password_rotation", "certificate_template"} {
		if _, ok := svc[field]; ok {
			t.Errorf("service field %q should be redacted", field)
		}
	}
	if svc["auth_type"] != "AUTOMATIC" || svc["password_field_name"] != "pwd" {
		t.Errorf("web/auth service fields should remain: %v", svc)
	}
	db := svc["db"].(map[string]any)
	if _, ok := db["tls_certificate_validation"]; ok {
		t.Error("db.tls_certificate_validation should be redacted")
	}
	if _, ok := db["tls_certificate_trust_anchors"]; ok {
		t.Error("db.tls_certificate_trust_anchors should be redacted")
	}
	if db["protocol"] != "postgres" {
		t.Errorf("db.protocol should remain, got %v", db["protocol"])
	}

	prin := out["principals"].([]any)[0].(map[string]any)
	for _, field := range []string{"passphrase", "rotate", "use_for_password_rotation"} {
		if _, ok := prin[field]; ok {
			t.Errorf("principal field %q should be redacted", field)
		}
	}
	if prin["principal"] != "admin" {
		t.Errorf("principal name should remain, got %v", prin["principal"])
	}
}

func TestFormatHostItems_RawStillRedacts(t *testing.T) {
	items := FormatHostItems([]hoststore.Host{{
		ID:                      "h1",
		CommonName:              "web1",
		Organization:            "acme",
		HostCertificateRaw:      "MIIC...",
		PasswordRotationEnabled: true,
		Principals: []hoststore.HostPrincipals{{
			Principal:  "admin",
			Passphrase: "secret",
			Rotate:     true,
		}},
	}}, true, Projection{})
	if len(items) != 1 {
		t.Fatalf("len = %d", len(items))
	}
	host := items[0]
	if host["organization"] != "acme" {
		t.Errorf("raw should keep organization, got %v", host["organization"])
	}
	if _, ok := host["host_certificate_raw"]; ok {
		t.Error("raw must still redact host_certificate_raw")
	}
	if _, ok := host["password_rotation_enabled"]; ok {
		t.Error("raw must still redact password_rotation_enabled")
	}
	prin := host["principals"].([]any)[0].(map[string]any)
	if _, ok := prin["passphrase"]; ok {
		t.Error("raw must still redact passphrase")
	}
}
