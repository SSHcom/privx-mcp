package connections

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
)

func TestFormatConnection_FlattensNestedFields(t *testing.T) {
	conn := connectionmanager.Connection{
		ID:                "c1",
		Type:              "SSH",
		Mode:              "PROXY",
		Status:            "CONNECTED",
		User:              connectionmanager.ConnectionUser{ID: "u1", DisplayName: "alice"},
		TargetHost:        connectionmanager.ConnectionHost{ID: "h1", CommonName: "web1"},
		TargetHostAddress: "10.0.0.1",
		TargetHostAccount: "admin",
		RemoteAddress:     "203.0.113.5",
		Connected:         "2026-08-17T08:00:00Z",
		Disconnected:      "",
		Duration:          120,
		BytesIn:           1024,
		BytesOut:          2048,
		AuditEnabled:      true,
	}

	m := FormatConnection(conn)

	if m["id"] != "c1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["user"] != "alice" {
		t.Errorf("user should flatten User.DisplayName, got %v", m["user"])
	}
	if m["target_host"] != "web1" {
		t.Errorf("target_host should flatten TargetHost.CommonName, got %v", m["target_host"])
	}
	if m["target_host_address"] != "10.0.0.1" {
		t.Errorf("target_host_address = %v", m["target_host_address"])
	}
	if m["target_host_account"] != "admin" {
		t.Errorf("target_host_account = %v", m["target_host_account"])
	}
	if m["status"] != "CONNECTED" {
		t.Errorf("status = %v", m["status"])
	}
	if m["audit_enabled"] != true {
		t.Errorf("audit_enabled = %v", m["audit_enabled"])
	}
}

func TestFormatConnectionItems_RawBypassesProjection(t *testing.T) {
	items := []connectionmanager.Connection{
		{ID: "c1", ProxyID: "p1"},
	}
	out := FormatConnectionItems(items, true)
	if len(out) != 1 {
		t.Fatalf("expected 1 item, got %d", len(out))
	}
	if out[0]["id"] != "c1" {
		t.Errorf("id = %v", out[0]["id"])
	}
	if _, ok := out[0]["proxy_id"]; !ok {
		t.Errorf("raw should include proxy_id, got %v", out[0]["proxy_id"])
	}
}

func TestFormatConnectionItems_RawRedactsMarkedFields(t *testing.T) {
	items := []connectionmanager.Connection{{
		ID: "c1",
		TargetHostData: &hoststore.Host{
			ID:                      "h1",
			HostCertificateRaw:      "CERT",
			PasswordRotationEnabled: true,
			SSHHostPubKeys: []hoststore.HostSSHPubKeys{{
				Key:         "ssh-ed25519 AAAA",
				FingerPrint: "SHA256:abc",
			}},
			Principals: []hoststore.HostPrincipals{{
				Principal:  "root",
				Passphrase: "secret",
			}},
			Services: []hoststore.HostService{{
				Service: "DB",
				DB: hoststore.HostServiceDBParameters{
					Protocol:                   "postgres",
					TLSCertificateValidation:   "STRICT",
					TLSCertificateTrustAnchors: "ANCHOR",
				},
			}},
		},
		UserData: &rolestore.User{
			ID:        "u1",
			Principal: "alice",
			MFA:       rolestore.MFAStatus{Status: "enabled", TotpMFASeed: rolestore.MFASeed{Seed_string: "SEED"}},
			Attributes: []rolestore.UserAttribute{
				{Key: "windows_sid", Value: "S-1-5"},
				{Key: "department", Value: "ops"},
			},
		},
	}}

	out := FormatConnectionItems(items, true)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}

	host := out[0]["target_host_data"].(map[string]any)
	if _, ok := host["host_certificate_raw"]; ok {
		t.Error("host_certificate_raw should be redacted")
	}
	if host["password_rotation_enabled"] != true {
		t.Errorf("password_rotation_enabled should remain, got %v", host["password_rotation_enabled"])
	}
	key := host["ssh_host_public_keys"].([]any)[0].(map[string]any)
	if _, ok := key["key"]; ok {
		t.Error("ssh host public key should be redacted")
	}
	if _, ok := key["fingerprint"]; ok {
		t.Error("ssh host public key fingerprint should be redacted")
	}
	prin := host["principals"].([]any)[0].(map[string]any)
	if _, ok := prin["passphrase"]; ok {
		t.Error("passphrase should be redacted")
	}
	if prin["principal"] != "root" {
		t.Errorf("principal = %v", prin["principal"])
	}
	db := host["services"].([]any)[0].(map[string]any)["db"].(map[string]any)
	if _, ok := db["tls_certificate_trust_anchors"]; ok {
		t.Error("tls_certificate_trust_anchors should be redacted")
	}
	if db["tls_certificate_validation"] != "STRICT" {
		t.Errorf("tls_certificate_validation = %v", db["tls_certificate_validation"])
	}

	user := out[0]["user_data"].(map[string]any)
	if user["principal"] != "alice" {
		t.Errorf("principal = %v", user["principal"])
	}
	mfa := user["mfa"].(map[string]any)
	if _, ok := mfa["seed"]; ok {
		t.Error("mfa.seed should be redacted")
	}
	if mfa["user_mfa_status"] != "enabled" {
		t.Errorf("mfa status = %v", mfa["user_mfa_status"])
	}
	attrs := user["attributes"].([]any)
	if len(attrs) != 1 || attrs[0].(map[string]any)["key"] != "department" {
		t.Errorf("attributes = %v", attrs)
	}
}

func TestExtractRoleNames_DeduplicatesAndSkipsEmpty(t *testing.T) {
	roles := []connectionmanager.ConnectionRole{
		{ID: "r1", Name: "admin"},
		{ID: "r2", Name: "admin"},
		{ID: "r3", Name: ""},
		{ID: "r4", Name: "operator"},
		{ID: "r5", Name: "operator"},
		{ID: "r6", Name: ""},
	}
	got := extractRoleNames(roles)
	want := []string{"admin", "operator"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestExtractRoleNames_Empty(t *testing.T) {
	got := extractRoleNames(nil)
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestFormatSingleConnection_NilSafe(t *testing.T) {
	conn := &connectionmanager.Connection{ID: "c1", User: connectionmanager.ConnectionUser{DisplayName: "alice"}}
	m := FormatSingleConnection(conn, false)
	if m["id"] != "c1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["user"] != "alice" {
		t.Errorf("user = %v", m["user"])
	}
}
