package api_targets

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
)

func TestSelectAPITargetFields_DefaultsOnly(t *testing.T) {
	target := map[string]any{
		"id":              "t1",
		"name":            "payments",
		"access_group_id": "ag1",
		"comment":         "dropped",
		"roles": []any{
			map[string]any{"id": "r1", "name": "admin", "deleted": true},
		},
		"authorized_endpoints": []any{
			map[string]any{
				"host":                  "api.example.com",
				"allow_unauthenticated": false,
				"protocols":             []any{"https"},
				"methods":               []any{"GET"},
				"paths":                 []any{"/v1/**"},
			},
			map[string]any{
				"host":                  "api-nat.example.com",
				"nat_target_host":       "10.0.0.5",
				"allow_unauthenticated": true,
				"protocols":             []any{"http"},
				"methods":               []any{"*"},
			},
		},
		"unauthorized_endpoints": []any{
			map[string]any{
				"host":                  "api.example.com",
				"allow_unauthenticated": false,
				"protocols":             []any{"https"},
				"methods":               []any{"DELETE"},
				"paths":                 []any{"/admin/**"},
			},
		},
	}

	out := SelectAPITargetFields(target, ProjectionFromParams(nil))
	if _, ok := out["comment"]; ok {
		t.Error("comment should be dropped")
	}
	if _, ok := out["unauthorized_endpoints"]; ok {
		t.Error("unauthorized_endpoints should not be in defaults")
	}
	if out["id"] != "t1" || out["name"] != "payments" || out["access_group_id"] != "ag1" {
		t.Errorf("root defaults = %v", out)
	}

	roles, ok := out["roles"].([]any)
	if !ok || len(roles) != 1 {
		t.Fatalf("roles = %v", out["roles"])
	}
	role := roles[0].(map[string]any)
	if role["id"] != "r1" || role["name"] != "admin" {
		t.Errorf("role = %v", role)
	}
	if _, ok := role["deleted"]; ok {
		t.Error("deleted should not be projected by default role fields")
	}

	eps, ok := out["authorized_endpoints"].([]any)
	if !ok || len(eps) != 2 {
		t.Fatalf("authorized_endpoints = %v", out["authorized_endpoints"])
	}
	ep0 := eps[0].(map[string]any)
	if _, ok := ep0["nat_target_host"]; ok {
		t.Error("absent nat_target_host should be omitted")
	}
	paths, ok := ep0["paths"].([]any)
	if !ok || len(paths) != 1 || paths[0] != "/v1/**" {
		t.Errorf("paths = %v", ep0["paths"])
	}
	if ep0["host"] != "api.example.com" {
		t.Errorf("host = %v", ep0["host"])
	}
	ep1 := eps[1].(map[string]any)
	if ep1["nat_target_host"] != "10.0.0.5" {
		t.Errorf("nat_target_host = %v", ep1["nat_target_host"])
	}
}

func TestSelectAPITargetFields_AbsentRootOmitted(t *testing.T) {
	out := SelectAPITargetFields(map[string]any{"id": "t1"}, Projection{Root: []string{"id", "name"}})
	if out["id"] != "t1" {
		t.Errorf("id = %v", out["id"])
	}
	if _, ok := out["name"]; ok {
		t.Error("missing name should be omitted")
	}
}

func TestSelectAPITargetFields_MalformedRoles(t *testing.T) {
	out := SelectAPITargetFields(map[string]any{"roles": []any{"x", nil}}, Projection{Root: []string{"roles"}, Roles: DefaultRoleFields})
	roles, ok := out["roles"].([]any)
	if !ok {
		t.Fatalf("roles = %v", out["roles"])
	}
	if len(roles) != 0 {
		t.Errorf("len = %d, want 0", len(roles))
	}
}

func TestSelectAPITargetFields_UnauthorizedEndpointsSameDefaults(t *testing.T) {
	target := map[string]any{
		"id": "t1",
		"unauthorized_endpoints": []any{
			map[string]any{
				"host":                  "api.example.com",
				"allow_unauthenticated": false,
				"protocols":             []any{"https"},
				"methods":               []any{"DELETE"},
				"paths":                 []any{"/admin/**"},
			},
		},
	}
	rootFields := []string{"id", "unauthorized_endpoints"}
	out := SelectAPITargetFields(target, Projection{
		Root:      rootFields,
		Roles:     DefaultRoleFields,
		Endpoints: DefaultEndpointFields,
	})
	eps, ok := out["unauthorized_endpoints"].([]any)
	if !ok || len(eps) != 1 {
		t.Fatalf("unauthorized_endpoints = %v", out["unauthorized_endpoints"])
	}
	ep := eps[0].(map[string]any)
	if ep["host"] != "api.example.com" {
		t.Errorf("host = %v", ep["host"])
	}
	paths, ok := ep["paths"].([]any)
	if !ok || len(paths) != 1 || paths[0] != "/admin/**" {
		t.Errorf("paths = %v", ep["paths"])
	}
	if _, ok := ep["nat_target_host"]; ok {
		t.Error("absent nat_target_host should be omitted")
	}
}

func TestRedactSensitiveAPITargetFields(t *testing.T) {
	target := map[string]any{
		"id":                "t1",
		"name":              "payments",
		"tls_trust_anchors": "-----BEGIN CERTIFICATE-----",
		"target_credential": map[string]any{
			"type":                           "basicauth",
			"basic_auth_username":            "svc",
			"basic_auth_password":            "secret",
			"bearer_token":                   "tok",
			"certificate":                    "CERT",
			"private_key":                    "KEY",
			"ephemeral_certificate_subject":  "CN=${username}",
			"ephemeral_certificate_san":      "DNS:${hostname}",
			"ephemeral_certificate_template": "default",
		},
	}

	out := RedactSensitiveAPITargetFields(target)
	if _, ok := out["tls_trust_anchors"]; ok {
		t.Error("tls_trust_anchors should be redacted")
	}
	if out["id"] != "t1" || out["name"] != "payments" {
		t.Errorf("non-sensitive root fields should remain: %v", out)
	}
	cred := out["target_credential"].(map[string]any)
	for _, field := range []string{"basic_auth_password", "bearer_token", "certificate", "private_key"} {
		if _, ok := cred[field]; ok {
			t.Errorf("credential field %q should be redacted", field)
		}
	}
	if cred["type"] != "basicauth" || cred["basic_auth_username"] != "svc" {
		t.Errorf("non-secret credential fields should remain: %v", cred)
	}
	if cred["ephemeral_certificate_subject"] != "CN=${username}" {
		t.Errorf("ephemeral subject should remain: %v", cred)
	}
}

func TestFormatAPITargetItems_RawStillRedacts(t *testing.T) {
	items := FormatAPITargetItems([]apiproxy.ApiTarget{{
		ID:              "t1",
		Name:            "payments",
		Comment:         "keep-in-raw",
		TLSTrustAnchors: "-----BEGIN CERTIFICATE-----",
		TargetCredential: apiproxy.TargetCredential{
			Type:              "token",
			BearerToken:       "secret-token",
			BasicAuthPassword: "pw",
		},
	}}, true, Projection{})
	if len(items) != 1 {
		t.Fatalf("len = %d", len(items))
	}
	target := items[0]
	if target["comment"] != "keep-in-raw" {
		t.Errorf("raw should keep comment, got %v", target["comment"])
	}
	if _, ok := target["tls_trust_anchors"]; ok {
		t.Error("raw must still redact tls_trust_anchors")
	}
	cred := target["target_credential"].(map[string]any)
	if _, ok := cred["bearer_token"]; ok {
		t.Error("raw must still redact bearer_token")
	}
	if _, ok := cred["basic_auth_password"]; ok {
		t.Error("raw must still redact basic_auth_password")
	}
}
