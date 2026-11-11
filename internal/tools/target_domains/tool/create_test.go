package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateTargetDomainHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var domain secretsmanager.TargetDomain
		if err := json.Unmarshal(raw, &domain); err != nil {
			t.Fatalf("unmarshal domain: %v", err)
		}
		if domain.Name != "labssh" || domain.DomainName != "labssh.com" {
			t.Errorf("domain identity = %q %q", domain.Name, domain.DomainName)
		}
		if len(domain.EndPoints) != 1 || domain.EndPoints[0].LdapBindPassword != "bind-secret" {
			t.Errorf("bind password = %+v", domain.EndPoints)
		}
		if domain.EndPoints[0].EntraClientSecret != "entra-secret" {
			t.Errorf("entra secret = %q", domain.EndPoints[0].EntraClientSecret)
		}
		return response.Identifier{ID: "td1"}, nil
	})

	res, err := createTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":        "labssh",
		"domain_name": "labssh.com",
		"endpoints": []any{
			map[string]any{
				"type":                "AD",
				"scan_priority":       float64(1),
				"rotation_priority":   float64(1),
				"ldap_bind_password":  "bind-secret",
				"entra_client_secret": "entra-secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "bind-secret") || strings.Contains(res.Content[0].Text, "entra-secret") {
		t.Fatalf("result echoed a secret: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "td1" {
		t.Errorf("id = %v, want td1", m["id"])
	}
	if _, ok := m["ldap_bind_password"]; ok {
		t.Error("result included ldap_bind_password")
	}
	if len(m) != 1 {
		t.Errorf("result = %v, want only id", m)
	}
}

func TestCreateTargetDomainHandler_MissingName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"domain_name": "labssh.com",
		"endpoints":   []any{validEndpoint(1)},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateTargetDomainHandler_MissingDomainName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":      "labssh",
		"endpoints": []any{validEndpoint(1)},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: domain_name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateTargetDomainHandler_MissingEndpoints(t *testing.T) {
	conn := testconn.New(t)
	res, err := createTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":        "labssh",
		"domain_name": "labssh.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: endpoints") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateTargetDomainHandler_DuplicateScanPriority(t *testing.T) {
	conn := testconn.New(t)
	res, err := createTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":        "labssh",
		"domain_name": "labssh.com",
		"endpoints": []any{
			validEndpoint(1),
			validEndpoint(1),
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "duplicate scan_priority") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func validEndpoint(scanPriority int) map[string]any {
	return map[string]any{
		"type":              "AD",
		"scan_priority":     float64(scanPriority),
		"rotation_priority": float64(1),
	}
}
