package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUpdateTargetDomainHandler_PreservesOmittedFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		return secretsmanager.TargetDomain{
			ID:         "td1",
			Name:       "labssh",
			DomainName: "labssh.com",
			Comment:    "old",
			EndPoints: []secretsmanager.TargetDomainEndpoint{{
				Type:             "AD",
				ScanPriority:     1,
				LdapBindPassword: "stored-secret",
			}},
		}, nil
	})
	conn.Handle("PUT", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var domain secretsmanager.TargetDomain
		if err := json.Unmarshal(raw, &domain); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if domain.Comment != "edited" {
			t.Errorf("comment = %q, want edited", domain.Comment)
		}
		if domain.DomainName != "labssh.com" {
			t.Errorf("domain_name = %q, want labssh.com", domain.DomainName)
		}
		if len(domain.EndPoints) != 1 || domain.EndPoints[0].LdapBindPassword != "stored-secret" {
			t.Errorf("endpoints = %+v", domain.EndPoints)
		}
		return nil, nil
	})

	res, err := updateTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":      "td1",
		"comment": "edited",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "stored-secret") {
		t.Fatalf("result echoed a secret: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "td1" || m["updated"] != true {
		t.Errorf("result = %v", m)
	}
	if _, ok := m["ldap_bind_password"]; ok {
		t.Error("result included ldap_bind_password")
	}
}

func TestUpdateTargetDomainHandler_ReplacesBindPassword(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		return secretsmanager.TargetDomain{
			ID:         "td1",
			Name:       "labssh",
			DomainName: "labssh.com",
			EndPoints: []secretsmanager.TargetDomainEndpoint{{
				Type:             "AD",
				ScanPriority:     1,
				LdapBindPassword: "old-secret",
			}},
		}, nil
	})
	conn.Handle("PUT", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var domain secretsmanager.TargetDomain
		if err := json.Unmarshal(raw, &domain); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(domain.EndPoints) != 1 || domain.EndPoints[0].LdapBindPassword != "new-secret" {
			t.Errorf("bind password = %+v", domain.EndPoints)
		}
		return nil, nil
	})

	res, err := updateTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id": "td1",
		"endpoints": []any{
			map[string]any{
				"type":               "AD",
				"scan_priority":      float64(1),
				"rotation_priority":  float64(1),
				"ldap_bind_password": "new-secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "new-secret") {
		t.Fatalf("result echoed a secret: %s", res.Content[0].Text)
	}
}

func TestUpdateTargetDomainHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
