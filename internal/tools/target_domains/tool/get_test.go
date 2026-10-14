package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetTargetDomainHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		return secretsmanager.TargetDomain{
			ID:         "td1",
			Name:       "corp",
			DomainName: "corp.example",
			EndPoints: []secretsmanager.TargetDomainEndpoint{{
				Type:              "ldap",
				LdapAddress:       "dc.example",
				LdapBindPassword:  "bind-secret",
				EntraClientSecret: "entra-secret",
				LdapBindDN:        "cn=svc",
			}},
		}, nil
	})
	res, err := getTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "td1" || m["domain_name"] != "corp.example" {
		t.Errorf("domain = %v", m)
	}
	eps := m["endpoints"].([]any)
	ep := eps[0].(map[string]any)
	if _, ok := ep["ldap_bind_password"]; ok {
		t.Error("ldap_bind_password should be stripped")
	}
	if _, ok := ep["entra_client_secret"]; ok {
		t.Error("entra_client_secret should be stripped")
	}
	if ep["ldap_bind_dn"] != "cn=svc" {
		t.Errorf("ldap_bind_dn = %v", ep["ldap_bind_dn"])
	}
}

func TestGetTargetDomainHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
