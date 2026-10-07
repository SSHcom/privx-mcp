package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestListTargetDomainsHandler_NoAuth(t *testing.T) {
	res, err := listTargetDomainsHandler(testconn.CtxNoAuth(), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListTargetDomainsHandler_InvalidSortKey(t *testing.T) {
	conn := testconn.New(t)
	res, err := listTargetDomainsHandler(testconn.CtxWithAuth(conn), map[string]any{"sortKey": "created"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "sortKey must be id or name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListTargetDomainsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	seen := false
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains", func(body any) (any, error) {
		seen = true
		return response.ResultSet[secretsmanager.TargetDomain]{
			Count: 1,
			Items: []secretsmanager.TargetDomain{{
				ID:         "td1",
				Name:       "corp",
				DomainName: "corp.example",
				EndPoints: []secretsmanager.TargetDomainEndpoint{{
					Type:              "ldap",
					LdapAddress:       "dc.example",
					LdapBindPassword:  "bind-secret",
					EntraClientSecret: "entra-secret",
				}},
			}},
		}, nil
	})

	res, err := listTargetDomainsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"fields":         "endpoints",
		"endpointFields": "ldap_bind_password,entra_client_secret",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !seen {
		t.Fatal("expected GET /secrets-manager/api/v1/targetdomains")
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	if m["limit"].(float64) != float64(common.TargetDomainsListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
	if m["offset"].(float64) != 0 {
		t.Errorf("offset = %v", m["offset"])
	}
	if m["returned"].(float64) != 1 {
		t.Errorf("returned = %v", m["returned"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	first := items[0].(map[string]any)
	if first["id"] != "td1" || first["name"] != "corp" {
		t.Errorf("item = %v", first)
	}
	eps := first["endpoints"].([]any)
	ep := eps[0].(map[string]any)
	if _, ok := ep["ldap_bind_password"]; ok {
		t.Error("ldap_bind_password should be stripped")
	}
	if _, ok := ep["entra_client_secret"]; ok {
		t.Error("entra_client_secret should be stripped")
	}
	if ep["ldap_address"] != "dc.example" {
		t.Errorf("ldap_address = %v", ep["ldap_address"])
	}
}
