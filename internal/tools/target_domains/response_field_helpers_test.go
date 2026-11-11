package target_domains

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
)

func domainWithSecrets() map[string]any {
	return map[string]any{
		"id":          "td1",
		"name":        "corp",
		"domain_name": "corp.example",
		"comment":     "keep",
		"endpoints": []any{
			map[string]any{
				"type":                "ldap",
				"ldap_address":        "dc.example",
				"ldap_bind_password":  "bind-secret",
				"entra_client_secret": "entra-secret",
				"ldap_bind_dn":        "cn=svc",
			},
		},
		"checkouts": []any{
			map[string]any{
				"id":      "c1",
				"secrets": []any{map[string]any{"password": "pw"}},
			},
		},
	}
}

func TestFormatTargetDomain_RedactsSecrets(t *testing.T) {
	out := RedactSensitiveTargetDomainFields(domainWithSecrets())
	ep := out["endpoints"].([]any)[0].(map[string]any)
	if _, ok := ep["ldap_bind_password"]; ok {
		t.Error("ldap_bind_password should be redacted")
	}
	if _, ok := ep["entra_client_secret"]; ok {
		t.Error("entra_client_secret should be redacted")
	}
	if ep["ldap_address"] != "dc.example" || ep["ldap_bind_dn"] != "cn=svc" {
		t.Errorf("non-secret endpoint fields should remain: %v", ep)
	}
	checkout := out["checkouts"].([]any)[0].(map[string]any)
	if _, ok := checkout["secrets"]; ok {
		t.Error("checkouts[].secrets should be redacted")
	}
	if checkout["id"] != "c1" {
		t.Errorf("checkout id = %v", checkout["id"])
	}
}

func TestFormatTargetDomainItems_ProjectedAndRawRedact(t *testing.T) {
	items := []secretsmanager.TargetDomain{{
		ID:      "td1",
		Name:    "corp",
		Comment: "keep",
		EndPoints: []secretsmanager.TargetDomainEndpoint{{
			Type:              "ldap",
			LdapAddress:       "dc.example",
			LdapBindDN:        "cn=svc",
			LdapBindPassword:  "bind-secret",
			EntraClientSecret: "entra-secret",
		}},
	}}
	proj := Projection{
		Root:      append(DefaultTargetDomainFields, "endpoints"),
		Endpoints: append(DefaultEndpointFields, "ldap_bind_password", "entra_client_secret", "ldap_bind_dn"),
	}

	projected := FormatTargetDomainItems(items, false, proj)
	ep := projected[0]["endpoints"].([]any)[0].(map[string]any)
	if _, ok := ep["ldap_bind_password"]; ok {
		t.Error("projected item should drop ldap_bind_password")
	}
	if _, ok := ep["entra_client_secret"]; ok {
		t.Error("projected item should drop entra_client_secret")
	}
	if ep["ldap_address"] != "dc.example" || ep["ldap_bind_dn"] != "cn=svc" {
		t.Errorf("projected endpoint = %v", ep)
	}
	if projected[0]["comment"] != "keep" {
		t.Errorf("comment = %v", projected[0]["comment"])
	}

	raw := FormatTargetDomainItems(items, true, Projection{})
	rawEP := raw[0]["endpoints"].([]any)[0].(map[string]any)
	if _, ok := rawEP["ldap_bind_password"]; ok {
		t.Error("raw item should drop ldap_bind_password")
	}
	if _, ok := rawEP["entra_client_secret"]; ok {
		t.Error("raw item should drop entra_client_secret")
	}
	if raw[0]["comment"] != "keep" || rawEP["ldap_bind_dn"] != "cn=svc" {
		t.Errorf("raw should keep non-secret fields: %v", raw[0])
	}
}
