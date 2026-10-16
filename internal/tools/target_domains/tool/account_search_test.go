package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func scannedAccount() secretsmanager.ScannedAccount {
	return secretsmanager.ScannedAccount{
		ID:             "sa1",
		Username:       "alice",
		FullName:       "Alice",
		Email:          "alice@example.com",
		SourceID:       "src",
		AdditionalData: map[string]string{"dn": "cn=alice"},
		TargetDomain:   secretsmanager.TargetDomainHandle{ID: "td1", Name: "corp"},
		State:          "UNMANAGED",
		Ignored:        false,
		Comment:        "note",
	}
}

func TestSearchTargetDomainAccountsHandler_NoAuth(t *testing.T) {
	res, err := searchTargetDomainAccountsHandler(testconn.CtxNoAuth(), map[string]any{"id": "td1"})
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

func TestSearchTargetDomainAccountsHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchTargetDomainAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchTargetDomainAccountsHandler_InvalidSearch(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchTargetDomainAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":     "td1",
		"search": "alice",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "invalid search body") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchTargetDomainAccountsHandler_DefaultsToUnmanaged(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains/:id/accounts/search", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		var search secretsmanager.ScannedAccountsSearch
		if err := json.Unmarshal(raw, &search); err != nil {
			t.Fatal(err)
		}
		if search.State != "UNMANAGED" {
			t.Errorf("state = %q, want UNMANAGED", search.State)
		}
		if search.Keywords != "" {
			t.Errorf("keywords = %q", search.Keywords)
		}
		return response.ResultSet[secretsmanager.ScannedAccount]{
			Count: 1,
			Items: []secretsmanager.ScannedAccount{scannedAccount()},
		}, nil
	})

	res, err := searchTargetDomainAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	if m["limit"].(float64) != float64(common.TargetDomainsListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
	first := m["items"].([]any)[0].(map[string]any)
	if first["id"] != "sa1" || first["username"] != "alice" || first["state"] != "UNMANAGED" {
		t.Errorf("item = %v", first)
	}
	if _, ok := first["additional_data"]; ok {
		t.Errorf("additional_data should be omitted: %v", first)
	}
	if _, ok := first["source_id"]; ok {
		t.Errorf("source_id should be omitted: %v", first)
	}
	if _, ok := first["comment"]; ok {
		t.Errorf("comment should be omitted: %v", first)
	}
}

func TestSearchTargetDomainAccountsHandler_StateOverrideAndFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains/:id/accounts/search", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		var search secretsmanager.ScannedAccountsSearch
		if err := json.Unmarshal(raw, &search); err != nil {
			t.Fatal(err)
		}
		if search.State != "NEW" || search.Keywords != "alice" {
			t.Errorf("search = %+v", search)
		}
		if search.Ignored == nil || *search.Ignored {
			t.Errorf("ignored = %v", search.Ignored)
		}
		return response.ResultSet[secretsmanager.ScannedAccount]{
			Count: 1,
			Items: []secretsmanager.ScannedAccount{scannedAccount()},
		}, nil
	})

	res, err := searchTargetDomainAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id": "td1",
		"search": map[string]any{
			"keywords": "alice",
			"state":    "NEW",
			"ignored":  false,
		},
		"fields": "target_domain,source_id",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	first := m["items"].([]any)[0].(map[string]any)
	if first["source_id"] != "src" {
		t.Errorf("source_id = %v", first["source_id"])
	}
	domain := first["target_domain"].(map[string]any)
	if domain["id"] != "td1" || domain["name"] != "corp" {
		t.Errorf("target_domain = %v", domain)
	}
	if _, ok := first["additional_data"]; ok {
		t.Errorf("additional_data should stay omitted: %v", first)
	}
}

func TestSearchTargetDomainAccountsHandler_Raw(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains/:id/accounts/search", func(body any) (any, error) {
		return response.ResultSet[secretsmanager.ScannedAccount]{
			Count: 1,
			Items: []secretsmanager.ScannedAccount{scannedAccount()},
		}, nil
	})

	res, err := searchTargetDomainAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":  "td1",
		"raw": true,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	first := m["items"].([]any)[0].(map[string]any)
	data := first["additional_data"].(map[string]any)
	if data["dn"] != "cn=alice" || first["comment"] != "note" || first["source_id"] != "src" {
		t.Errorf("raw item = %v", first)
	}
}
