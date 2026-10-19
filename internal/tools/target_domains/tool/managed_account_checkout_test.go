package tool

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

const authorizerCheckoutPath = "/authorizer/api/v1/secrets/checkouts"

func TestCheckoutManagedAccountHandler_ReturnsLatestSecret(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: true,
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var search authorizer.AccountSecretSearch
		if err := json.Unmarshal(raw, &search); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if search.Username != "alice" {
			t.Errorf("username = %q", search.Username)
		}
		return response.ResultSet[authorizer.HostAccountSecret]{
			Count: 1,
			Items: []authorizer.HostAccountSecret{{
				Path:     "targetdomainsecrets/td1/alice",
				Type:     targetDomainSecretType,
				Username: "alice",
				TargetDomain: authorizer.TargetDomainHandle{
					ID:   "td1",
					Name: "labssh",
				},
			}},
		}, nil
	})
	checkedOut := false
	conn.Handle("POST", authorizerCheckoutPath, func(body any) (any, error) {
		checkedOut = true
		raw, _ := json.Marshal(body)
		var req authorizer.CheckoutRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Path != "targetdomainsecrets/td1/alice" {
			t.Errorf("path = %q", req.Path)
		}
		return authorizer.Checkout{
			Path:             req.Path,
			Username:         "alice",
			Expires:          "2026-10-13T12:14:18.699581Z",
			ManagedAccountID: "ma1",
			Secrets: []authorizer.Secrets{
				{Version: 1, Secret: "stale-value", Created: time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC)},
				{Version: 4, Secret: "edit-me-now", Created: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)},
			},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !checkedOut {
		t.Fatal("expected POST " + authorizerCheckoutPath)
	}
	if !strings.Contains(res.Content[0].Text, "edit-me-now") {
		t.Fatalf("secret missing: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "stale-value") {
		t.Fatalf("older secret returned: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["secret"] != "edit-me-now" || m["version"].(float64) != 4 || m["username"] != "alice" {
		t.Errorf("result = %v", m)
	}
}

func TestCheckoutManagedAccountHandler_SecretNotListed(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: true,
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		return response.ResultSet[authorizer.HostAccountSecret]{Count: 0}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not available for checkout") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_ExplicitCheckoutDisabled(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: false,
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "explicit checkout is disabled") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_ReturnsPrivXStringsUnchanged(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: true,
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		return response.ResultSet[authorizer.HostAccountSecret]{
			Count: 1,
			Items: []authorizer.HostAccountSecret{{
				Path:         "targetdomainsecrets/td1/alice",
				Type:         targetDomainSecretType,
				Username:     "alice",
				TargetDomain: authorizer.TargetDomainHandle{ID: "td1"},
			}},
		}, nil
	})
	conn.Handle("POST", authorizerCheckoutPath, func(body any) (any, error) {
		return authorizer.Checkout{
			Path:             "targetdomainsecrets/td1/alice",
			Username:         "delete me",
			ManagedAccountID: "ma1",
			Secrets: []authorizer.Secrets{{
				Version: 1,
				Secret:  "edit-me-now",
			}},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("checkout must return PrivX strings unchanged: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, `"username":"delete me"`) || !strings.Contains(res.Content[0].Text, `"secret":"edit-me-now"`) {
		t.Fatalf("expected username and password as PrivX sent them, got %s", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "ma1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_IgnoresOtherTargetDomains(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: true,
			TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1"},
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		return response.ResultSet[authorizer.HostAccountSecret]{
			Count: 2,
			Items: []authorizer.HostAccountSecret{
				{
					Path:         "targetdomainsecrets/other/alice",
					Type:         targetDomainSecretType,
					Username:     "alice",
					TargetDomain: authorizer.TargetDomainHandle{ID: "other", Name: "other"},
				},
				{
					Path:         "targetdomainsecrets/td1/alice",
					Type:         targetDomainSecretType,
					Username:     "alice",
					TargetDomain: authorizer.TargetDomainHandle{ID: "td1", Name: "labssh"},
				},
			},
		}, nil
	})
	conn.Handle("POST", authorizerCheckoutPath, func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var req authorizer.CheckoutRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Path != "targetdomainsecrets/td1/alice" {
			t.Fatalf("checked out %q", req.Path)
		}
		return authorizer.Checkout{
			Path:             req.Path,
			Username:         "alice",
			ManagedAccountID: "ma1",
			TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1"},
			Secrets: []authorizer.Secrets{{
				Version: 1,
				Secret:  "edit-me-now",
			}},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "other") {
		t.Fatalf("other domain included: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, "edit-me-now") {
		t.Fatalf("secret missing: %s", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_EmailUsernameScopedToDomain(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/search", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var search secretsmanager.ManagedAccountsSearch
		if err := json.Unmarshal(raw, &search); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if search.Keywords != "demouser@labssh.com" {
			t.Errorf("keywords = %q", search.Keywords)
		}
		return response.ResultSet[secretsmanager.ManagedAccount]{
			Count: 2,
			Items: []secretsmanager.ManagedAccount{
				{
					ID:               "other-account",
					Username:         "demouser@elsewhere.example",
					Email:            "demouser@elsewhere.example",
					ExplicitCheckout: true,
					TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1"},
				},
				{
					ID:               "ma1",
					Username:         "demouser@labssh.com",
					Email:            "demouser@labssh.com",
					ExplicitCheckout: true,
					TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1", Name: "labssh"},
				},
			},
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		return response.ResultSet[authorizer.HostAccountSecret]{
			Count: 2,
			Items: []authorizer.HostAccountSecret{
				{
					Path:         "targetdomainsecrets/other/demouser@labssh.com",
					Type:         targetDomainSecretType,
					Username:     "demouser@labssh.com",
					TargetDomain: authorizer.TargetDomainHandle{ID: "other"},
				},
				{
					Path:         "targetdomainsecrets/td1/demouser@labssh.com",
					Type:         targetDomainSecretType,
					Username:     "demouser@labssh.com",
					TargetDomain: authorizer.TargetDomainHandle{ID: "td1"},
				},
			},
		}, nil
	})
	conn.Handle("POST", authorizerCheckoutPath, func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var req authorizer.CheckoutRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Path != "targetdomainsecrets/td1/demouser@labssh.com" {
			t.Fatalf("checked out %q", req.Path)
		}
		return authorizer.Checkout{
			Path:             req.Path,
			Username:         "demouser@labssh.com",
			ManagedAccountID: "ma1",
			TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1", Name: "labssh"},
			Secrets: []authorizer.Secrets{{
				Version: 4,
				Secret:  "edit-me-now",
			}},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "demouser@labssh.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["secret"] != "edit-me-now" || m["managed_account_id"] != "ma1" {
		t.Errorf("result = %v", m)
	}
	if strings.Contains(res.Content[0].Text, "other") {
		t.Fatalf("other domain included: %s", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_RejectsCheckoutFromOtherDomain(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return secretsmanager.ManagedAccount{
			ID:               "ma1",
			Username:         "alice",
			ExplicitCheckout: true,
		}, nil
	})
	conn.Handle("POST", "/authorizer/api/v1/secrets/search", func(body any) (any, error) {
		return response.ResultSet[authorizer.HostAccountSecret]{
			Count: 1,
			Items: []authorizer.HostAccountSecret{{
				Path:         "targetdomainsecrets/td1/alice",
				Type:         targetDomainSecretType,
				Username:     "alice",
				TargetDomain: authorizer.TargetDomainHandle{ID: "td1"},
			}},
		}, nil
	})
	conn.Handle("POST", authorizerCheckoutPath, func(body any) (any, error) {
		return authorizer.Checkout{
			Path:             "targetdomainsecrets/other/alice",
			Username:         "alice",
			ManagedAccountID: "ma1",
			TargetDomain:     secretsmanager.TargetDomainHandle{ID: "other"},
			Secrets: []authorizer.Secrets{{
				Version: 1,
				Secret:  "edit-me-now",
			}},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not under this target domain") {
		t.Fatalf("got %q", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "edit-me-now") {
		t.Fatalf("secret leaked: %s", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_EmailUsernameNotInDomain(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/search", func(body any) (any, error) {
		return response.ResultSet[secretsmanager.ManagedAccount]{
			Count: 1,
			Items: []secretsmanager.ManagedAccount{{
				ID:               "ma-other",
				Username:         "demouser@labssh.com",
				ExplicitCheckout: true,
				TargetDomain:     secretsmanager.TargetDomainHandle{ID: "other"},
			}},
		}, nil
	})

	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "demouser@labssh.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not found under this target domain") {
		t.Fatalf("got %q", res.Content[0].Text)
	}
}

func TestCheckoutManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := checkoutManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
