package auth

import (
	"context"
	"testing"
)

func TestFromContext_ReturnsNilWhenNotSet(t *testing.T) {
	ctx := context.Background()
	ac := FromContext(ctx)
	if ac != nil {
		t.Errorf("expected nil AuthContext, got %+v", ac)
	}
}

func TestFromContext_ReturnsStoredAuthContext(t *testing.T) {
	expected := &AuthContext{
		Username:  "bob",
		Roles:     []Role{{ID: "role-1", Name: "admin"}},
		Connector: &mockConnector{},
	}

	ctx := NewContext(context.Background(), expected)
	ac := FromContext(ctx)

	if ac == nil {
		t.Fatal("expected non-nil AuthContext")
		return
	}
	if ac.Username != expected.Username {
		t.Errorf("expected username %q, got %q", expected.Username, ac.Username)
	}
	if len(ac.Roles) != 1 || ac.Roles[0].Name != "admin" || ac.Roles[0].ID != "role-1" {
		t.Errorf("expected roles [{role-1 admin}], got %v", ac.Roles)
	}
}

func TestHasRole(t *testing.T) {
	ac := &AuthContext{Roles: []Role{
		{ID: "id-approver", Name: " Approver "},
		{ID: "id-viewer", Name: "viewer"},
	}}
	if !ac.HasRole("approver") {
		t.Fatal("expected HasRole to match case-insensitively with trim")
	}
	if ac.HasRole("missing") {
		t.Fatal("expected HasRole to return false for unknown role")
	}
	if (*AuthContext)(nil).HasRole("approver") {
		t.Fatal("expected nil AuthContext HasRole to be false")
	}
	if ac.HasRole("") {
		t.Fatal("expected empty role name to be false")
	}
	if !ac.HasRole("", "id-approver") {
		t.Fatal("expected HasRole to match by ID when provided")
	}
	if !ac.HasRole("wrong-name", "id-viewer") {
		t.Fatal("expected HasRole to prefer ID match when ID is provided")
	}
	if ac.HasRole("approver", "missing-id") {
		t.Fatal("expected HasRole with ID to ignore name and fail on unknown ID")
	}
}

func TestHasAnyRole(t *testing.T) {
	ac := &AuthContext{Roles: []Role{{ID: "id-viewer", Name: "viewer"}}}
	if !ac.HasAnyRole("approver", "viewer") {
		t.Fatal("expected HasAnyRole to match when one role is present")
	}
	if ac.HasAnyRole("approver", "admin") {
		t.Fatal("expected HasAnyRole to be false when none match")
	}
	if (*AuthContext)(nil).HasAnyRole("viewer") {
		t.Fatal("expected nil AuthContext HasAnyRole to be false")
	}
}
