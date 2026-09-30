package oauth

import (
	"testing"
)

func TestMap_StripDomain_Email(t *testing.T) {
	mapper := NewIdentityMapper("email", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@example.com"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "alice" {
		t.Fatalf("expected 'alice', got %q", result)
	}
}

func TestMap_StripDomain_NoAtSign(t *testing.T) {
	mapper := NewIdentityMapper("email", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "alice" {
		t.Fatalf("expected 'alice', got %q", result)
	}
}

func TestMap_StripDomain_MultipleAtSigns(t *testing.T) {
	mapper := NewIdentityMapper("email", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@corp@example.com"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "alice" {
		t.Fatalf("expected 'alice', got %q", result)
	}
}

func TestMap_AsIs_Email(t *testing.T) {
	mapper := NewIdentityMapper("email", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@example.com"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "alice@example.com" {
		t.Fatalf("expected 'alice@example.com', got %q", result)
	}
}

func TestMap_PreferredUsername(t *testing.T) {
	mapper := NewIdentityMapper("preferred_username", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"preferred_username": "bob@corp.local"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "bob" {
		t.Fatalf("expected 'bob', got %q", result)
	}
}

func TestMap_UPN(t *testing.T) {
	mapper := NewIdentityMapper("upn", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"upn": "carol@domain.org"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "carol@domain.org" {
		t.Fatalf("expected 'carol@domain.org', got %q", result)
	}
}

func TestMap_Sub(t *testing.T) {
	mapper := NewIdentityMapper("sub", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"sub": "user-12345"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "user-12345" {
		t.Fatalf("expected 'user-12345', got %q", result)
	}
}

func TestMap_Sub_StripDomain(t *testing.T) {
	mapper := NewIdentityMapper("sub", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"sub": "user@idp.example.com"}}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "user" {
		t.Fatalf("expected 'user', got %q", result)
	}
}

func TestMap_MissingEmail_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("email", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"sub": "sub-123", "upn": "user@corp.local"}}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for missing email claim")
	}
	expected := "identity claim 'email' not found in token"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestMap_MissingUPN_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("upn", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@example.com"}}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for missing upn claim")
	}
	expected := "identity claim 'upn' not found in token"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestMap_MissingSub_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("sub", "strip-domain")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@example.com"}}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for missing sub claim")
	}
	expected := "identity claim 'sub' not found in token"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestMap_MissingPreferredUsername_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("preferred_username", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": "alice@example.com"}}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for missing preferred_username claim")
	}
	expected := "identity claim 'preferred_username' not found in token"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestMap_EmptyEmail_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("email", "as-is")
	claims := &IdentityClaims{RawClaims: map[string]any{"email": ""}}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for empty email claim")
	}
}

func TestMap_DotNotationNestedField(t *testing.T) {
	mapper := NewIdentityMapper("user.profile.username", "as-is")
	claims := &IdentityClaims{
		RawClaims: map[string]any{
			"user": map[string]any{
				"profile": map[string]any{
					"username": "nested-user",
				},
			},
		},
	}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "nested-user" {
		t.Fatalf("expected nested-user, got %q", result)
	}
}

func TestMap_DotNotationArrayIndex(t *testing.T) {
	mapper := NewIdentityMapper("resource_access.account.roles[0]", "as-is")
	claims := &IdentityClaims{
		RawClaims: map[string]any{
			"resource_access": map[string]any{
				"account": map[string]any{
					"roles": []any{"manage-account", "view-profile"},
				},
			},
		},
	}

	result, err := mapper.Map(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "manage-account" {
		t.Fatalf("expected manage-account, got %q", result)
	}
}

func TestMap_ClaimPathWithNonStringValue_ReturnsError(t *testing.T) {
	mapper := NewIdentityMapper("realm_access.roles", "as-is")
	claims := &IdentityClaims{
		RawClaims: map[string]any{
			"realm_access": map[string]any{
				"roles": []any{"default-roles-mcp"},
			},
		},
	}

	_, err := mapper.Map(claims)
	if err == nil {
		t.Fatal("expected error for non-string claim value")
	}
	expected := "identity claim 'realm_access.roles' must be a string, got []interface {}"
	if err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}
