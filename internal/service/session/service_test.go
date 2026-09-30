package session

import (
	"errors"
	"testing"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

func TestBuildIdentityKeyRequiresBaseIssuerSubject(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	if _, ok := BuildIdentityKey("", identity); ok {
		t.Fatal("expected key build to fail when base url is empty")
	}
	if _, ok := BuildIdentityKey("https://privx.example.com", &oauth.IdentityClaims{Subject: "user-1"}); ok {
		t.Fatal("expected key build to fail when issuer is empty")
	}
	if _, ok := BuildIdentityKey("https://privx.example.com", &oauth.IdentityClaims{Issuer: "https://issuer.example.com"}); ok {
		t.Fatal("expected key build to fail when subject is empty")
	}

	key, ok := BuildIdentityKey("https://privx.example.com", identity)
	if !ok {
		t.Fatal("expected key build to succeed")
	}
	want := "https://privx.example.com|https://issuer.example.com|user-1"
	if key != want {
		t.Fatalf("unexpected key %q, want %q", key, want)
	}
}

func TestServiceGetSetHitAndExpiry(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	svc := NewServiceWithClock(30*time.Second, func() time.Time { return now })

	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}
	value := CachedUserContext{
		UserID: "u-123",
		ResolvedRoles: &rolestore.User{
			Permissions: []string{"hosts-view"},
		},
	}

	svc.Set("https://privx.example.com", identity, value)

	got, ok := svc.Get("https://privx.example.com", identity)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.UserID != "u-123" {
		t.Fatalf("unexpected user id %q", got.UserID)
	}
	if got.Issuer != identity.Issuer || got.Subject != identity.Subject {
		t.Fatalf("cached issuer/subject = %q %q", got.Issuer, got.Subject)
	}
	if got.ResolvedRoles == nil || len(got.ResolvedRoles.Permissions) != 1 || got.ResolvedRoles.Permissions[0] != "hosts-view" {
		t.Fatalf("unexpected cached permissions: %#v", got.ResolvedRoles)
	}

	now = now.Add(31 * time.Second)
	if _, ok := svc.Get("https://privx.example.com", identity); ok {
		t.Fatal("expected cache miss after ttl expiry")
	}
}

func TestServiceDisabledWhenTTLIsZero(t *testing.T) {
	svc := NewService(0)
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	svc.Set("https://privx.example.com", identity, CachedUserContext{
		UserID: "u-123",
	})
	if _, ok := svc.Get("https://privx.example.com", identity); ok {
		t.Fatal("expected disabled cache to always miss")
	}
}

func TestTryInvalidateForRefresh_CooldownAndUserID(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	svc := NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}
	baseURL := "https://privx.example.com"
	cooldown := time.Minute

	svc.Set(baseURL, identity, CachedUserContext{UserID: "u-123"})

	userID, ok := svc.TryInvalidateForRefresh(baseURL, identity, cooldown)
	if !ok {
		t.Fatal("expected first invalidate to succeed")
	}
	if userID != "u-123" {
		t.Fatalf("unexpected user id %q, want u-123", userID)
	}
	if _, hit := svc.Get(baseURL, identity); hit {
		t.Fatal("expected cache entry to be dropped after invalidate")
	}

	if _, ok := svc.TryInvalidateForRefresh(baseURL, identity, cooldown); ok {
		t.Fatal("expected second invalidate inside cooldown to be skipped")
	}

	now = now.Add(time.Minute)
	userID, ok = svc.TryInvalidateForRefresh(baseURL, identity, cooldown)
	if !ok {
		t.Fatal("expected invalidate after cooldown to succeed")
	}
	if userID != "" {
		t.Fatalf("expected empty user id when cache entry is already gone, got %q", userID)
	}
}

func TestTryInvalidateForRefresh_DisabledOrZeroCooldown(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}
	baseURL := "https://privx.example.com"

	disabled := NewService(0)
	if _, ok := disabled.TryInvalidateForRefresh(baseURL, identity, time.Minute); ok {
		t.Fatal("expected disabled cache to skip invalidate")
	}

	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	enabled := NewServiceWithClock(30*time.Second, func() time.Time { return now })
	enabled.Set(baseURL, identity, CachedUserContext{UserID: "u-123"})
	if _, ok := enabled.TryInvalidateForRefresh(baseURL, identity, 0); ok {
		t.Fatal("expected zero cooldown to skip invalidate")
	}
	if _, hit := enabled.Get(baseURL, identity); !hit {
		t.Fatal("expected zero cooldown to leave the cache entry in place")
	}
}

func TestBindIssuerSubjectRejectsMissingAndChangedPair(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	svc := NewServiceWithClock(30*time.Second, func() time.Time { return now })
	baseURL := "https://privx.example.com"
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	if err := svc.BindIssuerSubject(baseURL, "alice", &oauth.IdentityClaims{Subject: "user-1"}); !errors.Is(err, ErrIssuerSubjectRequired) {
		t.Fatalf("expected missing issuer to be rejected, got %v", err)
	}
	if err := svc.BindIssuerSubject(baseURL, "alice", &oauth.IdentityClaims{Issuer: "https://issuer.example.com"}); !errors.Is(err, ErrIssuerSubjectRequired) {
		t.Fatalf("expected missing subject to be rejected, got %v", err)
	}
	if err := svc.BindIssuerSubject(baseURL, "alice", identity); err != nil {
		t.Fatalf("expected first bind to succeed, got %v", err)
	}
	if err := svc.BindIssuerSubject(baseURL, "alice", identity); err != nil {
		t.Fatalf("expected same pair to be accepted, got %v", err)
	}

	changed := &oauth.IdentityClaims{Issuer: identity.Issuer, Subject: "user-2"}
	if err := svc.BindIssuerSubject(baseURL, "alice", changed); !errors.Is(err, ErrIssuerSubjectChanged) {
		t.Fatalf("expected changed subject to be rejected, got %v", err)
	}

	otherUser := &oauth.IdentityClaims{Issuer: "https://other.example.com", Subject: "user-9"}
	if err := svc.BindIssuerSubject(baseURL, "bob", otherUser); err != nil {
		t.Fatalf("expected a different user to bind its own pair, got %v", err)
	}

	now = now.Add(31 * time.Second)
	if err := svc.BindIssuerSubject(baseURL, "alice", changed); err != nil {
		t.Fatalf("expected a new pair after expiry, got %v", err)
	}
}

func TestBindIssuerSubjectDisabledStillRequiresPair(t *testing.T) {
	svc := NewService(0)
	if err := svc.BindIssuerSubject("https://privx.example.com", "alice", &oauth.IdentityClaims{Subject: "user-1"}); !errors.Is(err, ErrIssuerSubjectRequired) {
		t.Fatalf("expected missing issuer to be rejected, got %v", err)
	}

	identity := &oauth.IdentityClaims{Issuer: "https://issuer.example.com", Subject: "user-1"}
	if err := svc.BindIssuerSubject("https://privx.example.com", "alice", identity); err != nil {
		t.Fatalf("expected disabled cache to accept a complete pair, got %v", err)
	}

	changed := &oauth.IdentityClaims{Issuer: identity.Issuer, Subject: "user-2"}
	if err := svc.BindIssuerSubject("https://privx.example.com", "alice", changed); err != nil {
		t.Fatalf("expected disabled cache to skip stability check, got %v", err)
	}
}

func testTimeUTC(t *testing.T, value string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	return parsed
}
