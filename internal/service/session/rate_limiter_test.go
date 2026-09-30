package session

import (
	"testing"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

func TestRateLimiterDisabledWhenEitherSettingZero(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	for _, limiter := range []*RateLimiter{
		NewRateLimiter(0, 10, 0),
		NewRateLimiter(60, 0, 0),
		NewRateLimiter(0, 0, 30),
		NewRateLimiter(0, 0, 0),
		nil,
	} {
		if limiter.Enabled() {
			t.Fatal("expected rate limiter to be disabled")
		}
		if !limiter.Allow("https://privx.example.com", identity) {
			t.Fatal("expected disabled rate limiter to allow")
		}
	}
}

func TestRateLimiterAllowsUntilMaxThenBlocks(t *testing.T) {
	now := testTimeUTC(t, "2026-07-31T10:00:00Z")
	limiter := NewRateLimiterWithClock(60, 3, 0, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	for i := 0; i < 3; i++ {
		if !limiter.Allow("https://privx.example.com", identity) {
			t.Fatalf("expected allow on request %d", i+1)
		}
	}
	if limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected deny after max requests in window")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	now := testTimeUTC(t, "2026-07-31T10:00:00Z")
	limiter := NewRateLimiterWithClock(60, 2, 0, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected first request allowed")
	}
	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected second request allowed")
	}
	if limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected third request denied")
	}

	now = now.Add(60 * time.Second)
	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected request allowed after window reset")
	}
}

func TestRateLimiterIsolatesIdentities(t *testing.T) {
	now := testTimeUTC(t, "2026-07-31T10:00:00Z")
	limiter := NewRateLimiterWithClock(60, 1, 0, func() time.Time { return now })

	alice := &oauth.IdentityClaims{Issuer: "https://issuer.example.com", Subject: "alice"}
	bob := &oauth.IdentityClaims{Issuer: "https://issuer.example.com", Subject: "bob"}

	if !limiter.Allow("https://privx.example.com", alice) {
		t.Fatal("expected alice allowed")
	}
	if limiter.Allow("https://privx.example.com", alice) {
		t.Fatal("expected alice denied on second call")
	}
	if !limiter.Allow("https://privx.example.com", bob) {
		t.Fatal("expected bob allowed independently")
	}
}

func TestRateLimiterMaxedWindowWaitBlocksUntilCooldown(t *testing.T) {
	now := testTimeUTC(t, "2026-07-31T10:00:00Z")
	limiter := NewRateLimiterWithClock(60, 2, 30, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected first request allowed")
	}
	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected second request allowed")
	}
	if limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected third request denied")
	}

	now = now.Add(60 * time.Second)
	if limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected request denied during maxed-window wait")
	}

	now = now.Add(29 * time.Second)
	if limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected request denied before maxed-window wait elapses")
	}

	now = now.Add(1 * time.Second)
	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected request allowed after window and maxed-window wait")
	}
}

func TestRateLimiterMaxedWindowWaitSkippedWhenWindowNotMaxed(t *testing.T) {
	now := testTimeUTC(t, "2026-07-31T10:00:00Z")
	limiter := NewRateLimiterWithClock(60, 2, 30, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
	}

	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected first request allowed")
	}

	now = now.Add(60 * time.Second)
	if !limiter.Allow("https://privx.example.com", identity) {
		t.Fatal("expected request allowed after unmaxed window with no extra wait")
	}
}
