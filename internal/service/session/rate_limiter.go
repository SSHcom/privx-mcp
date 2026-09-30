package session

import (
	"sync"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

type rateLimitEntry struct {
	windowStart time.Time
	count       int
}

// RateLimiter enforces a fixed-window per-identity tool-call quota.
type RateLimiter struct {
	window    time.Duration
	max       int
	maxedWait time.Duration
	nowFunc   func() time.Time
	mu        sync.Mutex
	entries   map[string]rateLimitEntry
}

// NewRateLimiter returns a limiter using the wall clock.
func NewRateLimiter(windowSeconds, maxRequests, maxedWaitSeconds int) *RateLimiter {
	return NewRateLimiterWithClock(windowSeconds, maxRequests, maxedWaitSeconds, time.Now)
}

// NewRateLimiterWithClock returns a limiter driven by the given clock.
func NewRateLimiterWithClock(windowSeconds, maxRequests, maxedWaitSeconds int, nowFunc func() time.Time) *RateLimiter {
	if nowFunc == nil {
		nowFunc = time.Now
	}

	return &RateLimiter{
		window:    time.Duration(windowSeconds) * time.Second,
		max:       maxRequests,
		maxedWait: time.Duration(maxedWaitSeconds) * time.Second,
		nowFunc:   nowFunc,
		entries:   make(map[string]rateLimitEntry),
	}
}

// Enabled reports whether rate limiting is active.
func (r *RateLimiter) Enabled() bool {
	return r != nil && r.window > 0 && r.max > 0
}

// Allow records one request for the identity and reports whether it is within
// the configured fixed window quota. After a window that hit the max, the
// next window cannot start until maxedWait has also elapsed. Disabled
// limiters always allow.
func (r *RateLimiter) Allow(privxBaseURL string, identity *oauth.IdentityClaims) bool {
	if !r.Enabled() {
		return true
	}

	key, ok := BuildIdentityKey(privxBaseURL, identity)
	if !ok {
		return true
	}

	now := r.nowFunc()

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.entries[key]
	if exists {
		windowEnd := entry.windowStart.Add(r.window)

		nextAllowed := windowEnd
		if entry.count >= r.max && r.maxedWait > 0 {
			nextAllowed = windowEnd.Add(r.maxedWait)
		}

		if now.Before(nextAllowed) {
			if now.Before(windowEnd) && entry.count < r.max {
				entry.count++
				r.entries[key] = entry

				return true
			}

			return false
		}
	}

	r.entries[key] = rateLimitEntry{windowStart: now, count: 1}

	return true
}
