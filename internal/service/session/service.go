package session

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

// ErrIssuerSubjectRequired is returned when an authenticated caller has no
// OpenID issuer or subject.
var ErrIssuerSubjectRequired = errors.New("issuer and subject are required")

// ErrIssuerSubjectChanged is returned when an authenticated user presents a
// different OpenID issuer or subject than the pair stored for the current session.
var ErrIssuerSubjectChanged = errors.New("issuer or subject changed")

// CachedUserContext is the resolved PrivX user context stored per identity.
type CachedUserContext struct {
	UserID          string
	ResolvedRoles   *rolestore.User
	ConnectorUserID string
	Issuer          string
	Subject         string
}

type issuerSubjectBinding struct {
	issuer    string
	subject   string
	expiresAt time.Time
}

type cacheEntry struct {
	value     CachedUserContext
	expiresAt time.Time
}

// Service caches per-identity PrivX user context for a short TTL.
type Service struct {
	ttl         time.Duration
	nowFunc     func() time.Time
	mu          sync.RWMutex
	entries     map[string]cacheEntry
	lastRefresh map[string]time.Time
	bindings    map[string]issuerSubjectBinding
}

// NewService returns a cache with the given TTL, backed by the wall clock.
func NewService(ttl time.Duration) *Service {
	return NewServiceWithClock(ttl, time.Now)
}

// NewServiceWithClock returns a cache with the given TTL and clock; a nil clock
// falls back to time.Now.
func NewServiceWithClock(ttl time.Duration, nowFunc func() time.Time) *Service {
	if nowFunc == nil {
		nowFunc = time.Now
	}

	return &Service{
		ttl:         ttl,
		nowFunc:     nowFunc,
		entries:     make(map[string]cacheEntry),
		lastRefresh: make(map[string]time.Time),
		bindings:    make(map[string]issuerSubjectBinding),
	}
}

// ValidateIssuerSubject returns an error when the OpenID issuer or subject is missing.
func ValidateIssuerSubject(identity *oauth.IdentityClaims) error {
	_, _, err := issuerAndSubject(identity)
	return err
}

// BindIssuerSubject stores the OpenID issuer and subject for an authenticated
// user. Both must be present. Until the session TTL expires, a later call for
// the same PrivX base URL and user must present the same pair.
// A disabled session cache still rejects a missing issuer or subject, and it
// does not remember the pair.
func (s *Service) BindIssuerSubject(privxBaseURL, userKey string, identity *oauth.IdentityClaims) error {
	issuer, subject, err := issuerAndSubject(identity)
	if err != nil {
		return err
	}

	if !s.Enabled() {
		return nil
	}

	baseURL := strings.TrimSpace(privxBaseURL)

	userKey = strings.TrimSpace(userKey)
	if baseURL == "" || userKey == "" {
		return fmt.Errorf("authenticated user and privx base url are required")
	}

	key := baseURL + "|" + userKey
	now := s.nowFunc()

	s.mu.Lock()
	defer s.mu.Unlock()

	binding, exists := s.bindings[key]
	if exists && now.Before(binding.expiresAt) {
		if binding.issuer != issuer || binding.subject != subject {
			return ErrIssuerSubjectChanged
		}

		binding.expiresAt = now.Add(s.ttl)
		s.bindings[key] = binding

		return nil
	}

	s.bindings[key] = issuerSubjectBinding{
		issuer:    issuer,
		subject:   subject,
		expiresAt: now.Add(s.ttl),
	}

	return nil
}

func issuerAndSubject(identity *oauth.IdentityClaims) (string, string, error) {
	if identity == nil {
		return "", "", ErrIssuerSubjectRequired
	}

	issuer := strings.TrimSpace(identity.Issuer)

	subject := strings.TrimSpace(identity.Subject)
	if issuer == "" || subject == "" {
		return "", "", ErrIssuerSubjectRequired
	}

	return issuer, subject, nil
}

// Enabled reports whether caching is active; a nil service or zero TTL disables it.
func (s *Service) Enabled() bool {
	return s != nil && s.ttl > 0
}

// Get returns the cached context for an identity, dropping it once the TTL expired.
func (s *Service) Get(privxBaseURL string, identity *oauth.IdentityClaims) (CachedUserContext, bool) {
	if !s.Enabled() {
		return CachedUserContext{}, false
	}

	key, ok := BuildIdentityKey(privxBaseURL, identity)
	if !ok {
		return CachedUserContext{}, false
	}

	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return CachedUserContext{}, false
	}

	if !s.nowFunc().Before(entry.expiresAt) {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()

		return CachedUserContext{}, false
	}

	return cloneCachedUserContext(entry.value), true
}

// Set stores a copy of the context for an identity and restarts its TTL.
func (s *Service) Set(privxBaseURL string, identity *oauth.IdentityClaims, value CachedUserContext) {
	if !s.Enabled() {
		return
	}

	key, ok := BuildIdentityKey(privxBaseURL, identity)
	if !ok {
		return
	}

	stored := cloneCachedUserContext(value)
	stored.Issuer = strings.TrimSpace(identity.Issuer)
	stored.Subject = strings.TrimSpace(identity.Subject)

	s.mu.Lock()
	s.entries[key] = cacheEntry{
		value:     stored,
		expiresAt: s.nowFunc().Add(s.ttl),
	}
	s.mu.Unlock()
}

// TryInvalidateForRefresh drops the cached context so the next lookup hits
// PrivX, subject to a per-identity cooldown. lastRefresh outlives the cache
// entry so deleting the value does not reset the cooldown. ok is false when
// caching is disabled, the identity key is missing, cooldown is <= 0, or the
// cooldown has not elapsed. On success it returns the previous UserID so the
// caller can skip SearchAllUsers.
func (s *Service) TryInvalidateForRefresh(
	privxBaseURL string,
	identity *oauth.IdentityClaims,
	cooldown time.Duration,
) (userID string, ok bool) {
	if !s.Enabled() || cooldown <= 0 {
		return "", false
	}

	key, keyOK := BuildIdentityKey(privxBaseURL, identity)
	if !keyOK {
		return "", false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	if last, exists := s.lastRefresh[key]; exists && now.Before(last.Add(cooldown)) {
		return "", false
	}

	s.lastRefresh[key] = now

	if entry, exists := s.entries[key]; exists {
		userID = strings.TrimSpace(entry.value.UserID)

		delete(s.entries, key)
	}

	return userID, true
}

// BuildIdentityKey returns a tenant-safe cache key for an identity.
func BuildIdentityKey(privxBaseURL string, identity *oauth.IdentityClaims) (string, bool) {
	if identity == nil {
		return "", false
	}

	baseURL := strings.TrimSpace(privxBaseURL)
	issuer := strings.TrimSpace(identity.Issuer)

	subject := strings.TrimSpace(identity.Subject)
	if baseURL == "" || issuer == "" || subject == "" {
		return "", false
	}

	return baseURL + "|" + issuer + "|" + subject, true
}

func cloneCachedUserContext(value CachedUserContext) CachedUserContext {
	return CachedUserContext{
		UserID:          strings.TrimSpace(value.UserID),
		ResolvedRoles:   cloneUser(value.ResolvedRoles),
		ConnectorUserID: strings.TrimSpace(value.ConnectorUserID),
		Issuer:          strings.TrimSpace(value.Issuer),
		Subject:         strings.TrimSpace(value.Subject),
	}
}

func cloneUser(user *rolestore.User) *rolestore.User {
	if user == nil {
		return nil
	}

	userCopy := *user
	userCopy.Permissions = append([]string(nil), user.Permissions...)

	userCopy.Roles = make([]rolestore.Role, len(user.Roles))
	for i := range user.Roles {
		roleCopy := user.Roles[i]
		roleCopy.Permissions = append([]string(nil), user.Roles[i].Permissions...)
		roleCopy.Context.Validity = append([]string(nil), user.Roles[i].Context.Validity...)
		userCopy.Roles[i] = roleCopy
	}

	return &userCopy
}
