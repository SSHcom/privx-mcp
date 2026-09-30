package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// IdentityTokenVerifier verifies external OIDC identity tokens.
type IdentityTokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*IdentityClaims, error)
}

// IdentityClaims holds the verified claims from an OIDC identity token.
type IdentityClaims struct {
	Subject   string
	Email     string
	UPN       string
	Issuer    string
	Audience  []string
	RawClaims map[string]any
}

// VerificationError represents a token verification failure with a stable reason.
type VerificationError struct {
	Reason  string // e.g. "invalid_signature", "expired", "wrong_audience", "wrong_issuer"
	Message string
}

func (e *VerificationError) Error() string {
	return e.Message
}

// JWKSTokenVerifierConfig defines configuration for JWKS-based verification.
type JWKSTokenVerifierConfig struct {
	JWKSURI          string
	ExpectedIssuer   string
	ExpectedAudience string
	CacheTTL         time.Duration
}

// JWKSTokenVerifier verifies identity tokens using keys from a JWKS endpoint.
type JWKSTokenVerifier struct {
	jwks             *keyfunc.JWKS
	expectedIssuer   string
	expectedAudience string
}

// NewJWKSTokenVerifier constructs a verifier that periodically refreshes JWKS keys.
func NewJWKSTokenVerifier(cfg JWKSTokenVerifierConfig) (*JWKSTokenVerifier, error) {
	if cfg.JWKSURI == "" {
		return nil, fmt.Errorf("JWKS URI is required")
	}

	if cfg.ExpectedIssuer == "" {
		return nil, fmt.Errorf("expected issuer is required")
	}

	if cfg.ExpectedAudience == "" {
		return nil, fmt.Errorf("expected audience is required")
	}

	refreshInterval := cfg.CacheTTL
	if refreshInterval == 0 {
		refreshInterval = 1 * time.Hour
	}

	options := keyfunc.Options{
		RefreshInterval: refreshInterval,
		RefreshErrorHandler: func(err error) {
			logging.Warn(
				"JWKS refresh failed; keeping previous keys",
				"uri", cfg.JWKSURI,
				"err", err,
			)
		},
	}

	jwks, err := keyfunc.Get(cfg.JWKSURI, options)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", cfg.JWKSURI, err)
	}

	return &JWKSTokenVerifier{
		jwks:             jwks,
		expectedIssuer:   cfg.ExpectedIssuer,
		expectedAudience: cfg.ExpectedAudience,
	}, nil
}

// Verify parses and validates the given raw JWT token string.
func (v *JWKSTokenVerifier) Verify(_ context.Context, rawToken string) (*IdentityClaims, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithIssuer(v.expectedIssuer),
		jwt.WithAudience(v.expectedAudience),
		jwt.WithExpirationRequired(),
	}

	token, err := jwt.Parse(rawToken, v.jwks.Keyfunc, parserOpts...)
	if err != nil {
		authErr := v.classifyError(err)
		v.logTokenTiming(rawToken, authErr)

		return nil, authErr
	}

	if !token.Valid {
		return nil, &VerificationError{
			Reason:  "invalid_token",
			Message: "token validation failed",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &VerificationError{
			Reason:  "invalid_token",
			Message: "unable to extract token claims",
		}
	}

	idClaims, err := v.extractClaims(claims)
	if err != nil {
		var authErr *VerificationError
		if errors.As(err, &authErr) {
			v.logTokenTimingFromClaims(claims, authErr)
		}

		return nil, err
	}

	v.logTokenTimingFromClaims(claims, nil)

	return idClaims, nil
}

// logTokenTiming reads exp/iat without validating the token so expiration can be
// inspected even when verification fails (e.g. expired → 401).
func (v *JWKSTokenVerifier) logTokenTiming(rawToken string, authErr *VerificationError) {
	parser := jwt.NewParser()

	token, _, err := parser.ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		reason := "unknown"
		if authErr != nil {
			reason = authErr.Reason
		}

		logging.Debug("token verification claims parse failed", "reason", reason, "err", err)

		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return
	}

	v.logTokenTimingFromClaims(claims, authErr)
}

func (v *JWKSTokenVerifier) logTokenTimingFromClaims(claims jwt.MapClaims, authErr *VerificationError) {
	now := time.Now().UTC()
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	sub, _ := claims.GetSubject()

	expInfo := "missing"

	if exp != nil {
		delta := exp.Time.Sub(now).Round(time.Second)
		if delta >= 0 {
			expInfo = fmt.Sprintf("%s (in %s)", exp.Time.UTC().Format(time.RFC3339), delta)
		} else {
			expInfo = fmt.Sprintf("%s (%s ago)", exp.Time.UTC().Format(time.RFC3339), -delta)
		}
	}

	iatInfo := "missing"
	if iat != nil {
		iatInfo = iat.Time.UTC().Format(time.RFC3339)
	}

	if authErr != nil {
		logging.Debug(
			"token verification failed",
			"reason", authErr.Reason,
			"sub", sub,
			"iat", iatInfo,
			"exp", expInfo,
			"now", now.Format(time.RFC3339),
		)

		return
	}

	logging.Debug(
		"token verified",
		"sub", sub,
		"iat", iatInfo,
		"exp", expInfo,
		"now", now.Format(time.RFC3339),
	)
}

// Close shuts down the background JWKS refresh goroutine.
func (v *JWKSTokenVerifier) Close() {
	v.jwks.EndBackground()
}

func (v *JWKSTokenVerifier) classifyError(err error) *VerificationError {
	switch {
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return &VerificationError{
			Reason:  "invalid_signature",
			Message: "token signature verification failed",
		}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &VerificationError{
			Reason:  "expired",
			Message: "token has expired",
		}
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return &VerificationError{
			Reason:  "wrong_audience",
			Message: fmt.Sprintf("token audience does not match expected audience %q", v.expectedAudience),
		}
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return &VerificationError{
			Reason:  "wrong_issuer",
			Message: fmt.Sprintf("token issuer does not match expected issuer %q", v.expectedIssuer),
		}
	}

	return &VerificationError{
		Reason:  "invalid_token",
		Message: fmt.Sprintf("token verification failed: %v", err),
	}
}

func (v *JWKSTokenVerifier) extractClaims(claims jwt.MapClaims) (*IdentityClaims, error) {
	idClaims := &IdentityClaims{
		RawClaims: make(map[string]any, len(claims)),
	}

	for k, v := range claims {
		idClaims.RawClaims[k] = v
	}

	sub, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return nil, &VerificationError{
			Reason:  "missing_subject",
			Message: "token subject is required",
		}
	}

	idClaims.Subject = sub

	if email, ok := claims["email"].(string); ok {
		idClaims.Email = email
	}

	if upn, ok := claims["preferred_username"].(string); ok {
		idClaims.UPN = upn
	} else if upn, ok := claims["upn"].(string); ok {
		idClaims.UPN = upn
	}

	iss, ok := claims["iss"].(string)
	if !ok || strings.TrimSpace(iss) == "" {
		return nil, &VerificationError{
			Reason:  "missing_issuer",
			Message: "token issuer is required",
		}
	}

	idClaims.Issuer = iss

	switch aud := claims["aud"].(type) {
	case string:
		idClaims.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				idClaims.Audience = append(idClaims.Audience, s)
			}
		}
	}

	return idClaims, nil
}
