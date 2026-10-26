package jwtcheck

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrMissingSubject is returned when sub is absent or blank.
	ErrMissingSubject = errors.New("token subject is required")
	// ErrMissingIssuer is returned when iss is absent or blank.
	ErrMissingIssuer = errors.New("token issuer is required")
)

// Claims holds the identity fields read from a JWT.
type Claims struct {
	Subject           string
	Email             string
	PreferredUsername string
	Issuer            string
	Audience          []string
	Raw               map[string]any
}

// Options selects issuer and audience checks. Expiration is always required.
type Options struct {
	ExpectedIssuer   string
	ExpectedAudience string
}

// ParseUnverified reads MapClaims from a JWT and does not check the signature.
func ParseUnverified(raw string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unable to extract token claims")
	}

	return claims, nil
}

// Validate requires a non-expired exp. Issuer and audience are checked when set.
func Validate(claims jwt.MapClaims, opts Options) error {
	parserOpts := []jwt.ParserOption{jwt.WithExpirationRequired()}

	if opts.ExpectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(opts.ExpectedIssuer))
	}

	if opts.ExpectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(opts.ExpectedAudience))
	}

	return jwt.NewValidator(parserOpts...).Validate(claims)
}

// Extract reads sub, iss, aud, email, and preferred_username.
// preferred_username falls back to upn. sub and iss are required.
func Extract(claims jwt.MapClaims) (Claims, error) {
	out := Claims{
		Raw: make(map[string]any, len(claims)),
	}

	for key, value := range claims {
		out.Raw[key] = value
	}

	sub, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return Claims{}, ErrMissingSubject
	}

	out.Subject = sub

	if email, ok := claims["email"].(string); ok {
		out.Email = email
	}

	if name, ok := claims["preferred_username"].(string); ok {
		out.PreferredUsername = name
	} else if name, ok := claims["upn"].(string); ok {
		out.PreferredUsername = name
	}

	iss, ok := claims["iss"].(string)
	if !ok || strings.TrimSpace(iss) == "" {
		return Claims{}, ErrMissingIssuer
	}

	out.Issuer = iss

	switch aud := claims["aud"].(type) {
	case string:
		out.Audience = []string{aud}
	case []any:
		for _, item := range aud {
			text, ok := item.(string)
			if !ok {
				continue
			}

			out.Audience = append(out.Audience, text)
		}
	}

	return out, nil
}
