package jwtcheck

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signed(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-checked"))
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func parsed(t *testing.T, claims jwt.MapClaims) jwt.MapClaims {
	t.Helper()

	got, err := ParseUnverified(signed(t, claims))
	if err != nil {
		t.Fatal(err)
	}

	return got
}

func TestParseUnverifiedIgnoresSignature(t *testing.T) {
	claims, err := ParseUnverified(signed(t, jwt.MapClaims{
		"sub": "user-1",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}))
	if err != nil {
		t.Fatal(err)
	}

	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v", claims["sub"])
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	issuer := "https://idp.example"
	audience := "api://app"

	valid := jwt.MapClaims{
		"sub": "user-1",
		"iss": issuer,
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(time.Hour)),
	}

	cases := []struct {
		name    string
		claims  jwt.MapClaims
		opts    Options
		wantErr error
	}{
		{
			name:   "issuer match",
			claims: valid,
			opts:   Options{ExpectedIssuer: issuer, ExpectedAudience: audience},
		},
		{
			name: "expired",
			claims: jwt.MapClaims{
				"sub": "user-1",
				"iss": issuer,
				"exp": jwt.NewNumericDate(now.Add(-time.Hour)),
			},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "missing exp",
			claims: jwt.MapClaims{
				"sub": "user-1",
				"iss": issuer,
			},
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:    "issuer mismatch",
			claims:  valid,
			opts:    Options{ExpectedIssuer: "https://other.example"},
			wantErr: jwt.ErrTokenInvalidIssuer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(parsed(t, tc.claims), tc.opts)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestExtractEmailAndPreferredUsername(t *testing.T) {
	now := time.Now()
	got, err := Extract(parsed(t, jwt.MapClaims{
		"sub":                "user-1",
		"iss":                "https://idp.example",
		"aud":                []string{"api://app", "api://other"},
		"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
		"email":              "alice@example.com",
		"preferred_username": "alice",
	}))
	if err != nil {
		t.Fatal(err)
	}

	if got.Email != "alice@example.com" || got.PreferredUsername != "alice" {
		t.Fatalf("email=%q preferred_username=%q", got.Email, got.PreferredUsername)
	}

	if len(got.Audience) != 2 || got.Audience[0] != "api://app" {
		t.Fatalf("aud = %v", got.Audience)
	}

	fallback, err := Extract(parsed(t, jwt.MapClaims{
		"sub": "user-1",
		"iss": "https://idp.example",
		"exp": jwt.NewNumericDate(now.Add(time.Hour)),
		"upn": "bob@example.com",
	}))
	if err != nil {
		t.Fatal(err)
	}

	if fallback.PreferredUsername != "bob@example.com" {
		t.Fatalf("upn fallback = %q", fallback.PreferredUsername)
	}
}
