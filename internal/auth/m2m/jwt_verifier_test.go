package m2m

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pmsshintegration/privx-mcp/internal/config"
)

func TestJWTVerifier(t *testing.T) {
	rows := []config.M2MJWTIdentity{
		{Claim: "preferred_username", Value: "jdone", Username: "john.done"},
		{Claim: "email", Value: "ada@example.com", Username: "ada"},
	}
	v := NewJWTVerifier(rows, "https://idp.example")
	defer v.Close()

	now := time.Now()
	ci, err := v.Verify(context.Background(), jwtToken(t, jwt.MapClaims{
		"sub":                "user-1",
		"iss":                "https://idp.example",
		"preferred_username": "jdone",
		"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
	}))
	if err != nil {
		t.Fatal(err)
	}

	if ci.Issuer != JWTIssuer || ci.Subject != "john.done" || ci.Email != "john.done" || ci.UPN != "john.done" {
		t.Fatalf("claims = %#v", ci)
	}

	if ci.RawClaims["sub"] != "user-1" || ci.RawClaims["exp"] == nil {
		t.Fatalf("raw = %#v", ci.RawClaims)
	}

	if !UsesConfiguredUsername(ci.Issuer) || !UsesConfiguredUsername(Issuer) {
		t.Fatal("configured username issuers")
	}

	email, err := v.Verify(context.Background(), jwtToken(t, jwt.MapClaims{
		"sub":   "ada-sub",
		"iss":   "https://idp.example",
		"email": "ada@example.com",
		"exp":   jwt.NewNumericDate(now.Add(time.Hour)),
	}))
	if err != nil {
		t.Fatal(err)
	}

	if email.Subject != "ada" {
		t.Fatalf("subject = %q", email.Subject)
	}

	for _, tc := range []struct {
		name   string
		claims jwt.MapClaims
		want   string
	}{
		{
			name: "expired",
			claims: jwt.MapClaims{
				"iss":                "https://idp.example",
				"preferred_username": "jdone",
				"exp":                jwt.NewNumericDate(now.Add(-time.Hour)),
			},
			want: "validate token",
		},
		{
			name: "missing exp",
			claims: jwt.MapClaims{
				"iss":                "https://idp.example",
				"preferred_username": "jdone",
			},
			want: "validate token",
		},
		{
			name: "issuer mismatch",
			claims: jwt.MapClaims{
				"iss":                "https://other.example",
				"preferred_username": "jdone",
				"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
			},
			want: "validate token",
		},
		{
			name: "unmapped",
			claims: jwt.MapClaims{
				"iss":                "https://idp.example",
				"preferred_username": "nobody",
				"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
			},
			want: "matched 0 rows",
		},
		{
			name: "two rows",
			claims: jwt.MapClaims{
				"iss":                "https://idp.example",
				"preferred_username": "jdone",
				"email":              "ada@example.com",
				"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
			},
			want: "matched 2 rows",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), jwtToken(t, tc.claims))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}

	open := NewJWTVerifier(rows, "")
	if _, err := open.Verify(context.Background(), jwtToken(t, jwt.MapClaims{
		"iss":                "https://anywhere.example",
		"preferred_username": "jdone",
		"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
	})); err != nil {
		t.Fatal(err)
	}
}

func jwtToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-checked"))
	if err != nil {
		t.Fatal(err)
	}

	return raw
}
