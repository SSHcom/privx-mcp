package oauth

import (
	"testing"
)

func TestParseBearerChallenge(t *testing.T) {
	t.Parallel()

	meta := "http://localhost:8181/.well-known/oauth-protected-resource"
	quoted := `Bearer resource_metadata="` + meta + `"`

	tests := []struct {
		name    string
		header  string
		wantOK  bool
		wantURL string
		wantSc  string
	}{
		{
			name:    "go percent-q quoted",
			header:  quoted,
			wantOK:  true,
			wantURL: meta,
		},
		{
			name:    "unquoted",
			header:  "Bearer resource_metadata=" + meta,
			wantOK:  true,
			wantURL: meta,
		},
		{
			name:    "scope quoted",
			header:  `Bearer realm="mcp", resource_metadata="` + meta + `", scope="openid profile"`,
			wantOK:  true,
			wantURL: meta,
			wantSc:  "openid profile",
		},
		{
			name:   "basic only",
			header: `Basic realm="x"`,
			wantOK: false,
		},
		{
			name:    "bearer among basic",
			header:  `Basic realm="x", Bearer resource_metadata="` + meta + `"`,
			wantOK:  true,
			wantURL: meta,
		},
		{
			name:   "empty",
			header: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseBearerChallenge(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}

			if !tt.wantOK {
				return
			}

			if got.ResourceMetadata != tt.wantURL {
				t.Fatalf("resource_metadata = %q, want %q", got.ResourceMetadata, tt.wantURL)
			}

			if got.Scope != tt.wantSc {
				t.Fatalf("scope = %q, want %q", got.Scope, tt.wantSc)
			}
		})
	}
}
