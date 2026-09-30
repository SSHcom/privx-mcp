package oauth

import (
	"net/http"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
)

const (
	// DiscoverTimeout is the budget for a full probe + PRM + AS metadata walk.
	DiscoverTimeout = 15 * time.Second
	maxJSONBody     = 1 << 20
)

// NewHTTPClient returns a client for discovery and token requests.
func NewHTTPClient(allowHTTP bool) *http.Client {
	return httpx.NewClient(allowHTTP)
}
