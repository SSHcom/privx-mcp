package wellknown

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DCRStubConfig holds the static client credentials returned by the stub
// Dynamic Client Registration endpoint. This allows MCP clients (like Kiro)
// that require DCR to succeed without actual dynamic registration at the IdP.
type DCRStubConfig struct {
	ClientID     string
	ClientSecret string

	// Scopes are returned as a space-delimited scope string. Some MCP
	// clients seed their authorization request scope from the DCR response.
	Scopes []string
}

// RegisterDCRStub mounts a stub /register endpoint that returns pre-configured
// client credentials. MCP clients that require DCR will POST here and receive
// a valid client_id/client_secret without any actual registration at the IdP.
func RegisterDCRStub(mux *http.ServeMux, cfg DCRStubConfig) error {
	if mux == nil {
		return fmt.Errorf("dcr stub mux is required")
	}

	if cfg.ClientID == "" {
		return fmt.Errorf("dcr stub client_id is required")
	}

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the DCR request to extract redirect_uris.
		body, _ := io.ReadAll(r.Body)

		var dcrRequest map[string]any

		_ = json.Unmarshal(body, &dcrRequest)

		// Echo back redirect_uris from the request, or use a default.
		redirectURIs := []string{"http://localhost:7778/oauth/callback"}
		if uris, ok := dcrRequest["redirect_uris"].([]any); ok && len(uris) > 0 {
			redirectURIs = make([]string, 0, len(uris))
			for _, u := range uris {
				if s, ok := u.(string); ok {
					redirectURIs = append(redirectURIs, s)
				}
			}
		}

		response := map[string]any{
			"client_id":                  cfg.ClientID,
			"client_name":                "privx-mcp-client",
			"redirect_uris":              redirectURIs,
			"token_endpoint_auth_method": "client_secret_post",
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
		}
		if cfg.ClientSecret != "" {
			response["client_secret"] = cfg.ClientSecret
		}

		if len(cfg.Scopes) > 0 {
			response["scope"] = strings.Join(cfg.Scopes, " ")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	})

	return nil
}
