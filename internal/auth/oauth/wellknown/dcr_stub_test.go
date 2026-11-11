package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func TestRegisterDCRStub_RejectsOversizedBody(t *testing.T) {
	mux := http.NewServeMux()
	if err := RegisterDCRStub(mux, DCRStubConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}); err != nil {
		t.Fatalf("RegisterDCRStub() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", http.NoBody)
	req.ContentLength = utils.MaxRequestBody + 1
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}

	if strings.Contains(rec.Body.String(), "client-secret") {
		t.Fatal("oversized registration returned the client secret")
	}
}

func TestRegisterDCRStub_AcceptsSmallBody(t *testing.T) {
	mux := http.NewServeMux()
	if err := RegisterDCRStub(mux, DCRStubConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}); err != nil {
		t.Fatalf("RegisterDCRStub() error = %v", err)
	}

	payload := `{"redirect_uris":["http://127.0.0.1/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	uris, ok := body["redirect_uris"].([]any)
	if !ok || len(uris) != 1 || uris[0] != "http://127.0.0.1/callback" {
		t.Fatalf("redirect_uris = %#v", body["redirect_uris"])
	}
}
