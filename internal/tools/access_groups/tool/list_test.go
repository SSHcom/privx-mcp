package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestListAccessGroupsHandler_NoAuth(t *testing.T) {
	res, err := listHandler(testconn.CtxNoAuth(), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListAccessGroupsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/authorizer/api/v1/accessgroups", func(body any) (any, error) {
		return response.ResultSet[authorizer.AccessGroup]{
			Count: 2,
			Items: []authorizer.AccessGroup{
				{ID: "ag1", Name: "Default", HostCertificateTrustAnchors: "HOST", CAKeyType: "RSA"},
				{ID: "ag2", Name: "test"},
			},
		}, nil
	})

	res, err := listHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 2 {
		t.Errorf("count = %v", m["count"])
	}
	if m["returned"].(float64) != 2 {
		t.Errorf("returned = %v", m["returned"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %v", m["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("first item not a map: %T", items[0])
	}
	if first["name"] != "Default" {
		t.Errorf("first name = %v, want Default", first["name"])
	}
	if _, ok := first["host_certificate_trust_anchors"]; ok {
		t.Error("host_certificate_trust_anchors should be redacted")
	}
	if first["key_type"] != "RSA" {
		t.Errorf("key_type = %v", first["key_type"])
	}
}
