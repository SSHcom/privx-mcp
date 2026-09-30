package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetAccessGroupHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/authorizer/api/v1/accessgroups/:id", func(body any) (any, error) {
		return authorizer.AccessGroup{
			ID:                               "ag1",
			Name:                             "Default",
			CAKeyType:                        "RSA",
			HostCertificateTrustAnchors:      "HOST",
			DBHostCertificateTrustAnchors:    "DB",
			WinRMHostCertificateTrustAnchors: "WINRM",
		}, nil
	})
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "ag1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "ag1" {
		t.Errorf("id = %v, want ag1", m["id"])
	}
	if m["key_type"] != "RSA" {
		t.Errorf("key_type = %v", m["key_type"])
	}
	for _, field := range []string{
		"host_certificate_trust_anchors",
		"db_host_certificate_trust_anchors",
		"winrm_host_certificate_trust_anchors",
	} {
		if _, ok := m[field]; ok {
			t.Errorf("%s should be redacted", field)
		}
	}
}

func TestGetAccessGroupHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
