package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetHostHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1", CommonName: "web1"}, nil
	})
	res, err := getHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "h1" {
		t.Errorf("id = %v", m["id"])
	}
}

func TestGetHostHandler_RedactsSensitiveFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{
			ID:                      "h1",
			CommonName:              "web1",
			HostCertificateRaw:      "MIIC...",
			PasswordRotationEnabled: true,
			SSHHostPubKeys:          []hoststore.HostSSHPubKeys{{Key: "ssh-ed25519 AAAA"}},
			Principals: []hoststore.HostPrincipals{{
				Principal:  "admin",
				Passphrase: "******************",
				Rotate:     true,
			}},
			Services: []hoststore.HostService{{
				Service:                "SSH",
				Address:                "10.0.0.1",
				UseForPasswordRotation: true,
				CertificateTemplate:    "default",
				AuthType:               "AUTOMATIC",
			}},
		}, nil
	})
	res, err := getHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	for _, field := range []string{
		"host_certificate_raw",
		"host_certificate",
		"ssh_host_public_keys",
		"password_rotation",
		"password_rotation_enabled",
	} {
		if _, ok := m[field]; ok {
			t.Errorf("field %q should be redacted", field)
		}
	}
	prin := m["principals"].([]any)[0].(map[string]any)
	if _, ok := prin["passphrase"]; ok {
		t.Error("passphrase should be redacted")
	}
	svc := m["services"].([]any)[0].(map[string]any)
	if _, ok := svc["certificate_template"]; ok {
		t.Error("certificate_template should be redacted")
	}
	if svc["auth_type"] != "AUTOMATIC" {
		t.Errorf("auth_type should remain, got %v", svc["auth_type"])
	}
}

func TestGetHostHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getHostHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetHostHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := getHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "failed to fetch host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
