package hosts

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestPatchHost_StringScalars(t *testing.T) {
	h := &hoststore.Host{}
	ac := &auth.AuthContext{}
	err := PatchHost(h, map[string]any{
		"common_name":           "web1",
		"organization":          "acme",
		"organizational_unit":   "eng",
		"zone":                  "dmz",
		"host_type":             "aws-ec2",
		"host_classification":   "restricted",
		"comment":               "test host",
		"contact_address":       "ops@example.com",
		"user_message":          "welcome",
		"distinguished_name":    "cn=web1",
		"external_id":           "ext-1",
		"instance_id":           "i-123",
		"access_group_id":       "ag-1",
		"cloud_provider":        "aws",
		"cloud_provider_region": "eu-west-1",
	}, ac)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.CommonName != "web1" {
		t.Errorf("common_name = %q", h.CommonName)
	}
	if h.Organization != "acme" {
		t.Errorf("organization = %q", h.Organization)
	}
	if h.OrganizationalUnit != "eng" {
		t.Errorf("organizational_unit = %q", h.OrganizationalUnit)
	}
	if h.Zone != "dmz" {
		t.Errorf("zone = %q", h.Zone)
	}
	if h.HostType != "aws-ec2" {
		t.Errorf("host_type = %q", h.HostType)
	}
	if h.HostClassification != "restricted" {
		t.Errorf("host_classification = %q", h.HostClassification)
	}
	if h.Comment != "test host" {
		t.Errorf("comment = %q", h.Comment)
	}
	if h.ContactAddress != "ops@example.com" {
		t.Errorf("contact_address = %q", h.ContactAddress)
	}
	if h.UserMessage != "welcome" {
		t.Errorf("user_message = %q", h.UserMessage)
	}
	if h.DistinguishedName != "cn=web1" {
		t.Errorf("distinguished_name = %q", h.DistinguishedName)
	}
	if h.ExternalID != "ext-1" {
		t.Errorf("external_id = %q", h.ExternalID)
	}
	if h.InstanceID != "i-123" {
		t.Errorf("instance_id = %q", h.InstanceID)
	}
	if h.AccessGroupID != "ag-1" {
		t.Errorf("access_group_id = %q", h.AccessGroupID)
	}
	if h.CloudProvider != "aws" {
		t.Errorf("cloud_provider = %q", h.CloudProvider)
	}
	if h.CloudProviderRegion != "eu-west-1" {
		t.Errorf("cloud_provider_region = %q", h.CloudProviderRegion)
	}
}

func TestPatchHost_PreservesUntouchedFields(t *testing.T) {
	h := &hoststore.Host{CommonName: "keep", Organization: "keep-org"}
	err := PatchHost(h, map[string]any{"comment": "new"}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.CommonName != "keep" {
		t.Errorf("common_name should be preserved, got %q", h.CommonName)
	}
	if h.Organization != "keep-org" {
		t.Errorf("organization should be preserved, got %q", h.Organization)
	}
	if h.Comment != "new" {
		t.Errorf("comment = %q", h.Comment)
	}
}

func TestPatchHost_Addresses(t *testing.T) {
	t.Run("wholesale replace", func(t *testing.T) {
		h := &hoststore.Host{Addresses: []string{"old"}}
		err := PatchHost(h, map[string]any{"addresses": []any{"a", "b"}}, &auth.AuthContext{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !equalStrings(h.Addresses, []string{"a", "b"}) {
			t.Errorf("addresses = %v", h.Addresses)
		}
	})
	t.Run("empty rejected", func(t *testing.T) {
		h := &hoststore.Host{Addresses: []string{"old"}}
		err := PatchHost(h, map[string]any{"addresses": []any{}}, &auth.AuthContext{})
		if err == nil {
			t.Fatal("expected error for empty addresses")
		}
	})
	t.Run("bad type rejected", func(t *testing.T) {
		h := &hoststore.Host{}
		err := PatchHost(h, map[string]any{"addresses": "not-array"}, &auth.AuthContext{})
		if err == nil {
			t.Fatal("expected error for non-array addresses")
		}
	})
}

func TestPatchHost_ScopeAndTags(t *testing.T) {
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{
		"scope": []any{"prod", "web"},
		"tags":  []any{"tier-1"},
	}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !equalStrings(h.Scope, []string{"prod", "web"}) {
		t.Errorf("scope = %v", h.Scope)
	}
	if !equalStrings(h.Tags, []string{"tier-1"}) {
		t.Errorf("tags = %v", h.Tags)
	}
}

func TestPatchHost_BoolPointers(t *testing.T) {
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{
		"audit_enabled": true,
		"tofu":          false,
		"toch":          true,
	}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.AuditEnabled == nil || *h.AuditEnabled != true {
		t.Errorf("audit_enabled = %v", h.AuditEnabled)
	}
	if h.Tofu == nil || *h.Tofu != false {
		t.Errorf("tofu = %v", h.Tofu)
	}
	if h.Toch == nil || *h.Toch != true {
		t.Errorf("toch = %v", h.Toch)
	}
}

func TestPatchHost_StandAloneHost(t *testing.T) {
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{"stand_alone_host": true}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.StandAloneHost != true {
		t.Errorf("stand_alone_host = %v", h.StandAloneHost)
	}
}

func TestPatchHost_SessionRecordingOptions(t *testing.T) {
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{
		"session_recording_options": map[string]any{
			"disable_clipboard_recording":     true,
			"disable_file_transfer_recording": true,
		},
	}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.SessionRecordingOptions == nil {
		t.Fatal("expected non-nil session recording options")
	}
	if !h.SessionRecordingOptions.DisableClipboardRecording {
		t.Error("expected clipboard recording disabled")
	}
	if !h.SessionRecordingOptions.DisableFileTransferRecording {
		t.Error("expected file transfer recording disabled")
	}
}

func TestPatchHost_Services(t *testing.T) {
	t.Run("wholesale replace", func(t *testing.T) {
		h := &hoststore.Host{Services: []hoststore.HostService{{Service: "old"}}}
		err := PatchHost(h, map[string]any{
			"services": []any{
				map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
			},
		}, &auth.AuthContext{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(h.Services) != 1 || h.Services[0].Service != "SSH" {
			t.Errorf("services = %+v", h.Services)
		}
	})
	t.Run("bad item rejected", func(t *testing.T) {
		h := &hoststore.Host{}
		err := PatchHost(h, map[string]any{
			"services": []any{map[string]any{"service": "SSH"}}, // missing address/port
		}, &auth.AuthContext{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("non-array rejected", func(t *testing.T) {
		h := &hoststore.Host{}
		err := PatchHost(h, map[string]any{"services": "x"}, &auth.AuthContext{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestPatchHost_PrincipalsWithRoleResolution(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
		return response.ResultSet[testconn.RolestoreRole]{Items: []testconn.RolestoreRole{{ID: "r1", Name: "admin"}}}, nil
	})
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		},
	}, &auth.AuthContext{Connector: conn})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(h.Principals) != 1 || h.Principals[0].Principal != "root" {
		t.Errorf("principals = %+v", h.Principals)
	}
	if len(h.Principals[0].Roles) != 1 || h.Principals[0].Roles[0].ID != "r1" {
		t.Errorf("roles = %+v", h.Principals[0].Roles)
	}
}

func TestPatchHost_PrincipalsRoleResolutionFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
		return nil, errors.New("role store down")
	})
	h := &hoststore.Host{}
	err := PatchHost(h, map[string]any{
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		},
	}, &auth.AuthContext{Connector: conn})
	if err == nil {
		t.Fatal("expected error from role resolution")
	}
}

func TestPatchHost_NoPrincipalEditWhenAbsent(t *testing.T) {
	h := &hoststore.Host{Principals: []hoststore.HostPrincipals{{Principal: "keep"}}}
	err := PatchHost(h, map[string]any{"comment": "x"}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(h.Principals) != 1 || h.Principals[0].Principal != "keep" {
		t.Errorf("principals should be preserved, got %+v", h.Principals)
	}
}

func TestPatchHost_CreateRequiresPrincipalsPatchDoesNot(t *testing.T) {
	h := &hoststore.Host{CommonName: "web1", Addresses: []string{"10.0.0.1"}}
	err := PatchHost(h, map[string]any{"comment": "no principals"}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("patch without principals should succeed: %v", err)
	}
}

func TestPatchHost_WrongTypeStringRejected(t *testing.T) {
	h := &hoststore.Host{Comment: "keep"}
	err := PatchHost(h, map[string]any{"comment": 1}, &auth.AuthContext{})
	if err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("got %v", err)
	}
	if h.Comment != "keep" {
		t.Errorf("comment = %q, want preserved", h.Comment)
	}
}

func TestPatchHost_EmptyCommentClears(t *testing.T) {
	h := &hoststore.Host{Comment: "keep"}
	err := PatchHost(h, map[string]any{"comment": ""}, &auth.AuthContext{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h.Comment != "" {
		t.Errorf("comment = %q, want empty", h.Comment)
	}
}
