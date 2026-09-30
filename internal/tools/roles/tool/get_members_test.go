package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestGetRoleMembersHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{
			Count: 1,
			Items: []rolestore.User{{
				ID:        "u1",
				Principal: "alice",
				Password:  "secret",
				MFA:       rolestore.MFAStatus{TotpMFASeed: rolestore.MFASeed{Seed_string: "SEED"}},
				Attributes: []rolestore.UserAttribute{
					{Key: "windows_sid", Value: "S-1-5"},
					{Key: "department", Value: "ops"},
				},
			}},
		}, nil
	})

	res, err := getRoleMembersHandler(testconn.CtxWithAuth(conn), map[string]any{"role_id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	if m["limit"].(float64) != float64(common.RolesListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	member := items[0].(map[string]any)
	if _, ok := member["password"]; ok {
		t.Error("password should be redacted")
	}
	mfa, ok := member["mfa"].(map[string]any)
	if !ok {
		t.Fatalf("mfa = %v", member["mfa"])
	}
	if _, ok := mfa["seed"]; ok {
		t.Error("mfa.seed should be redacted")
	}
	attrs := member["attributes"].([]any)
	if len(attrs) != 1 || attrs[0].(map[string]any)["key"] != "department" {
		t.Errorf("attributes = %v", attrs)
	}
}

func TestGetRoleMembersHandler_MissingRoleID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getRoleMembersHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: role_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetRoleMembersHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return nil, errors.New("backend down")
	})
	res, err := getRoleMembersHandler(testconn.CtxWithAuth(conn), map[string]any{"role_id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch role members") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
