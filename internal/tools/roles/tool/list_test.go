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

func TestListRolesHandler(t *testing.T) {
	t.Run("no_auth", func(t *testing.T) {
		res, err := listRolesHandler(testconn.CtxNoAuth(), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError || !strings.Contains(res.Content[0].Text, "authentication error") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})

	t.Run("happy", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("GET", "/role-store/api/v1/roles", func(body any) (any, error) {
			return response.ResultSet[rolestore.Role]{
				Count: 2,
				Items: []rolestore.Role{
					{
						ID:                  "r1",
						Name:                "admin",
						PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
						Context:             rolestore.ContextualLimit{IPMasks: []string{"10.0.0.0/8"}, Enabled: true},
					},
					{ID: "r2", Name: "user"},
				},
			}, nil
		})

		res, err := listRolesHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
		if m["limit"].(float64) != float64(common.RolesListLimit) {
			t.Errorf("limit = %v", m["limit"])
		}
		if m["returned"].(float64) != 2 {
			t.Errorf("returned = %v", m["returned"])
		}
		items, ok := m["items"].([]any)
		if !ok || len(items) != 2 {
			t.Fatalf("items = %v", m["items"])
		}
		first := items[0].(map[string]any)
		if _, ok := first["principal_public_key_strings"]; ok {
			t.Error("principal_public_key_strings should be redacted")
		}
		context := first["context"].(map[string]any)
		if _, ok := context["ip_masks"]; ok {
			t.Error("context.ip_masks should be redacted")
		}
		if context["enabled"] != true {
			t.Errorf("enabled = %v", context["enabled"])
		}
	})

	t.Run("fetch_error", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("GET", "/role-store/api/v1/roles", func(body any) (any, error) {
			return nil, errors.New("backend down")
		})
		res, err := listRolesHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch roles") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})
}
