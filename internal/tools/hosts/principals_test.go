package hosts

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestResolvePrincipals(t *testing.T) {
	t.Run("resolves roles", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
			return response.ResultSet[testconn.RolestoreRole]{
				Items: []testconn.RolestoreRole{{ID: "r1", Name: "admin"}},
			}, nil
		})

		principals, err := ResolvePrincipals([]any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		}, conn)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(principals) != 1 || principals[0].Principal != "root" {
			t.Fatalf("principals = %+v", principals)
		}
		if len(principals[0].Roles) != 1 || principals[0].Roles[0].ID != "r1" {
			t.Fatalf("roles = %+v", principals[0].Roles)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		_, err := ResolvePrincipals([]any{
			map[string]any{"principal": "", "roles": []any{}},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "principals[0]") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("role lookup failure", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
			return nil, errors.New("role store down")
		})

		_, err := ResolvePrincipals([]any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		}, conn)
		if err == nil || !strings.Contains(err.Error(), "failed to resolve roles") {
			t.Fatalf("got %v", err)
		}
	})
}
