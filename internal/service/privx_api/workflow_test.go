package api_test

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestListRequestableRoles(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/workflows/roles", func(any) (any, error) {
		return response.ResultSet[apiservice.RequestableRole]{
			Count: 2,
			Items: []apiservice.RequestableRole{
				{
					ID:                        "role-a",
					Name:                      "windows-admins",
					Action:                    "BOTH",
					GrantTypes:                []string{"FLOATING", "PERMANENT", "TIME_RESTRICTED"},
					MaxFloatingDuration:       8,
					MaxTimeRestrictedDuration: 7,
				},
				{
					ID:         "role-b",
					Name:       "DummyRole",
					Action:     "BOTH",
					GrantTypes: []string{"PERMANENT"},
				},
			},
		}, nil
	})

	page, err := apiservice.NewWorkflowService(conn).ListRequestableRoles()
	if err != nil {
		t.Fatalf("ListRequestableRoles: %v", err)
	}
	if page.Count != 2 || len(page.Items) != 2 {
		t.Fatalf("got count=%d items=%d", page.Count, len(page.Items))
	}
	if page.Items[0].Name != "windows-admins" || page.Items[1].MaxFloatingDuration != 0 {
		t.Fatalf("unexpected items: %#v", page.Items)
	}
}

func TestListAllRequestableRolesPages(t *testing.T) {
	conn := testconn.New(t)
	calls := 0
	conn.Handle("GET", "/workflow-engine/api/v1/workflows/roles", func(any) (any, error) {
		calls++
		if calls == 1 {
			return response.ResultSet[apiservice.RequestableRole]{
				Count: 2,
				Items: []apiservice.RequestableRole{{ID: "role-a", Name: "a"}},
			}, nil
		}
		return response.ResultSet[apiservice.RequestableRole]{
			Count: 2,
			Items: []apiservice.RequestableRole{{ID: "role-b", Name: "b"}},
		}, nil
	})

	roles, err := apiservice.NewWorkflowService(conn).ListAllRequestableRoles()
	if err != nil {
		t.Fatalf("ListAllRequestableRoles: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 page fetches, got %d", calls)
	}
	if len(roles) != 2 || roles[0].ID != "role-a" || roles[1].ID != "role-b" {
		t.Fatalf("unexpected roles: %#v", roles)
	}
}

func TestListAllRequestableRolesUninitialized(t *testing.T) {
	_, err := apiservice.NewWorkflowService(nil).ListAllRequestableRoles()
	if err == nil {
		t.Fatal("expected error")
	}
}
