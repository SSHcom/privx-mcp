package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

const linuxAdminRoleID = "f4727910-32f5-54be-576b-44b8585c2a1e"

func baseCreateParams() map[string]any {
	return map[string]any{
		"grant_type": "PERMANENT",
		"requested_role": map[string]any{
			"id": linuxAdminRoleID,
		},
		"target_user": map[string]any{
			"id": "a1111111-1111-1111-1111-111111111111",
		},
		"request_justification": "test",
	}
}

func defaultRequestableRole() apiservice.RequestableRole {
	return apiservice.RequestableRole{
		ID:                        linuxAdminRoleID,
		Name:                      "Linux-Admin",
		Action:                    "BOTH",
		GrantTypes:                []string{"FLOATING", "PERMANENT", "TIME_RESTRICTED"},
		MaxFloatingDuration:       8,
		MaxTimeRestrictedDuration: 7,
	}
}

func handleRequestableRoles(conn *testconn.FakeConnector, roles ...apiservice.RequestableRole) {
	items := roles
	if len(items) == 0 {
		items = []apiservice.RequestableRole{defaultRequestableRole()}
	}
	conn.Handle("GET", "/workflow-engine/api/v1/workflows/roles", func(any) (any, error) {
		return response.ResultSet[apiservice.RequestableRole]{
			Count: len(items),
			Items: items,
		}, nil
	})
}

func TestCreateRequestHandler_HappyPermanent(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn)
	conn.Handle("POST", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var req workflow.AccessRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.Action != "GRANT" {
			t.Errorf("action = %q", req.Action)
		}
		if req.GrantType != "PERMANENT" {
			t.Errorf("grant_type = %q", req.GrantType)
		}
		if req.RequestJustification != "test" {
			t.Errorf("request_justification = %q", req.RequestJustification)
		}
		if req.Requester != nil {
			t.Errorf("requester must be omitted, got %+v", req.Requester)
		}
		if req.RequestedRole == nil || req.RequestedRole.ID != "f4727910-32f5-54be-576b-44b8585c2a1e" {
			t.Errorf("requested_role = %+v", req.RequestedRole)
		}
		if req.RequestedRole.Name != "Linux-Admin" {
			t.Errorf("requested_role.name = %q, want Linux-Admin from workflows/roles", req.RequestedRole.Name)
		}
		if req.TargetUser == nil || req.TargetUser.ID != "a1111111-1111-1111-1111-111111111111" {
			t.Errorf("target_user = %+v", req.TargetUser)
		}
		if req.TargetUser.DisplayName != "" {
			t.Errorf("target_user.display_name must be omitted, got %q", req.TargetUser.DisplayName)
		}
		if req.FloatingLength != 0 || req.GrantStart != "" || req.GrantEnd != "" {
			t.Errorf("unexpected time fields: floating=%d start=%q end=%q",
				req.FloatingLength, req.GrantStart, req.GrantEnd)
		}
		return response.Identifier{ID: "new-request-id"}, nil
	})

	res, err := createRequestHandler(testconn.CtxWithAuth(conn), baseCreateParams())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-request-id" {
		t.Errorf("id = %v, want new-request-id", m["id"])
	}
}

func TestCreateRequestHandler_HappyFloating(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn)
	conn.Handle("POST", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var req workflow.AccessRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.GrantType != "FLOATING" || req.FloatingLength != 3 {
			t.Errorf("grant_type=%q floating_length=%d", req.GrantType, req.FloatingLength)
		}
		return response.Identifier{ID: "float-id"}, nil
	})

	params := baseCreateParams()
	params["grant_type"] = "FLOATING"
	params["floating_length"] = 3
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_HappyRestricted(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn)
	conn.Handle("POST", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var req workflow.AccessRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req.GrantType != "TIME_RESTRICTED" {
			t.Errorf("grant_type = %q", req.GrantType)
		}
		if req.GrantStart != "2026-08-06T10:00:00Z" || req.GrantEnd != "2026-08-07T10:00:00Z" {
			t.Errorf("range = %q..%q", req.GrantStart, req.GrantEnd)
		}
		return response.Identifier{ID: "tr-id"}, nil
	})

	params := baseCreateParams()
	params["grant_type"] = "RESTRICTED"
	params["grant_start"] = "2026-08-06T10:00:00Z"
	params["grant_end"] = "2026-08-07T10:00:00Z"
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_MissingJustification(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	delete(params, "request_justification")
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "request_justification") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_MissingRoleID(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	params["requested_role"] = map[string]any{}
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "requested_role.id is required") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_MissingUserID(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	params["target_user"] = map[string]any{}
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "target_user.id is required") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_PermanentRejectsTimeFields(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	params["grant_start"] = "2026-08-06T10:00:00Z"
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "PERMANENT grants must not include") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_FloatingLengthRequired(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	params["grant_type"] = "FLOATING"
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "floating_length") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_FloatingLengthTooLarge(t *testing.T) {
	conn := testconn.New(t)
	role := defaultRequestableRole()
	role.MaxFloatingDuration = 2
	handleRequestableRoles(conn, role)
	params := baseCreateParams()
	params["grant_type"] = "FLOATING"
	params["floating_length"] = 3
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "at most 2 (hours)") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_RestrictedSpanTooLong(t *testing.T) {
	conn := testconn.New(t)
	role := defaultRequestableRole()
	role.MaxTimeRestrictedDuration = 2
	handleRequestableRoles(conn, role)
	params := baseCreateParams()
	params["grant_type"] = "RESTRICTED"
	params["grant_start"] = "2026-08-06T10:00:00Z"
	params["grant_end"] = "2026-08-09T10:00:00Z"
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "at most 2 days") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_RestrictedEndBeforeStart(t *testing.T) {
	conn := testconn.New(t)
	params := baseCreateParams()
	params["grant_type"] = "RESTRICTED"
	params["grant_start"] = "2026-08-07T10:00:00Z"
	params["grant_end"] = "2026-08-06T10:00:00Z"
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "grant_end must be after grant_start") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_CreateAPIError(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn)
	inner := errors.New("boom")
	conn.Handle("POST", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		return nil, inner
	})
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), baseCreateParams())
	if err == nil {
		t.Fatalf("expected operational error, got result %#v", res)
	}
	if !strings.Contains(err.Error(), "failed to create access request") {
		t.Errorf("got %v", err)
	}
	if !errors.Is(err, inner) {
		t.Errorf("expected wrapped cause, got %v", err)
	}
}

func TestCreateRequestHandler_ListRequestableRolesError(t *testing.T) {
	conn := testconn.New(t)
	inner := errors.New("workflow down")
	conn.Handle("GET", "/workflow-engine/api/v1/workflows/roles", func(any) (any, error) {
		return nil, inner
	})
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), baseCreateParams())
	if err == nil {
		t.Fatalf("expected operational error, got result %#v", res)
	}
	if !strings.Contains(err.Error(), "failed to list requestable roles") {
		t.Errorf("got %v", err)
	}
	if !errors.Is(err, inner) {
		t.Errorf("expected wrapped cause, got %v", err)
	}
}

func TestFindRequestableRole_WrapsListError(t *testing.T) {
	conn := testconn.New(t)
	inner := errors.New("workflow down")
	conn.Handle("GET", "/workflow-engine/api/v1/workflows/roles", func(any) (any, error) {
		return nil, inner
	})
	role, err := findRequestableRole(conn, linuxAdminRoleID)
	if role != nil {
		t.Fatalf("expected nil role, got %#v", role)
	}
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, inner) {
		t.Errorf("expected wrapped cause, got %v", err)
	}
}

func TestCreateRequestHandler_RoleNotRequestable(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn, apiservice.RequestableRole{
		ID:         "other-role",
		Name:       "other",
		GrantTypes: []string{"PERMANENT"},
	})
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), baseCreateParams())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "is not requestable via workflow") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRequestHandler_GrantTypeNotAllowed(t *testing.T) {
	conn := testconn.New(t)
	handleRequestableRoles(conn, apiservice.RequestableRole{
		ID:         linuxAdminRoleID,
		Name:       "DummyRole",
		GrantTypes: []string{"PERMANENT"},
	})
	params := baseCreateParams()
	params["grant_type"] = "FLOATING"
	params["floating_length"] = 1
	res, err := createRequestHandler(testconn.CtxWithAuth(conn), params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "grant_type FLOATING is not allowed") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreate_RequestedRolePointsAtAvailableRoles(t *testing.T) {
	raw, err := json.Marshal(Create().InputSchema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	if !strings.Contains(string(raw), "available-roles") {
		t.Errorf("requested_role should point at mcp-info available-roles, got %s", raw)
	}
}
