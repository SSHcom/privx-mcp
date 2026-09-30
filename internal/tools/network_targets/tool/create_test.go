package tool

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateNetworkTargetHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/network-access-manager/api/v1/nwtargets", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var nt networkaccessmanager.NetworkTarget
		if err := json.Unmarshal(raw, &nt); err != nil {
			t.Fatalf("unmarshal network target: %v", err)
		}
		if nt.Name != "my-target" {
			t.Errorf("name = %q", nt.Name)
		}
		return response.Identifier{ID: "new-nt"}, nil
	})

	res, err := createNetworkTargetHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name": "my-target",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-nt" {
		t.Errorf("id = %v, want new-nt", m["id"])
	}
}
