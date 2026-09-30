package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestListHostsHandler(t *testing.T) {
	t.Run("no_auth", func(t *testing.T) {
		res, err := listHostsHandler(testconn.CtxNoAuth(), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error result")
		}
		if !strings.Contains(res.Content[0].Text, "authentication error") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})

	t.Run("happy", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("GET", "/host-store/api/v1/hosts", func(body any) (any, error) {
			return response.ResultSet[hoststore.Host]{
				Count: 3,
				Items: []hoststore.Host{
					{ID: "h1", CommonName: "web1", Addresses: []string{"10.0.0.1"}},
					{ID: "h2", CommonName: "web2", Addresses: []string{"10.0.0.2"}},
					{ID: "h3", CommonName: "web3", Addresses: []string{"10.0.0.3"}},
				},
			}, nil
		})

		res, err := listHostsHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", res.Content[0].Text)
		}
		m := testconn.DecodeResult(t, res.Content[0].Text)
		if m["count"].(float64) != 3 {
			t.Errorf("count = %v", m["count"])
		}
		if m["limit"].(float64) != float64(common.HostsListLimit) {
			t.Errorf("limit = %v", m["limit"])
		}
		if m["offset"].(float64) != 0 {
			t.Errorf("offset = %v", m["offset"])
		}
		if m["returned"].(float64) != 3 {
			t.Errorf("returned = %v", m["returned"])
		}
		if m["remaining"].(float64) != 0 {
			t.Errorf("remaining = %v", m["remaining"])
		}
		if m["pagesRemaining"].(float64) != 0 {
			t.Errorf("pagesRemaining = %v", m["pagesRemaining"])
		}
		if _, ok := m["nextOffset"]; ok {
			t.Error("list envelope must omit nextOffset")
		}
		items, ok := m["items"].([]any)
		if !ok || len(items) != 3 {
			t.Fatalf("items = %v", m["items"])
		}
		first, ok := items[0].(map[string]any)
		if !ok {
			t.Fatalf("first item not a map: %T", items[0])
		}
		if first["id"] != "h1" {
			t.Errorf("first id = %v", first["id"])
		}
		if first["common_name"] != "web1" {
			t.Errorf("first common_name = %v", first["common_name"])
		}
	})

	t.Run("fetch_error", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("GET", "/host-store/api/v1/hosts", func(body any) (any, error) {
			return nil, errors.New("backend down")
		})
		res, err := listHostsHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error result")
		}
		if !strings.Contains(res.Content[0].Text, "failed to fetch hosts") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})
}

func TestListHostsHandler_RawBypassesProjection(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts", func(body any) (any, error) {
		return response.ResultSet[hoststore.Host]{
			Count: 1,
			Items: []hoststore.Host{{ID: "h1", CommonName: "web1", Organization: "acme"}},
		}, nil
	})

	res, err := listHostsHandler(testconn.CtxWithAuth(conn), map[string]any{"raw": true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("first item not a map: %T", items[0])
	}
	if first["organization"] != "acme" {
		t.Errorf("raw should include organization, got %v", first["organization"])
	}
}

func TestListHostsHandler_ExtraFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts", func(body any) (any, error) {
		return response.ResultSet[hoststore.Host]{
			Count: 1,
			Items: []hoststore.Host{{ID: "h1", CommonName: "web1", Organization: "acme"}},
		}, nil
	})

	res, err := listHostsHandler(testconn.CtxWithAuth(conn), map[string]any{"fields": "organization"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, _ := m["items"].([]any)
	first, _ := items[0].(map[string]any)
	if first["organization"] != "acme" {
		t.Errorf("organization = %v, want acme", first["organization"])
	}
}
