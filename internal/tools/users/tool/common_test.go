package tool

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
)

func TestBuildUserSearch(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s, sourceType, err := buildUserSearch(nil)
		if err != nil || s == nil {
			t.Fatalf("got %v, err %v", s, err)
		}
		if sourceType != "" {
			t.Errorf("source_type = %q, want empty", sourceType)
		}
	})
	t.Run("not object", func(t *testing.T) {
		_, _, err := buildUserSearch([]any{"x"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("fields accepted", func(t *testing.T) {
		s, sourceType, err := buildUserSearch(map[string]any{
			"keywords":    "alice",
			"source":      "src-1",
			"source_type": "AD",
			"user_id":     []any{"u1", "u2"},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if s.Keywords != "alice" {
			t.Errorf("keywords = %q", s.Keywords)
		}
		if s.Source != "src-1" {
			t.Errorf("source = %q", s.Source)
		}
		if len(s.UserIDs) != 2 || s.UserIDs[0] != "u1" {
			t.Errorf("user_id = %v", s.UserIDs)
		}
		if sourceType != "AD" {
			t.Errorf("source_type = %q, want AD", sourceType)
		}
	})
	t.Run("unknown fields dropped", func(t *testing.T) {
		s, sourceType, err := buildUserSearch(map[string]any{"not_a_field": "x", "keywords": "bob"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if s.Keywords != "bob" {
			t.Errorf("keywords = %q", s.Keywords)
		}
		if sourceType != "" {
			t.Errorf("source_type = %q, want empty", sourceType)
		}
	})
}

func TestFilterUsersBySourceType(t *testing.T) {
	users := []rolestore.User{
		{ID: "1", SourceType: "LOCAL"},
		{ID: "2", SourceType: "AD"},
		{ID: "3", SourceType: "ad"},
		{ID: "4", SourceType: "MICROSOFTGRAPH"},
	}

	t.Run("empty filter returns all", func(t *testing.T) {
		got := filterUsersBySourceType(users, "")
		if len(got) != len(users) {
			t.Fatalf("len = %d, want %d", len(got), len(users))
		}
	})

	t.Run("case insensitive match", func(t *testing.T) {
		got := filterUsersBySourceType(users, "Ad")
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].ID != "2" || got[1].ID != "3" {
			t.Errorf("ids = [%s %s], want [2 3]", got[0].ID, got[1].ID)
		}
	})
}
