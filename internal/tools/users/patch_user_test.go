package users

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
)

func TestPatchLocalUser_StringScalars(t *testing.T) {
	u := &userstore.LocalUser{
		Principal:              "old-user",
		FullName:               "Old Name",
		Email:                  "old@example.com",
		Password:               userstore.LocalUserPassword{Password: "secret"},
		PasswordChangeRequired: false,
	}
	err := PatchLocalUser(u, map[string]any{
		"username":        "new-user",
		"full_name":       "New Name",
		"email":           "new@example.com",
		"comment":         "note",
		"windows_account": "DOMAIN\\new",
		"unix_account":    "newunix",
		"display_name":    "Display",
		"first_name":      "First",
		"last_name":       "Last",
		"job_title":       "Engineer",
		"company":         "Acme",
		"department":      "Eng",
		"telephone":       "123",
		"locale":          "en_US",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if u.Principal != "new-user" {
		t.Errorf("username = %q", u.Principal)
	}
	if u.FullName != "New Name" {
		t.Errorf("full_name = %q", u.FullName)
	}
	if u.Email != "new@example.com" {
		t.Errorf("email = %q", u.Email)
	}
	if u.Comment != "note" {
		t.Errorf("comment = %q", u.Comment)
	}
	if u.WindowsAccount != "DOMAIN\\new" {
		t.Errorf("windows_account = %q", u.WindowsAccount)
	}
	if u.UnixAccount != "newunix" {
		t.Errorf("unix_account = %q", u.UnixAccount)
	}
	if u.DisplayName != "Display" {
		t.Errorf("display_name = %q", u.DisplayName)
	}
	if u.FirstName != "First" {
		t.Errorf("first_name = %q", u.FirstName)
	}
	if u.LastName != "Last" {
		t.Errorf("last_name = %q", u.LastName)
	}
	if u.JobTitle != "Engineer" {
		t.Errorf("job_title = %q", u.JobTitle)
	}
	if u.Company != "Acme" {
		t.Errorf("company = %q", u.Company)
	}
	if u.Department != "Eng" {
		t.Errorf("department = %q", u.Department)
	}
	if u.Telephone != "123" {
		t.Errorf("telephone = %q", u.Telephone)
	}
	if u.Locale != "en_US" {
		t.Errorf("locale = %q", u.Locale)
	}
	if u.Password.Password != "secret" {
		t.Errorf("password changed to %q, want preserved", u.Password.Password)
	}
	if u.PasswordChangeRequired {
		t.Error("password_change_required changed, want preserved false")
	}
}

func TestPatchLocalUser_PreservesUnmentionedFields(t *testing.T) {
	u := &userstore.LocalUser{
		Principal: "alice",
		FullName:  "Alice Example",
		Email:     "alice@example.com",
		Comment:   "keep me",
		Company:   "Acme",
	}
	err := PatchLocalUser(u, map[string]any{
		"id":        "u1",
		"full_name": "Alice Updated",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if u.FullName != "Alice Updated" {
		t.Errorf("full_name = %q", u.FullName)
	}
	if u.Principal != "alice" {
		t.Errorf("username = %q, want preserved", u.Principal)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q, want preserved", u.Email)
	}
	if u.Comment != "keep me" {
		t.Errorf("comment = %q, want preserved", u.Comment)
	}
	if u.Company != "Acme" {
		t.Errorf("company = %q, want preserved", u.Company)
	}
}

func TestPatchLocalUser_Tags(t *testing.T) {
	u := &userstore.LocalUser{Tags: []string{"old"}}
	err := PatchLocalUser(u, map[string]any{
		"tags": []any{"a", "b"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(u.Tags) != 2 || u.Tags[0] != "a" || u.Tags[1] != "b" {
		t.Errorf("tags = %v", u.Tags)
	}
}

func TestPatchLocalUser_BadTags(t *testing.T) {
	u := &userstore.LocalUser{}
	err := PatchLocalUser(u, map[string]any{
		"tags": "not-an-array",
	})
	if err == nil || !strings.Contains(err.Error(), "tags") {
		t.Fatalf("got %v", err)
	}
}

func TestPatchLocalUser_RejectsImmutableFields(t *testing.T) {
	u := &userstore.LocalUser{
		ID:                     "u1",
		Created:                "created-1",
		Updated:                "updated-1",
		UpdatedBy:              "admin",
		Author:                 "author-1",
		Password:               userstore.LocalUserPassword{Password: "secret"},
		PasswordChangeRequired: false,
	}
	for _, key := range []string{
		"created", "updated", "updated_by", "source", "stale_access_token", "mfa",
		"password", "password_change_required", "author",
	} {
		err := PatchLocalUser(u, map[string]any{key: "attacker"})
		if err == nil || !strings.Contains(err.Error(), `field "`+key+`" cannot be updated`) {
			t.Errorf("key %q: got %v", key, err)
		}
	}
	if u.ID != "u1" || u.Created != "created-1" || u.Updated != "updated-1" || u.UpdatedBy != "admin" {
		t.Errorf("server-managed fields mutated: %+v", u)
	}
	if u.Password.Password != "secret" || u.PasswordChangeRequired {
		t.Errorf("password fields mutated: %+v", u.Password)
	}
}

func TestPatchLocalUser_IDIsLookupOnly(t *testing.T) {
	u := &userstore.LocalUser{
		ID:       "u1",
		FullName: "Alice",
	}
	err := PatchLocalUser(u, map[string]any{
		"id":        "attacker-id",
		"full_name": "Alice Updated",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if u.ID != "u1" {
		t.Errorf("id = %q, want preserved u1", u.ID)
	}
	if u.FullName != "Alice Updated" {
		t.Errorf("full_name = %q", u.FullName)
	}
}

func TestPatchLocalUser_EmptyCommentClears(t *testing.T) {
	u := &userstore.LocalUser{Comment: "keep me"}
	err := PatchLocalUser(u, map[string]any{"comment": ""})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if u.Comment != "" {
		t.Errorf("comment = %q, want empty", u.Comment)
	}
}

func TestPatchLocalUser_WrongTypeStringRejected(t *testing.T) {
	u := &userstore.LocalUser{Comment: "keep me"}
	err := PatchLocalUser(u, map[string]any{"comment": 1})
	if err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("got %v", err)
	}
	if u.Comment != "keep me" {
		t.Errorf("comment = %q, want preserved", u.Comment)
	}
}
