package users

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// immutableLocalUserUpdateFields are never accepted as update inputs.
// id is allowed only as the lookup key and is never written onto the user.
var immutableLocalUserUpdateFields = map[string]struct{}{
	"created":                  {},
	"updated":                  {},
	"updated_by":               {},
	"source":                   {},
	"stale_access_token":       {},
	"mfa":                      {},
	"password":                 {},
	"password_change_required": {},
	"author":                   {},
}

// PatchLocalUser overlays caller-supplied overrides onto the fetched local
// user. Only fields present in params are touched; everything else is
// preserved. Server-managed and sensitive fields (id, created, updated,
// updated_by, author, source, stale_access_token, mfa, password,
// password_change_required) are never applied from params.
func PatchLocalUser(current *userstore.LocalUser, params map[string]any) error {
	for key := range params {
		if _, forbidden := immutableLocalUserUpdateFields[key]; forbidden {
			return fmt.Errorf("validation error: field %q cannot be updated", key)
		}
	}

	// Snapshot server-managed identity fields so they cannot be altered even
	// if a future editable mapping mistakenly touches them.
	preservedID := current.ID
	preservedCreated := current.Created
	preservedUpdated := current.Updated
	preservedUpdatedBy := current.UpdatedBy
	preservedAuthor := current.Author
	preservedPassword := current.Password
	preservedPasswordChangeRequired := current.PasswordChangeRequired

	assign := func(key string, dst *string) error {
		s, ok, err := utils.OverlayString(params, key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok {
			*dst = s
		}

		return nil
	}

	for key := range params {
		var err error

		switch key {
		case "id":
			// Lookup key only; never written onto the user object.
			continue
		case "username":
			err = assign(key, &current.Principal)
		case "full_name":
			err = assign(key, &current.FullName)
		case "email":
			err = assign(key, &current.Email)
		case "comment":
			err = assign(key, &current.Comment)
		case "windows_account":
			err = assign(key, &current.WindowsAccount)
		case "unix_account":
			err = assign(key, &current.UnixAccount)
		case "display_name":
			err = assign(key, &current.DisplayName)
		case "first_name":
			err = assign(key, &current.FirstName)
		case "last_name":
			err = assign(key, &current.LastName)
		case "job_title":
			err = assign(key, &current.JobTitle)
		case "company":
			err = assign(key, &current.Company)
		case "department":
			err = assign(key, &current.Department)
		case "telephone":
			err = assign(key, &current.Telephone)
		case "locale":
			err = assign(key, &current.Locale)
		}

		if err != nil {
			return err
		}
	}

	if v, ok := params["tags"]; ok {
		tags, err := utils.ToStringSlice(v)
		if err != nil {
			return fmt.Errorf("validation error: tags: %w", err)
		}

		current.Tags = tags
	}

	current.ID = preservedID
	current.Created = preservedCreated
	current.Updated = preservedUpdated
	current.UpdatedBy = preservedUpdatedBy
	current.Author = preservedAuthor
	current.Password = preservedPassword
	current.PasswordChangeRequired = preservedPasswordChangeRequired

	return nil
}
