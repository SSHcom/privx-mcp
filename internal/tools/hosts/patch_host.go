package hosts

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
)

// PatchHost overlays caller-supplied overrides onto the fetched host.
// Only fields present in params are touched; everything else is preserved.
// Sensitive and server-managed fields are never read from params.
func PatchHost(current *hoststore.Host, params map[string]any, authCtx *auth.AuthContext) error {
	if err := applyPatchHostStringScalars(current, params); err != nil {
		return err
	}

	if err := applyPatchHostStringArrays(current, params); err != nil {
		return err
	}

	if err := applyPatchHostBools(current, params); err != nil {
		return err
	}

	if err := applyPatchHostSessionRecording(current, params); err != nil {
		return err
	}

	if err := applyPatchHostServices(current, params); err != nil {
		return err
	}

	return applyPatchHostPrincipals(current, params, authCtx)
}

func applyPatchHostPrincipals(current *hoststore.Host, params map[string]any, authCtx *auth.AuthContext) error {
	v, ok := params["principals"]
	if !ok {
		return nil
	}

	principalsRaw, ok := v.([]any)
	if !ok {
		return fmt.Errorf("validation error: principals must be an array")
	}

	principals, err := ResolvePrincipals(principalsRaw, authCtx.Connector)
	if err != nil {
		return err
	}

	current.Principals = principals

	return nil
}
