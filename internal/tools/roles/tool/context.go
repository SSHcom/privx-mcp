package tool

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// parseRoleContext converts a map[string]any (from tool params) into a
// rolestore.ContextualLimit struct.
func parseRoleContext(m map[string]any) rolestore.ContextualLimit {
	ctx := rolestore.ContextualLimit{}

	if v, ok := m["enabled"].(bool); ok {
		ctx.Enabled = v
	}

	if v, ok := m["block_role"].(bool); ok {
		ctx.BlockRole = v
	}

	if v := utils.StringFromMap(m, "start_time"); v != "" {
		ctx.StartTime = v
	}

	if v := utils.StringFromMap(m, "end_time"); v != "" {
		ctx.EndTime = v
	}

	if v := utils.StringFromMap(m, "timezone"); v != "" {
		ctx.TimeZone = v
	}

	if raw, ok := m["validity"]; ok {
		if vals, err := utils.ToStringSlice(raw); err == nil {
			ctx.Validity = vals
		}
	}

	if raw, ok := m["ip_masks"]; ok {
		if vals, err := utils.ToStringSlice(raw); err == nil {
			ctx.IPMasks = vals
		}
	}

	return ctx
}
