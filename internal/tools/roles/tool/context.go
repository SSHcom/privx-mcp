package tool

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func roleContextProperty(description string) map[string]any {
	return map[string]any{
		"type":        "object",
		"description": description,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Whether contextual restrictions are active.",
			},
			"block_role": map[string]any{
				"type":        "boolean",
				"description": "Block role entirely when restrictions are not met.",
			},
			"validity": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Active weekdays (e.g. [\"MON\",\"TUE\",\"WED\",\"THU\",\"FRI\"]).",
			},
			"start_time": map[string]any{
				"type":        "string",
				"description": "Daily start time (e.g. \"09:00\").",
			},
			"end_time": map[string]any{
				"type":        "string",
				"description": "Daily end time (e.g. \"17:00\").",
			},
			"timezone": map[string]any{
				"type":        "string",
				"description": "Timezone (e.g. \"UTC\", \"Europe/Helsinki\").",
			},
			"ip_masks": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Allowed source IP ranges in CIDR notation (e.g. [\"172.0.0.1/24\"]).",
			},
		},
	}
}

// mergeRoleContext overlays a caller-supplied context object onto dst.
// Keys the caller leaves out stay as they are. A value of the wrong type
// is an error, so a bad field cannot clear an existing restriction.
func mergeRoleContext(dst *rolestore.ContextualLimit, raw any) error {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return fmt.Errorf("context must be an object")
	}

	return applyRoleContext(dst, m)
}

func applyRoleContext(dst *rolestore.ContextualLimit, m map[string]any) error {
	if err := overlayContextBool(m, "enabled", &dst.Enabled); err != nil {
		return err
	}

	if err := overlayContextBool(m, "block_role", &dst.BlockRole); err != nil {
		return err
	}

	if err := overlayContextString(m, "start_time", &dst.StartTime); err != nil {
		return err
	}

	if err := overlayContextString(m, "end_time", &dst.EndTime); err != nil {
		return err
	}

	if err := overlayContextString(m, "timezone", &dst.TimeZone); err != nil {
		return err
	}

	if err := overlayContextStrings(m, "validity", &dst.Validity); err != nil {
		return err
	}

	return overlayContextStrings(m, "ip_masks", &dst.IPMasks)
}

func overlayContextBool(m map[string]any, key string, dst *bool) error {
	value, ok, err := utils.OverlayBool(m, key)
	if err != nil {
		return fmt.Errorf("context.%w", err)
	}

	if ok {
		*dst = value
	}

	return nil
}

func overlayContextString(m map[string]any, key string, dst *string) error {
	value, ok, err := utils.OverlayString(m, key)
	if err != nil {
		return fmt.Errorf("context.%w", err)
	}

	if ok {
		*dst = value
	}

	return nil
}

func overlayContextStrings(m map[string]any, key string, dst *[]string) error {
	raw, ok := m[key]
	if !ok {
		return nil
	}

	vals, err := utils.ToStringSlice(raw)
	if err != nil {
		return fmt.Errorf("context.%s: %w", key, err)
	}

	*dst = vals

	return nil
}
