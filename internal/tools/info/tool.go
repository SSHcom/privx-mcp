package info

import (
	"fmt"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

const toolName = "mcp-info"

// Info returns the mcp-info tool definition.
func Info(snapshot InstanceSnapshot) registry.Tool {
	ctxKeys := contextEnumKeys()
	resKeys := resourceKeys()

	properties := registry.NewOrderedMap().
		Set("context", map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "string",
				"enum": ctxKeys,
			},
			"description": fmt.Sprintf(
				"PrivX concept topics. Most keys return markdown strings. "+
					"%q is a live JSON list of roles the caller can request (excludes roles they already hold). "+
					"Use %q for every topic. When investigating a topic, also request related resources for example shapes. Allowed: %s.",
				contextKeyAvailableRoles, contextKeyAll, strings.Join(ctxKeys, ", "),
			),
		}).
		Set("resources", map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "string",
				"enum": resKeys,
			},
			"description": fmt.Sprintf(
				"Example resource record shapes to include as JSON objects. "+
					"When inspecting a resource, also request related context topics for concept background. Allowed: %s.",
				strings.Join(resKeys, ", "),
			),
		})

	return registry.Tool{
		Name: toolName,
		Description: "Return MCP/PrivX information for the current session. " +
			"This always includes authenticated caller info and PrivX instance config. " +
			"Optionally request context (markdown concept topics, plus live available-roles for access requests) " +
			"and resources (example resource JSON objects). " +
			"Pair related context and resources when looking up a topic (or the reverse).",
		Writes: false,
		// Payload and parameter keys are server-owned documentation; several of
		// them ("access-groups", "delete" in audit event codes) would otherwise
		// trip the security blacklist. The handler checks the PrivX-sourced
		// strings it embeds itself.
		Trusted: true,
		InputSchema: registry.NewOrderedMap().
			Set("type", "object").
			Set("properties", properties),
		Handler: infoHandler(snapshot),
	}
}
