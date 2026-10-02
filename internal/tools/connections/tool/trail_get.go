package tool

import (
	"context"
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/connections"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// TrailGet returns the connection-trail-get tool definition.
//
// It returns the actual commands executed within an SSH connection's recorded
// session trail by downloading and parsing the per-channel trail logs (the same
// approach as the PrivX Python SDK example). This does not depend on trail
// indexing, so it works whenever an audited trail exists, regardless of a
// connection's index_status. Prerequisites: the connection type must be SSH and
// session recording (audit) must be enabled. Connection status is not
// restricted, but the trail is only readable once the session has ended.
func TrailGet() registry.Tool {
	description := "Get the recorded session trail for an SSH connection: the actual commands " +
		"executed in the connection, reconstructed from the downloaded session trail logs. " +
		"Prerequisites: the connection type must be SSH and session recording (audit) must be enabled. " +
		"The trail is only readable after the session has disconnected. " +
		"Use connection-list or connection-search first to find a connection id. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the connection whose trail to fetch.",
		}).
		Set("channel_id", map[string]any{
			"type":        "string",
			"description": "Restrict the trail to a single connection channel. Defaults to all channels.",
		}).
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Case-insensitive substring filter applied to reconstructed commands.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of trail commands to return. Defaults to %d.", common.ConnectionTrailListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first trail command to include in the page.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"description": "Include connection trail metadata (trail_id, session_id, index_status) alongside commands.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "connection-trail-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     trailGetHandler,
	}
}

func trailGetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	connID := utils.StringFromMap(params, "id")
	if connID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	paging, errResult := common.ParsePaging(params, common.ConnectionTrailListLimit)
	if errResult != nil {
		return errResult, nil
	}

	channelID := utils.StringFromMap(params, "channel_id")
	keywords := utils.StringFromMap(params, "keywords")
	raw := utils.BoolFromMap(params, "raw")

	// Fetch the connection to validate prerequisites and surface metadata.
	conn, err := connectionmanager.New(authCtx.Connector).GetConnection(connID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch connection: %v", err)), nil
	}

	if conn.Type != "SSH" {
		return registry.ErrorResult(fmt.Sprintf(
			"connection %s is of type %q; trail retrieval requires an SSH connection", connID, conn.Type)), nil
	}

	if !conn.AuditEnabled {
		return registry.ErrorResult(fmt.Sprintf(
			"session recording (audit) is not enabled for connection %s; no trail is available", connID)), nil
	}

	if conn.TrailRemoved {
		return registry.ErrorResult(fmt.Sprintf(
			"the trail for connection %s has been removed", connID)), nil
	}

	// Discover channels from the raw connection JSON (the typed SDK struct drops
	// the trail field), then download and parse each channel's trail log.
	channels, err := connections.DiscoverTrailChannels(authCtx.Connector, connID, channelID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to resolve connection trail channels: %v", err)), nil
	}

	if len(channels) == 0 {
		return registry.ErrorResult(fmt.Sprintf(
			"no trail channels available for connection %s; the trail may not be ready yet "+
				"(a session must disconnect before its trail can be read)", connID)), nil
	}

	commands, err := connections.CollectTrailCommands(authCtx.Connector, connID, channels)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to read connection trail: %v", err)), nil
	}

	commands = filterTrailCommands(commands, keywords)

	// Page over the reconstructed command list in memory.
	total := len(commands)
	page := pageTrailCommands(commands, paging.Offset, paging.Limit)

	opts := []common.PageOption{
		common.WithReturned(len(page)),
		common.WithNextOffset(),
	}
	if raw {
		opts = append(opts, common.WithExtra("connection", connections.FormatConnectionTrailMeta(conn)))
	}

	return common.JSONPage(
		paging,
		connections.FormatTrailCommandItems(page),
		total,
		len(page),
		opts...,
	), nil
}

func filterTrailCommands(cmds []connections.TrailCommand, keywords string) []connections.TrailCommand {
	if keywords == "" {
		return cmds
	}

	needle := strings.ToLower(keywords)

	filtered := make([]connections.TrailCommand, 0, len(cmds))
	for _, c := range cmds {
		if strings.Contains(strings.ToLower(c.Command), needle) {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

func pageTrailCommands(cmds []connections.TrailCommand, offset, limit int) []connections.TrailCommand {
	if offset >= len(cmds) {
		return nil
	}

	end := offset + limit
	if end > len(cmds) {
		end = len(cmds)
	}

	return cmds[offset:end]
}
