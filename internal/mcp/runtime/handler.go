package runtime

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/service/security"
)

func (c *Core) createToolHandler(tool registry.Tool) mcp.ToolHandler {
	safeHandler := RecoverMiddleware(tool.Handler)

	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		params, err := argumentsMap(request)
		if err != nil {
			return errorCallResult("invalid tool arguments: expected a JSON object"), nil
		}

		if !tool.Trusted {
			security.Prepare(params)
		}

		if isCreateOrUpdate(tool.Name) && security.ContainsRedacted(params) {
			return errorCallResult(`invalid tool arguments: "[redacted]" is not allowed in a value`), nil
		}

		logging.Debug("tool call input params", "tool", tool.Name, "params", params)

		ctx = security.ContextWithFilter(ctx, c.responseFilter)

		result, err := safeHandler(ctx, params)
		if err != nil {
			errResult := ToMCPError(err)
			return toCallToolResult(errResult, tool, c.responseFilter), nil
		}

		return toCallToolResult(result, tool, c.responseFilter), nil
	}
}

func argumentsMap(request *mcp.CallToolRequest) (map[string]any, error) {
	params := map[string]any{}
	if request == nil || request.Params == nil || len(request.Params.Arguments) == 0 {
		return params, nil
	}

	if err := json.Unmarshal(request.Params.Arguments, &params); err != nil {
		return nil, err
	}

	return params, nil
}

func convertTool(t registry.Tool) *mcp.Tool {
	title := toolTitle(t.Name)
	writes := t.Writes
	readOnly := !writes

	return &mcp.Tool{
		Name:        t.Name,
		Title:       title,
		Description: t.Description,
		InputSchema: toolInputSchema(t.InputSchema),
		Annotations: &mcp.ToolAnnotations{
			Title:           title,
			ReadOnlyHint:    readOnly,
			DestructiveHint: &writes,
		},
	}
}

func toolInputSchema(schema any) json.RawMessage {
	emptyObject := json.RawMessage(`{"type":"object"}`)
	if schema == nil {
		return emptyObject
	}

	encoded, err := json.Marshal(schema)
	if err != nil {
		return emptyObject
	}

	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return emptyObject
	}

	if object["type"] != "object" {
		object["type"] = "object"

		rewritten, err := json.Marshal(object)
		if err != nil {
			return emptyObject
		}

		return rewritten
	}

	return encoded
}

func toolTitle(name string) string {
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}

		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}

	return strings.Join(parts, " ")
}

// toCallToolResult converts a tool result to the MCP wire form. Unless the tool
// is trusted (registry.Tool.Trusted), successful payloads are sanitized,
// word-filtered, and wrapped in the security envelope. Sensitive tools and
// tools named whitelist-* are sanitized and wrapped, but not word-filtered.
// Error results are always delivered as plain text.
func toCallToolResult(result *registry.ToolResult, tool registry.Tool, filter security.Filter) *mcp.CallToolResult {
	if result == nil {
		return textCallResult("")
	}

	if result.IsError {
		msg := ""
		if len(result.Content) > 0 {
			msg = result.Content[0].Text
		}

		return errorCallResult(msg)
	}

	if len(result.Content) == 0 {
		return textCallResult("")
	}

	texts := make([]string, 0, len(result.Content))
	for _, block := range result.Content {
		text := block.Text
		if !tool.Trusted {
			secured, rejection := secureText(text, tool, filter)
			if rejection != "" {
				return errorCallResult(rejection)
			}

			text = secured
		}

		texts = append(texts, text)
	}

	contents := make([]mcp.Content, 0, len(texts))
	for _, text := range texts {
		contents = append(contents, &mcp.TextContent{Text: text})
	}

	return &mcp.CallToolResult{Content: contents}
}

func textCallResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func errorCallResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
	}
}

// secureText sanitizes a successful tool payload and wraps it in the security
// envelope. Whole words from filter are replaced unless the tool is sensitive
// or named whitelist-*. A payload that is not valid JSON becomes the
// envelope's data string. A non-empty rejection means the envelope could not
// be built and that message is returned to the client instead.
func secureText(text string, tool registry.Tool, filter security.Filter) (payload, rejection string) {
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		decoded = text
	}

	var cleaned any
	if skipResponseFilter(tool) {
		cleaned = security.Prepare(decoded)
	} else {
		cleaned = security.PrepareResponse(decoded, filter)
	}

	wrapped, err := security.Wrap(cleaned)
	if err != nil {
		logging.Error("failed to wrap tool result in security envelope", "error", err)
		return "", "the tool result could not be prepared for delivery"
	}

	return string(wrapped), ""
}

func skipResponseFilter(tool registry.Tool) bool {
	return tool.Sensitive || strings.HasPrefix(tool.Name, "whitelist-")
}

// isCreateOrUpdate matches tools that write caller text into PrivX.
// user-create-local and user-update-local contain the same substrings.
func isCreateOrUpdate(name string) bool {
	return strings.Contains(name, "-create") || strings.Contains(name, "-update")
}

// RecoverMiddleware turns a panicking handler into a generic error result so a
// single tool cannot take down the server.
func RecoverMiddleware(handler registry.ToolHandler) registry.ToolHandler {
	return func(ctx context.Context, params map[string]any) (result *registry.ToolResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				logging.Error("recovered from panic in tool handler", "panic", r)

				result = &registry.ToolResult{
					Content: []registry.ContentBlock{{Type: "text", Text: "an unexpected internal error occurred"}},
					IsError: true,
				}
				err = nil
			}
		}()

		return handler(ctx, params)
	}
}
