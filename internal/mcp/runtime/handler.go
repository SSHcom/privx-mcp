package runtime

import (
	"context"
	"encoding/json"
	"fmt"
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
			if _, term, found := security.Prepare(params); found {
				logging.Debug("blocked tool call input", "tool", tool.Name, "term", term)
				return errorCallResult(security.InputRejectedMessage(term)), nil
			}
		}

		logging.Debug("tool call input params", "tool", tool.Name, "params", params)

		result, err := safeHandler(ctx, params)
		if err != nil {
			errResult := ToMCPError(err)
			return toCallToolResult(errResult, tool.Trusted, tool.Name), nil
		}

		return toCallToolResult(result, tool.Trusted, tool.Name), nil
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
// blacklist-checked, and wrapped in the security envelope. List/search
// payloads with a top-level items array drop failing rows instead of
// rejecting the page. Error results are always delivered as plain text.
func toCallToolResult(result *registry.ToolResult, trusted bool, toolName string) *mcp.CallToolResult {
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
		if !trusted {
			secured, rejection := secureText(text, toolName)
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
// envelope. A payload that is not valid JSON becomes the envelope's data
// string as-is. A non-empty rejection means nothing is revealed and that
// message is returned to the client instead.
func secureText(text, toolName string) (payload, rejection string) {
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		decoded = text
	}

	cleaned, omitted, term, found := security.PrepareOutput(decoded)
	if found {
		logging.Warn("blocked tool call output", "type", toolName, "term", term)
		return "", security.OutputRejectedMessage()
	}

	for _, item := range omitted {
		logOmitted(toolName, item)
	}

	if len(omitted) > 0 {
		if root, ok := cleaned.(map[string]any); ok {
			root["dropped"] = len(omitted)
		}
	}

	wrapped, err := security.Wrap(cleaned)
	if err != nil {
		logging.Error("failed to wrap tool result in security envelope", "error", err)
		return "", "the tool result could not be prepared for delivery"
	}

	return string(wrapped), ""
}

func logOmitted(toolName string, item security.OmittedItem) {
	if item.HasID {
		logging.Warn("omitted insecure record",
			"type", toolName, "id", item.ID, "key", item.Key, "value", item.Value, "term", item.Term)

		return
	}

	record := fmt.Sprintf("%v", item.Record)
	if encoded, err := json.Marshal(item.Record); err == nil {
		record = string(encoded)
	}

	logging.Warn("omitted insecure record",
		"type", toolName, "record", record, "term", item.Term)
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
