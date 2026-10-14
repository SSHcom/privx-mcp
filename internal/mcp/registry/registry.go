// Package registry defines the tool registry interface and types for MCP tool management.
package registry

import (
	"context"
	"sync"
)

// Special permission scope names shared between the tools package (which owns
// the permission-to-tool map) and the runtime package (which enforces scopes).
//
// These are not real PrivX role permissions; the runtime treats them
// specially when evaluating tool access.
const (
	// PermissionAuthenticated covers tools available to any authenticated
	// user regardless of assigned PrivX permissions.
	PermissionAuthenticated = "authenticated"

	// PermissionPublic covers tools that require no authentication. Tools in
	// this scope carry an empty RequiredPermissions list and are always
	// visible.
	PermissionPublic = "public"
)

// Tool defines a single MCP tool with its metadata and handler.
type Tool struct {
	Name        string
	Description string
	// Writes indicates whether invoking this tool mutates remote state.
	// Read-only execution modes can use this to prune write-capable tools early.
	Writes bool
	// RequiredPermissions are PrivX permission attributes (role.permission)
	// required to invoke this tool. Empty means no permission requirement.
	RequiredPermissions []string
	// Trusted marks a tool whose parameters are enumerated server-side and
	// whose payload the server itself produces (documentation, examples, usage
	// guidance) rather than reading from PrivX. The runtime exempts such tools
	// from boundary hardening: no sanitizing, no word blacklist, and no
	// security envelope, because that text may legitimately read as guidance
	// and its own keys collide with blacklisted words. PrivX-sourced strings
	// embedded in a trusted payload must be checked by the tool itself (see
	// security.PrepareStrings).
	Trusted bool
	// Sensitive marks a tool that can surface secrets, credentials, or raw
	// keystroke/session content captured from PrivX (for example reconstructed
	// SSH session trails, which may include typed passwords, DB connection
	// strings, or key material). Such tools are gated off at registration
	// unless the operator explicitly opts in, and are then restricted to
	// privx-admin role holders unless non-admin access is also opted in. The
	// marker is intrinsic to the tool and cannot be cleared by config.
	Sensitive bool
	// InputSchema is the JSON schema for the tool's input. It may be a
	// map[string]any (keys marshalled in sorted order by encoding/json) or
	// an *OrderedMap to preserve a specific key order on the wire.
	InputSchema any
	Handler     ToolHandler
}

// ToolHandler processes a tool invocation.
// ctx carries the authenticated user context (PrivX connector, roles).
type ToolHandler func(ctx context.Context, params map[string]any) (*ToolResult, error)

// ToolResult is the response from a tool handler.
type ToolResult struct {
	Content []ContentBlock
	IsError bool
}

// ContentBlock represents a piece of tool output.
type ContentBlock struct {
	Type string // "text"
	Text string
}

// TextResult builds a tool result containing a single text content block.
func TextResult(text string) *ToolResult {
	return &ToolResult{
		Content: []ContentBlock{
			{Type: "text", Text: text},
		},
	}
}

// ErrorResult builds a tool result that signals an error to the caller
// while still delivering the message as a text content block.
func ErrorResult(text string) *ToolResult {
	return &ToolResult{
		Content: []ContentBlock{
			{Type: "text", Text: text},
		},
		IsError: true,
	}
}

// Registry manages tool registration and lookup.
type Registry interface {
	Register(tools ...Tool)
	Tools() []Tool
	Get(name string) (Tool, bool)
}

// defaultRegistry is the concrete implementation of the Registry interface.
// It stores tools in a map for O(1) lookup by name and uses a RWMutex for
// thread-safe concurrent access.
type defaultRegistry struct {
	mu    sync.RWMutex
	tools map[string]Tool
	order []string // preserves registration order for Tools()
}

// NewRegistry creates a new empty Registry.
func NewRegistry() Registry {
	return &defaultRegistry{
		tools: make(map[string]Tool),
	}
}

// Register adds one or more tools to the registry, indexed by name.
// If a tool with the same name already exists, it is overwritten.
func (r *defaultRegistry) Register(tools ...Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, t := range tools {
		if _, exists := r.tools[t.Name]; !exists {
			r.order = append(r.order, t.Name)
		}

		r.tools[t.Name] = t
	}
}

// Tools returns a snapshot of all registered tools in registration order.
// The returned slice is a copy and safe to modify without affecting the registry.
func (r *defaultRegistry) Tools() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Tool, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.tools[name])
	}

	return result
}

// Get looks up a tool by name. Returns the tool and true if found,
// or a zero-value Tool and false if not found.
func (r *defaultRegistry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tools[name]

	return t, ok
}
