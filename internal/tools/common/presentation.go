package common

// PresentationGuidance is appended to MCP tool descriptions so clients surface
// human-readable fields only and omit IDs and other non-human-readable values.
const PresentationGuidance = "When presenting results to the user, use human-readable fields only; do not present IDs or other non-human-readable values unless explicitly requested by the user. " +
	"Use mcp-info to look up PrivX concepts and examples of raw JSON data shapes (e.g. user, host) returned by tools."
