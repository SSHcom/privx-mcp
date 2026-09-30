package tool

// connItem mirrors connectionmanager.Connection fields used by
// hosts.AssertNoActiveConnections. Only id, connected, disconnected are read;
// the SDK round-trips them through JSON.
type connItem struct {
	ID           string `json:"id,omitempty"`
	Connected    string `json:"connected,omitempty"`
	Disconnected string `json:"disconnected,omitempty"`
}
