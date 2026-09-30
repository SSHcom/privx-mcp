package help

import (
	"bytes"
	"strings"
	"testing"
)

func TestFprintContainsCommandConfigAndClient(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := Fprint(&buf); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	for _, want := range []string{
		"privx-mcp-proxy <config file>.toml",
		"--connect",
		"--reset-session",
		"mcp_url",
		"[client]",
		"mcpServers",
		"/absolute/path/to/privx-mcp-proxy",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q:\n%s", want, got)
		}
	}

	if !strings.HasSuffix(got, "\n") {
		t.Fatal("help missing trailing newline")
	}
}
