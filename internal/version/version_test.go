package version

import (
	"bytes"
	"strings"
	"testing"
)

func TestLinesPreserveOrder(t *testing.T) {
	t.Parallel()

	got, err := Lines(Proxy)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"privx-mcp-proxy 1.44.0",
		"modelcontextprotocol/go-sdk 1.7.0",
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %#v, want %#v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestComponent(t *testing.T) {
	t.Parallel()

	got, err := Component(Server, ServerBinary)
	if err != nil {
		t.Fatal(err)
	}

	if got != "1.44.0" {
		t.Fatalf("Component = %q, want 1.44.0", got)
	}

	if _, err := Component("nope", ServerBinary); err == nil {
		t.Fatal("expected error for unknown product")
	}

	if _, err := Component(Server, "missing"); err == nil {
		t.Fatal("expected error for unknown component")
	}
}

func TestFprint(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := Fprint(&buf, Server); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	wantPrefix := "privx-mcp 1.44.0\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("Fprint = %q, want prefix %q", got, wantPrefix)
	}

	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("Fprint missing trailing newline: %q", got)
	}

	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3: %q", len(lines), got)
	}
}
