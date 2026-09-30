package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/help"
)

func TestParseArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		wantPath    string
		wantConnect bool
		wantReset   bool
		wantErr     bool
	}{
		{name: "path", args: []string{"proxy.toml"}, wantPath: "proxy.toml"},
		{name: "connect after", args: []string{"proxy.toml", "--connect"}, wantPath: "proxy.toml", wantConnect: true},
		{name: "connect before", args: []string{"--connect", "proxy.toml"}, wantPath: "proxy.toml", wantConnect: true},
		{name: "reset session", args: []string{"--reset-session", "proxy.toml"}, wantPath: "proxy.toml", wantReset: true},
		{name: "reset and connect", args: []string{"proxy.toml", "--connect", "--reset-session"}, wantPath: "proxy.toml", wantConnect: true, wantReset: true},
		{name: "connect only", args: []string{"--connect"}, wantErr: true},
		{name: "help skipped in parseArgs", args: []string{"--connect", "--help"}, wantErr: true},
		{name: "missing", args: []string{}, wantErr: true},
		{name: "unknown flag", args: []string{"--config", "x.toml"}, wantErr: true},
		{name: "extra", args: []string{"a.toml", "b.toml"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, connect, reset, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("error = nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("error = %v", err)
			}

			if got != tt.wantPath {
				t.Fatalf("path = %q, want %q", got, tt.wantPath)
			}

			if connect != tt.wantConnect {
				t.Fatalf("connect = %v, want %v", connect, tt.wantConnect)
			}

			if reset != tt.wantReset {
				t.Fatalf("reset = %v, want %v", reset, tt.wantReset)
			}
		})
	}
}

func TestHelpDescribesStdioProxy(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := help.Fprint(&buf); err != nil {
		t.Fatal(err)
	}

	got := buf.String()

	if strings.Contains(got, "not implemented") {
		t.Fatalf("usage still describes a wait loop:\n%s", got)
	}

	if !strings.Contains(got, "Stdio-to-streamable-HTTP") {
		t.Fatalf("usage missing stdio proxy description:\n%s", got)
	}

	if !strings.Contains(got, "--connect") {
		t.Fatalf("usage missing --connect:\n%s", got)
	}

	if !strings.Contains(got, "mcpServers") {
		t.Fatalf("usage missing client config example:\n%s", got)
	}
}

func TestHasArgDetectsHelpWithConnect(t *testing.T) {
	t.Parallel()

	if !hasArg([]string{"--connect", "--help"}, "-h", "--help") {
		t.Fatal("expected --help to be detected so run() can skip the config path")
	}

	if hasArg([]string{"--connect", "proxy.toml"}, "-h", "--help") {
		t.Fatal("did not expect --help")
	}
}

func TestFormatHeadersRedactsSensitiveValues(t *testing.T) {
	t.Parallel()

	got := formatHeaders(http.Header{
		"Authorization": {"Bearer token"},
		"Cookie":        {"sid=abc"},
		"Accept":        {"application/json"},
	})

	if !strings.Contains(got, `Accept="application/json"`) {
		t.Fatalf("missing normal header: %s", got)
	}

	if !strings.Contains(got, `Authorization="[REDACTED]"`) {
		t.Fatalf("authorization not redacted: %s", got)
	}

	if !strings.Contains(got, `Cookie="[REDACTED]"`) {
		t.Fatalf("cookie not redacted: %s", got)
	}
}

func TestInferSessionMode(t *testing.T) {
	t.Parallel()

	if got := inferSessionMode(nil); got != "unknown" {
		t.Fatalf("mode = %q, want unknown", got)
	}

	if got := inferSessionMode(&connectSessionProbe{}); got != "unknown" {
		t.Fatalf("mode = %q, want unknown", got)
	}

	if got := inferSessionMode(&connectSessionProbe{sawMCPResponse: true}); got != "stateless" {
		t.Fatalf("mode = %q, want stateless", got)
	}

	if got := inferSessionMode(&connectSessionProbe{sawMCPResponse: true, sawSessionID: true}); got != "sessioned" {
		t.Fatalf("mode = %q, want sessioned", got)
	}
}

func TestConnectSessionProbeObserve(t *testing.T) {
	t.Parallel()

	probe := &connectSessionProbe{}
	reqURL, err := url.Parse("http://localhost:8181/mcp")
	if err != nil {
		t.Fatal(err)
	}

	probe.observe(
		&http.Request{URL: reqURL},
		&http.Response{Header: http.Header{}},
		"http://localhost:8181/mcp",
	)

	if !probe.sawMCPResponse {
		t.Fatal("expected mcp response observation")
	}

	if probe.sawSessionID {
		t.Fatal("did not expect session id")
	}

	probe.observe(
		&http.Request{URL: reqURL},
		&http.Response{Header: http.Header{"Mcp-Session-Id": {"sess-1"}}},
		"http://localhost:8181/mcp",
	)

	if !probe.sawSessionID {
		t.Fatal("expected session id observation")
	}
}

func TestSessionModeInterpretation(t *testing.T) {
	t.Parallel()

	if got := sessionModeInterpretation("stateless"); got != "using stateless streamable HTTP mode" {
		t.Fatalf("got %q", got)
	}

	if got := sessionModeInterpretation("sessioned"); got != "using sessioned streamable HTTP mode" {
		t.Fatalf("got %q", got)
	}

	if got := sessionModeInterpretation("unknown"); got != "mode unknown from observed traffic" {
		t.Fatalf("got %q", got)
	}
}
