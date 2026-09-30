package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/bridge"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/help"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/remote"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/version"
)

var proxyVersion = version.MustComponent(version.Proxy, version.ProxyBinary)

func main() {
	os.Exit(run())
}

func run() int {
	if hasArg(os.Args[1:], "-h", "--help") {
		if err := help.Fprint(os.Stdout); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)

			return 1
		}

		return 0
	}

	if hasArg(os.Args[1:], "--version") {
		if err := version.Fprint(os.Stdout, version.Proxy); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)

			return 1
		}

		return 0
	}

	path, connect, resetSession, err := parseArgs(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)

		return 1
	}

	cfg, err := config.Load(path)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)

		return 1
	}

	cleanup, err := setupLogging(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to initialize logging: %v\n", err)

		return 1
	}
	defer cleanup()

	logging.Info("using config file", "path", path)

	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := oauth.NewHTTPClient(cfg.AllowHTTP)

	var sessionProbe *connectSessionProbe
	if connect {
		client, sessionProbe = withConnectHeaderLogging(client, cfg.MCPURL)
	}

	discCtx, cancel := context.WithTimeout(runCtx, oauth.DiscoverTimeout)
	discovered, err := oauth.Discover(discCtx, client, cfg.MCPURL, cfg.Client.Scopes, cfg.AllowHTTP)

	cancel()

	if err != nil {
		logging.Error("oauth discovery failed", "err", err)

		return 1
	}

	var sess *oauth.Session

	if discovered.Unauthenticated {
		logging.Info("MCP URL did not require authentication",
			"mcp_url", cfg.MCPURL,
			"unauthenticated", true,
		)
	} else {
		logging.Info("oauth discovery complete",
			"mcp_url", cfg.MCPURL,
			"unauthenticated", false,
			"resource", discovered.Resource,
			"authorization_server", discovered.AuthorizationServer,
			"authorization_endpoint", discovered.AuthorizationEndpoint,
			"token_endpoint", discovered.TokenEndpoint,
			"scopes", discovered.Scopes,
		)

		tokens, err := oauth.Obtain(runCtx, oauth.ObtainParams{
			HTTP:         client,
			Config:       cfg,
			Discovered:   discovered,
			ResetSession: resetSession,
		})
		if err != nil {
			logging.Error("oauth token flow failed", "err", err)

			return 1
		}

		sess, err = oauth.NewSession(oauth.SessionParams{
			HTTP:       client,
			Config:     cfg,
			Discovered: discovered,
			Tokens:     tokens,
			Ephemeral:  resetSession,
		})
		if err != nil {
			logging.Error("oauth session failed", "err", err)

			return 1
		}

		logging.Info("oauth tokens ready",
			"resource", discovered.Resource,
			"expires_at", tokens.ExpiresAt.Format(time.RFC3339),
		)
	}

	mcpHTTP := oauth.MCPHTTP(client, sess)

	params := remote.Params{
		HTTP:    mcpHTTP,
		MCPURL:  cfg.MCPURL,
		Name:    "privx-mcp-proxy",
		Version: proxyVersion,
	}

	if connect {
		connCtx, connCancel := context.WithTimeout(runCtx, remote.ConnectTimeout)
		listed, err := remote.Connect(connCtx, params)

		connCancel()

		if err != nil {
			logConnectSessionMode(sessionProbe, cfg.MCPURL)
			logging.Error("mcp connect failed", "err", err)

			return 1
		}

		logConnectSessionMode(sessionProbe, cfg.MCPURL)
		logging.Info("mcp tools listed",
			"mcp_url", cfg.MCPURL,
			"count", len(listed.ToolNames),
			"tools", listed.ToolNames,
		)

		return 0
	}

	openCtx, openCancel := context.WithTimeout(runCtx, remote.ConnectTimeout)
	session, err := remote.Open(openCtx, params)

	openCancel()

	if err != nil {
		logging.Error("mcp connect failed", "err", err)

		return 1
	}

	logging.Info("stdio proxy starting", "mcp_url", cfg.MCPURL)

	if err := bridge.Run(
		runCtx,
		session,
		params,
		&mcp.StdioTransport{},
	); err != nil && !errors.Is(err, context.Canceled) {
		logging.Error("stdio proxy failed", "err", err)

		return 1
	}

	logging.Info("proxy exiting")

	return 0
}

func setupLogging(cfg *config.Config) (func(), error) {
	if cfg.LogFile != "" {
		return logging.Setup(cfg.LogFile, cfg.LogLevel)
	}

	level, err := parseLogLevel(cfg.LogLevel)
	if err != nil {
		return nil, err
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	prev := slog.Default()

	slog.SetDefault(slog.New(handler))

	prevFlags := log.Flags()
	prevOutput := log.Writer()

	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	return func() {
		slog.SetDefault(prev)
		log.SetFlags(prevFlags)
		log.SetOutput(prevOutput)
	}, nil
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return slog.LevelError, nil
	case "warn":
		return slog.LevelWarn, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want error, warn, info, or debug)", s)
	}
}

func hasArg(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name {
				return true
			}
		}
	}

	return false
}

func parseArgs(args []string) (string, bool, bool, error) {
	var path string

	connect := false
	resetSession := false

	for _, arg := range args {
		switch arg {
		case "-h", "--help", "--version":
			continue
		case "--connect":
			connect = true

			continue
		case "--reset-session":
			resetSession = true

			continue
		}

		if strings.HasPrefix(arg, "-") {
			return "", false, false, fmt.Errorf("unknown flag %q", arg)
		}

		if path != "" {
			return "", false, false, fmt.Errorf("unexpected extra argument %q", arg)
		}

		path = arg
	}

	if path == "" {
		return "", false, false, fmt.Errorf("config file path is required")
	}

	return path, connect, resetSession, nil
}

type connectSessionProbe struct {
	sawMCPResponse bool
	sawSessionID   bool
}

func withConnectHeaderLogging(base *http.Client, mcpURL string) (*http.Client, *connectSessionProbe) {
	if base == nil {
		return nil, nil
	}

	probe := &connectSessionProbe{}
	cloned := *base
	inner := base.Transport

	if inner == nil {
		inner = http.DefaultTransport
	}

	cloned.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		logging.Info("connect http request",
			"method", req.Method,
			"url", req.URL.String(),
			"headers", formatHeaders(req.Header),
		)

		resp, err := inner.RoundTrip(req)
		if err != nil {
			logging.Info("connect http response",
				"method", req.Method,
				"url", req.URL.String(),
				"err", err,
			)

			return nil, err
		}

		logging.Info("connect http response",
			"method", req.Method,
			"url", req.URL.String(),
			"status", resp.StatusCode,
			"headers", formatHeaders(resp.Header),
		)
		probe.observe(req, resp, mcpURL)

		return resp, nil
	})

	return &cloned, probe
}

func (p *connectSessionProbe) observe(req *http.Request, resp *http.Response, mcpURL string) {
	if p == nil || req == nil || resp == nil || req.URL == nil {
		return
	}

	if normalizeURL(req.URL.String()) != normalizeURL(mcpURL) {
		return
	}

	p.sawMCPResponse = true
	if strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")) != "" {
		p.sawSessionID = true
	}
}

func logConnectSessionMode(probe *connectSessionProbe, mcpURL string) {
	mode := inferSessionMode(probe)
	interpretation := sessionModeInterpretation(mode)
	logging.Info(
		"mcp session mode from Mcp-Session-Id observation",
		"mcp_url", mcpURL,
		"mode", mode,
		"using_mode", interpretation,
		"mcp_session_id_seen", probe != nil && probe.sawSessionID,
	)
}

func inferSessionMode(probe *connectSessionProbe) string {
	if probe == nil || !probe.sawMCPResponse {
		return "unknown"
	}

	if probe.sawSessionID {
		return "sessioned"
	}

	return "stateless"
}

func normalizeURL(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), "/")
}

func sessionModeInterpretation(mode string) string {
	switch mode {
	case "stateless":
		return "using stateless streamable HTTP mode"
	case "sessioned":
		return "using sessioned streamable HTTP mode"
	default:
		return "mode unknown from observed traffic"
	}
}

func formatHeaders(headers http.Header) string {
	if len(headers) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", key, redactHeaderValue(key, headers.Values(key))))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

func redactHeaderValue(key string, values []string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		if len(values) == 0 {
			return "[]"
		}

		return "[REDACTED]"
	default:
		return strings.Join(values, ", ")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
