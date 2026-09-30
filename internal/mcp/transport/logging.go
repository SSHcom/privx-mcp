package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	applog "github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// withRequestLogging wraps an http.Handler with a single-line log per
// incoming request, including method, path, remote addr, and the resulting
// status code / duration. For POST /mcp it also captures and logs the
// JSON-RPC request and response bodies to aid debugging.
func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		hasSessionID := requestHasSessionID(r)
		observedMode := modeFromSessionID(hasSessionID)

		// Capture request body for POST so we can see the JSON-RPC method.
		var reqBody []byte
		if r.Method == http.MethodPost {
			reqBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		rr := &statusRecorder{ResponseWriter: w, status: http.StatusOK, body: &bytes.Buffer{}}
		next.ServeHTTP(rr, r)

		applog.Debug(
			"http request",
			"method", r.Method,
			"path", r.URL.RequestURI(),
			"from", r.RemoteAddr,
			"mcp_session_id_present", hasSessionID,
			"using_mode", observedMode,
			"status", rr.status,
			"duration", time.Since(start).Round(time.Millisecond),
		)

		if r.Method == http.MethodPost {
			applog.Debug("http request body", "body", string(truncate(reqBody, 2000)))
			applog.Debug("http response body", "body", string(truncate(rr.body.Bytes(), 2000)))
		}
	})
}

func requestHasSessionID(r *http.Request) bool {
	if r == nil {
		return false
	}

	return strings.TrimSpace(r.Header.Get("Mcp-Session-Id")) != ""
}

func modeFromSessionID(hasSessionID bool) string {
	if hasSessionID {
		return "sessioned streamable HTTP mode"
	}

	return "stateless streamable HTTP mode"
}

func truncate(b []byte, limit int) []byte {
	if len(b) <= limit {
		return b
	}

	return append(b[:limit:limit], []byte("...[truncated]")...)
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        *bytes.Buffer
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}

	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	s.body.Write(p)
	return s.ResponseWriter.Write(p)
}

// Flush forwards to the underlying ResponseWriter when it implements
// http.Flusher. The streamable MCP transport uses SSE and calls Flush after
// each event; without this the wrapped writer would not satisfy http.Flusher
// and streaming would break.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying ResponseWriter when it implements
// http.Hijacker, so connection upgrades are not blocked by the wrapper.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}

	return nil, nil, fmt.Errorf("response writer does not implement http.Hijacker")
}
