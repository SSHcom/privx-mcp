package transport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	applog "github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// withRequestLogging wraps an http.Handler with a single-line log per
// incoming request, including method, path, remote addr, and the resulting
// status code / duration. For POST /mcp it also logs the JSON-RPC method and,
// for tools/call, the tool name. Request and response bodies are included only
// when logToolBody reports that the named tool is registered and not sensitive.
// Every other POST is logged as a byte count. A POST body above
// utils.MaxRequestBody is rejected with 413 before the next handler runs.
func withRequestLogging(next http.Handler, logToolBody func(name string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		hasSessionID := requestHasSessionID(r)
		observedMode := modeFromSessionID(hasSessionID)

		// Capture request body for POST so we can see the JSON-RPC method.
		var reqBody []byte
		if r.Method == http.MethodPost {
			body, err := utils.ReadLimitedBody(w, r)
			if err != nil {
				writeRequestBodyError(w, err)
				return
			}

			reqBody = body
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
			call := classifyPostBody(reqBody, logToolBody)
			debugBody("http request body", call, reqBody)
			debugBody("http response body", call, rr.body.Bytes())
		}
	})
}

type postCall struct {
	method  string
	tool    string
	logBody bool
}

func classifyPostBody(body []byte, logToolBody func(name string) bool) postCall {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return postCall{}
	}

	call := postCall{method: msg.Method}
	if msg.Method != "tools/call" {
		return call
	}

	call.tool = msg.Params.Name
	if msg.Params.Name == "" || logToolBody == nil {
		return call
	}

	call.logBody = logToolBody(msg.Params.Name)

	return call
}

func debugBody(msg string, call postCall, body []byte) {
	attrs := []any{"method", call.method}
	if call.tool != "" {
		attrs = append(attrs, "tool", call.tool)
	}

	if call.logBody {
		attrs = append(attrs, "body", string(truncate(body, 2000)))
	} else {
		attrs = append(attrs, "bytes", len(body))
	}

	applog.Debug(msg, attrs...)
}

func writeRequestBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, utils.ErrBodyTooLarge) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	http.Error(w, "failed to read request body", http.StatusBadRequest)
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
