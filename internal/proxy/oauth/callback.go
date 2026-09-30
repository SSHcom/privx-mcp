package oauth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
)

type callbackResult struct {
	code string
	err  error
}

// Callback is a single-request loopback listener for the authorization code.
type Callback struct {
	server *http.Server
	result chan callbackResult
}

// StartCallback binds the pinned callback port. The caller must Close it.
func StartCallback(cb config.CallbackConfig, state string) (*Callback, error) {
	result := make(chan callbackResult, 1)
	path := cb.Path

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)

			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		q := r.URL.Query()

		idpErr := strings.TrimSpace(q.Get("error"))
		if idpErr != "" {
			desc := strings.TrimSpace(q.Get("error_description"))
			writeCallbackHTML(w, http.StatusBadRequest, "Authentication failed.", desc)
			sendCallbackResult(result, callbackResult{
				err: fmt.Errorf("authorization server error %q", idpErr),
			})

			return
		}

		gotState := q.Get("state")
		if gotState != state {
			writeCallbackHTML(w, http.StatusBadRequest, "Authentication failed.", "Invalid state.")
			sendCallbackResult(result, callbackResult{err: fmt.Errorf("oauth callback state mismatch")})

			return
		}

		code := strings.TrimSpace(q.Get("code"))
		if code == "" {
			writeCallbackHTML(w, http.StatusBadRequest, "Authentication failed.", "Missing authorization code.")
			sendCallbackResult(result, callbackResult{err: fmt.Errorf("oauth callback missing code")})

			return
		}

		writeCallbackHTML(w, http.StatusOK, "Authentication complete. You can close this window.", "")
		sendCallbackResult(result, callbackResult{code: code})
	})

	ln, err := net.Listen("tcp", listenAddr(cb))
	if err != nil {
		return nil, fmt.Errorf("oauth callback listen: %w", err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Debug("oauth callback server stopped", "err", err)
		}
	}()

	return &Callback{server: srv, result: result}, nil
}

// Wait blocks until a code arrives, timeout, or ctx is cancelled.
func (c *Callback) Wait(ctx context.Context, timeout time.Duration) (string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case r := <-c.result:
		return r.code, r.err
	case <-waitCtx.Done():
		if ctx.Err() != nil {
			return "", fmt.Errorf("oauth callback canceled: %w", ctx.Err())
		}

		return "", fmt.Errorf("oauth callback timed out after %s", timeout)
	}
}

// Close shuts down the listener.
func (c *Callback) Close() error {
	if c == nil || c.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := c.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("oauth callback shutdown: %w", err)
	}

	return nil
}

func sendCallbackResult(ch chan callbackResult, r callbackResult) {
	select {
	case ch <- r:
	default:
	}
}

func writeCallbackHTML(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>PrivX MCP</title></head><body><p>")
	b.WriteString(html.EscapeString(title))
	b.WriteString("</p>")

	if detail != "" {
		b.WriteString("<p>")
		b.WriteString(html.EscapeString(detail))
		b.WriteString("</p>")
	}

	b.WriteString("</body></html>")
	_, _ = w.Write([]byte(b.String()))
}
