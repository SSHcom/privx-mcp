package oauth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
)

func TestCallback_SuccessAndFailures(t *testing.T) {
	t.Parallel()

	t.Run("code", func(t *testing.T) {
		t.Parallel()

		cb, port := startTestCallback(t, "expected-state")
		t.Cleanup(func() { _ = cb.Close() })

		go func() {
			resp, err := http.Get(fmt.Sprintf(
				"http://127.0.0.1:%d/oauth/callback?code=the-code&state=expected-state",
				port,
			))
			if err != nil {
				t.Error(err)

				return
			}

			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d", resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "the-code") {
				t.Error("callback page leaked the code")
			}
		}()

		code, err := cb.Wait(context.Background(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}

		if code != "the-code" {
			t.Fatalf("code = %q", code)
		}
	})

	t.Run("forged callback does not abort login", func(t *testing.T) {
		t.Parallel()

		cb, port := startTestCallback(t, "expected-state")
		t.Cleanup(func() { _ = cb.Close() })

		go func() {
			forged := []string{
				fmt.Sprintf("http://127.0.0.1:%d/oauth/callback?error=access_denied", port),
				fmt.Sprintf("http://127.0.0.1:%d/oauth/callback?code=x&state=wrong", port),
				fmt.Sprintf(
					"http://127.0.0.1:%d/oauth/callback?error=access_denied&state=wrong",
					port,
				),
			}
			for _, rawURL := range forged {
				resp, err := http.Get(rawURL)
				if err != nil {
					t.Error(err)

					return
				}

				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("status = %d", resp.StatusCode)
				}

				_ = resp.Body.Close()
			}

			resp, err := http.Get(fmt.Sprintf(
				"http://127.0.0.1:%d/oauth/callback?code=the-code&state=expected-state",
				port,
			))
			if err != nil {
				t.Error(err)

				return
			}

			_ = resp.Body.Close()
		}()

		code, err := cb.Wait(context.Background(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}

		if code != "the-code" {
			t.Fatalf("code = %q", code)
		}
	})

	t.Run("idp error", func(t *testing.T) {
		t.Parallel()

		cb, port := startTestCallback(t, "expected-state")
		t.Cleanup(func() { _ = cb.Close() })

		go func() {
			resp, err := http.Get(fmt.Sprintf(
				"http://127.0.0.1:%d/oauth/callback?error=access_denied&error_description=nope&state=expected-state",
				port,
			))
			if err != nil {
				t.Error(err)

				return
			}

			_ = resp.Body.Close()
		}()

		_, err := cb.Wait(context.Background(), 3*time.Second)
		if err == nil {
			t.Fatal("error = nil")
		}
	})
}

func startTestCallback(t *testing.T, state string) (*Callback, int) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("addr type %T", ln.Addr())
	}

	port := addr.Port
	_ = ln.Close()

	cb, err := StartCallback(config.CallbackConfig{
		Host:               "127.0.0.1",
		Port:               port,
		Path:               "/oauth/callback",
		AuthTimeoutSeconds: 5,
	}, state)
	if err != nil {
		t.Fatal(err)
	}

	return cb, port
}
