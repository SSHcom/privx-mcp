package utils

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadLimitedBody_ContentLengthOverLimitDoesNotRead(t *testing.T) {
	body := &countReader{}
	req := httptest.NewRequest(http.MethodPost, "/mcp", body)
	req.ContentLength = MaxRequestBody + 1
	rec := httptest.NewRecorder()

	got, err := ReadLimitedBody(rec, req)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("ReadLimitedBody() error = %v, want ErrBodyTooLarge", err)
	}

	if got != nil {
		t.Fatalf("ReadLimitedBody() body = %d bytes, want nil", len(got))
	}

	if body.n != 0 {
		t.Fatalf("read %d bytes, want none", body.n)
	}

	if rec.Header().Get("Connection") != "close" {
		t.Fatal("expected Connection: close")
	}
}

func TestReadLimitedBody_ExactLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), int(MaxRequestBody))
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	got, err := ReadLimitedBody(rec, req)
	if err != nil {
		t.Fatalf("ReadLimitedBody() error = %v", err)
	}

	if len(got) != len(payload) {
		t.Fatalf("ReadLimitedBody() len = %d, want %d", len(got), len(payload))
	}
}

func TestReadLimitedBody_StopsPastLimit(t *testing.T) {
	body := &countReader{}
	req := httptest.NewRequest(http.MethodPost, "/mcp", body)
	req.ContentLength = -1
	rec := httptest.NewRecorder()

	got, err := ReadLimitedBody(rec, req)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("ReadLimitedBody() error = %v, want ErrBodyTooLarge", err)
	}

	if got != nil {
		t.Fatalf("ReadLimitedBody() body = %d bytes, want nil", len(got))
	}

	if body.n > MaxRequestBody+1 {
		t.Fatalf("read %d bytes, want at most %d", body.n, MaxRequestBody+1)
	}
}

type countReader struct {
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for i := range p {
		p[i] = 'a'
	}

	c.n += int64(len(p))

	return len(p), nil
}

func (c *countReader) Close() error {
	return nil
}
