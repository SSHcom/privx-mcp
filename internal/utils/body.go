package utils

import (
	"errors"
	"io"
	"net/http"
)

// MaxRequestBody is the largest request body ReadLimitedBody will accept.
// 1 << 20 is 2^20 bytes, which is 1 MiB (1,048,576 bytes).
const MaxRequestBody int64 = 1 << 20

// ErrBodyTooLarge is returned when a request body exceeds MaxRequestBody.
var ErrBodyTooLarge = errors.New("request body too large")

// ReadLimitedBody reads r.Body up to MaxRequestBody bytes.
// Content-Length above the limit is rejected before the body is read.
// A body that exceeds the limit during the read returns ErrBodyTooLarge.
func ReadLimitedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.ContentLength > MaxRequestBody {
		rejectLargeBody(w)
		return nil, ErrBodyTooLarge
	}

	body := r.Body
	if body == nil {
		body = http.NoBody
	}

	limited := http.MaxBytesReader(w, body, MaxRequestBody)
	r.Body = limited

	data, err := io.ReadAll(limited)
	if err == nil {
		return data, nil
	}

	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		rejectLargeBody(w)
		return nil, ErrBodyTooLarge
	}

	return nil, err
}

func rejectLargeBody(w http.ResponseWriter) {
	if w == nil {
		return
	}

	w.Header().Set("Connection", "close")
}
