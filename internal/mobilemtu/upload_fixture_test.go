package mobilemtu

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadFixtureKeepsExactBoundsDuringCancellation(t *testing.T) {
	const size = 256 << 10
	for _, tc := range []struct {
		name                  string
		actual, declared      int
		chunked, cancelled    bool
		wantOK, wantCancelled bool
	}{
		{"complete", size, size, false, false, true, false},
		{"truncated", size - 1, size, false, false, false, false},
		{"oversized", size + 1, size, false, false, false, false},
		{"wrong-declaration", size, size + 1, false, false, false, false},
		{"chunked", size, size, true, false, false, false},
		{"cancelled-partial", 128, size, false, true, false, true},
		{"cancelled-complete", size, size, false, true, false, true},
		{"cancelled-oversized", size + 1, size, false, true, false, false},
		{"cancelled-wrong-declaration", 128, size + 1, false, true, false, false},
		{"cancelled-chunked", 128, size, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(strings.Repeat("a", tc.actual))
			request := httptest.NewRequest("POST", "/api/benchmark/upload", body)
			request.ContentLength = int64(tc.declared)
			if tc.chunked {
				request.TransferEncoding = []string{"chunked"}
			}
			if tc.cancelled {
				ctx, cancel := context.WithCancel(request.Context())
				cancel()
				request = request.WithContext(ctx)
			}
			n, err := readFixtureUpload(request)
			if (err == nil) != tc.wantOK || errors.Is(err, context.Canceled) != tc.wantCancelled {
				t.Fatalf("incorrect completion classification: bytes=%d error=%v", n, err)
			}
			if n > size+1 {
				t.Fatal("fixture read beyond its bound")
			}
			if tc.wantOK && n != size {
				t.Fatal("incomplete upload acknowledged")
			}
		})
	}
}

type brokenUploadReader struct{}

func (brokenUploadReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestUploadFixtureCannotExcuseUncancelledIOFailure(t *testing.T) {
	request := httptest.NewRequest("POST", "/api/benchmark/upload", brokenUploadReader{})
	request.ContentLength = 256 << 10
	if _, err := readFixtureUpload(request); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("uncancelled read failure accepted", err)
	}
}
