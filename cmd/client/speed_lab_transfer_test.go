package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type speedLabTestTransport func(*http.Request) (*http.Response, error)

func (f speedLabTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type speedLabBrokenResponse struct{}

func (speedLabBrokenResponse) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (speedLabBrokenResponse) Close() error             { return nil }

func TestSpeedLabTransferUploadRequiresConsumedRequestBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		consumed  int64
		status    int
		broken    bool
		oversized bool
		wantErr   bool
	}{
		{name: "complete", consumed: 1024, status: 200},
		{name: "early success", consumed: 4, status: 200, wantErr: true},
		{name: "empty success", status: 200, wantErr: true},
		{name: "broken response", consumed: 1024, status: 200, broken: true, wantErr: true},
		{name: "oversized response", consumed: 1024, status: 200, oversized: true, wantErr: true},
		{name: "rejected", consumed: 1024, status: 403, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: speedLabTestTransport(func(req *http.Request) (*http.Response, error) {
				defer req.Body.Close()
				if req.ContentLength != 1024 {
					t.Fatalf("request length = %d", req.ContentLength)
				}
				if _, err := io.CopyN(io.Discard, req.Body, tc.consumed); err != nil {
					return nil, err
				}
				var body io.ReadCloser = io.NopCloser(strings.NewReader("ok"))
				if tc.oversized {
					body = io.NopCloser(strings.NewReader(strings.Repeat("x", (64<<10)+1)))
				}
				if tc.broken {
					body = speedLabBrokenResponse{}
				}
				return &http.Response{StatusCode: tc.status, Body: body, Header: make(http.Header), Request: req}, nil
			})}
			got, elapsed, err := speedLabUploadRound(context.Background(), client, 1024, []byte("payload"))
			if (err != nil) != tc.wantErr {
				t.Fatalf("bytes=%d err=%v; want error=%t", got, err, tc.wantErr)
			}
			if got != tc.consumed {
				t.Fatalf("reported %d bytes; transport consumed %d", got, tc.consumed)
			}
			if elapsed <= 0 {
				t.Fatal("missing elapsed measurement")
			}
			if tc.broken && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("response failure was hidden: %v", err)
			}
		})
	}
}

func TestSpeedLabTransferDoesNotInheritEnvironmentProxy(t *testing.T) {
	client := newSpeedLabHTTPClient(time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing dedicated HTTP transport")
	}
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("ambient proxy settings can change the path labeled as the active VPN")
	}
	if !transport.DisableCompression {
		t.Fatal("compression could invalidate measured payload bytes")
	}
	if client.CheckRedirect == nil {
		t.Fatal("missing provider redirect guard")
	}
}

func TestSpeedLabTransferParallelRejectsPartialUploads(t *testing.T) {
	client := &http.Client{Transport: speedLabTestTransport(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()
		if _, err := io.CopyN(io.Discard, req.Body, 4); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
	})}
	got, _, err := speedLabParallelRound(context.Background(), "upload", client, 4096, 4, []byte("payload"))
	if err == nil || got >= 4096 {
		t.Fatalf("partial streams were accepted as a complete upload: bytes=%d err=%v", got, err)
	}
}
