package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Route-sensitive measurements must follow the active OS/TUN route, not an
// ambient environment proxy, and must never follow a redirect onto a different
// path or service.
func newRouteBoundHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("route-bound telemetry redirect refused")
		},
	}
}

func newPrivateTelemetryHTTPClient(timeout time.Duration) *http.Client {
	return newRouteBoundHTTPClient(timeout)
}

func privateBenchmarkRequestContext(ctx context.Context, method, target, token string, body io.Reader) (*http.Request, error) {
	if ctx == nil {
		return nil, errors.New("private benchmark requires a request context")
	}
	req, err := privateBenchmarkRequest(method, target, token, body)
	if err != nil {
		return nil, err
	}
	return req.WithContext(ctx), nil
}

func privateDNSBenchmarkRequestContext(ctx context.Context, routerAPI, token string) (*http.Request, error) {
	if ctx == nil {
		return nil, errors.New("private DNS benchmark requires a request context")
	}
	base, err := validatedPrivateRouterAPI(routerAPI)
	if err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("private DNS benchmark requires a node token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/dns/benchmark", strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	return req, nil
}

// Validate before attaching the node token. The benchmark boundary is not a
// general authenticated HTTP client or a resolver for imported public hosts.
func validatePrivateBenchmarkTarget(method, target string) error {
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.ForceQuery || strings.Contains(target, "#") {
		return errors.New("private benchmark URL is invalid")
	}
	origin := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
	if _, err := validatedPrivateRouterAPI(origin); err != nil {
		return err
	}
	if (method != http.MethodGet || u.Path != "/api/benchmark/download") && (method != http.MethodPost || u.Path != "/api/benchmark/upload") {
		return errors.New("private benchmark requires the exact download GET or upload POST endpoint")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("private benchmark query is invalid")
	}
	if len(query) == 0 {
		return nil
	}
	if method != http.MethodGet || len(query) != 1 || len(query["bytes"]) != 1 {
		return errors.New("private benchmark accepts only one download byte limit")
	}
	count, err := strconv.ParseInt(query.Get("bytes"), 10, 64)
	if err != nil || count <= 0 || count > 16<<20 {
		return errors.New("private benchmark download byte limit is invalid")
	}
	return nil
}
