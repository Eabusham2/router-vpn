package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

// The caller supplies the session-owned exit transport. There is intentionally
// no default-client fallback: the two providers must use the same proved path.
func probePublicExitIPContext(ctx context.Context, client *http.Client) (string, error) {
	if err := context.Cause(ctx); err != nil {
		return "", err
	}
	if client == nil {
		return "", errors.New("public-exit lookup requires an owned HTTP client")
	}
	for _, endpoint := range []string{"https://api64.ipify.org", "https://api.ipify.org"} {
		if err := context.Cause(ctx); err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Read a sentinel byte; truncating to the limit can turn an oversized
		// response with a valid IP prefix into apparent proof.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 257))
		_ = resp.Body.Close()
		if err := context.Cause(ctx); err != nil {
			return "", err
		}
		if readErr != nil || resp.StatusCode/100 != 2 || len(body) > 256 {
			continue
		}
		ip, err := common.NormalizeExpectedPublicIP(strings.TrimSpace(string(body)))
		if err == nil {
			return ip, nil
		}
	}
	if err := context.Cause(ctx); err != nil {
		return "", err
	}
	return "", errors.New("could not determine the public VPN exit address through the current selected path")
}
