package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"router-vpn/internal/common"
)

var publicExitProofProviders = []string{"https://api64.ipify.org", "https://api.ipify.org"}

func stopTimerWithoutBlocking(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func proveExpectedPublicExit(ctx context.Context, client *http.Client, providers []string, expected, label string, window time.Duration) error {
	publicExpected, err := common.NormalizeExpectedPublicIP(expected)
	if err != nil {
		return fmt.Errorf("expected public exit IP is invalid: %w", err)
	}
	expectedIP := net.ParseIP(publicExpected)
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return errors.New("public exit proof client is nil")
	}
	if len(providers) == 0 {
		return errors.New("public exit proof has no providers")
	}
	if window <= 0 {
		return errors.New("public exit proof window must be positive")
	}
	if strings.TrimSpace(label) == "" {
		label = "public exit"
	}

	// Preserve the caller's owned transport and TLS settings, but never let a
	// provider redirect substitute another endpoint as connection evidence.
	// Do not mutate a shared client's redirect policy.
	proofClient := *client
	proofClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("public exit proof redirect refused")
	}
	proofCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	var last error
	for {
		for _, endpoint := range providers {
			if err := proofCtx.Err(); err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("%s proof cancelled: %w", label, ctx.Err())
				}
				if last != nil {
					return fmt.Errorf("%s proof timed out: %w", label, last)
				}
				return fmt.Errorf("%s proof timed out", label)
			}
			req, err := http.NewRequestWithContext(proofCtx, http.MethodGet, endpoint, nil)
			if err != nil {
				last = err
				continue
			}
			req.Header.Set("Cache-Control", "no-store")
			req.Header.Set("Accept-Encoding", "identity")
			resp, err := proofClient.Do(req)
			if err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("%s proof cancelled: %w", label, ctx.Err())
				}
				last = err
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 257))
			_ = resp.Body.Close()
			// A late successful body cannot finish a cancelled connection. Also
			// read a sentinel byte instead of accepting a truncated IP prefix.
			if err := proofCtx.Err(); err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("%s proof cancelled: %w", label, ctx.Err())
				}
				return fmt.Errorf("%s proof timed out: %w", label, err)
			}
			if len(body) > 256 {
				last = fmt.Errorf("%s proof returned an oversized response", label)
				continue
			}
			if readErr != nil {
				last = readErr
				continue
			}
			if resp.StatusCode/100 != 2 {
				last = fmt.Errorf("%s proof returned HTTP %d", label, resp.StatusCode)
				continue
			}
			observed := net.ParseIP(strings.TrimSpace(string(body)))
			if observed == nil {
				last = fmt.Errorf("%s proof returned a non-IP value", label)
				continue
			}
			if observed.Equal(expectedIP) {
				return nil
			}
			last = fmt.Errorf("%s reached public address %s, expected %s", label, observed.String(), expectedIP.String())
		}

		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-proofCtx.Done():
			stopTimerWithoutBlocking(timer)
			if ctx.Err() != nil {
				return fmt.Errorf("%s proof cancelled: %w", label, ctx.Err())
			}
			if last != nil {
				return fmt.Errorf("%s proof timed out: %w", label, last)
			}
			return fmt.Errorf("%s proof timed out", label)
		case <-timer.C:
		}
	}
}

func (a *app) proveStandardExitForOperation(expected string) error {
	if strings.TrimSpace(expected) == "" {
		a.mu.Lock()
		torRuntime := a.state.RuntimeMode == "external-tor-bridge" && a.state.Mode == "external-node"
		a.mu.Unlock()
		if !torRuntime {
			return errors.New("standard exit has no expected public exit IP")
		}
		_, err := a.proveTorBridgeExit()
		return err
	}
	proxyURL, err := url.Parse(multihopProofProxy)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ForceAttemptHTTP2 = false
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	return proveExpectedPublicExit(a.connectionOperationContextOrBackground(), client, publicExitProofProviders, expected, "standard exit", 10*time.Second)
}

func (a *app) proveOpenVPNStandardExitForOperation(expected string) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	return proveExpectedPublicExit(a.connectionOperationContextOrBackground(), client, publicExitProofProviders, expected, "OpenVPN exit", 14*time.Second)
}
