package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const torCheckURL = "https://check.torproject.org/api/ip"

func publicTorExit(value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", errors.New("Tor check returned an invalid/non-public exit address")
	}
	return ip.String(), nil
}

func proveTorBridgeExitWithContext(ctx context.Context, window time.Duration) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if window <= 0 {
		return "", errors.New("Tor dynamic public-exit proof window must be positive")
	}
	proofCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	var last error
	for {
		if err := proofCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if last != nil {
				return "", errors.New("Tor dynamic public-exit proof timed out: " + last.Error())
			}
			return "", errors.New("Tor dynamic public-exit proof timed out")
		}
		req, err := http.NewRequestWithContext(proofCtx, http.MethodGet, torCheckURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-store")
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
			_ = resp.Body.Close()
			if readErr == nil && len(body) <= 4096 && resp.StatusCode/100 == 2 {
				var proof struct {
					IsTor bool   `json:"IsTor"`
					IP    string `json:"IP"`
				}
				if jsonErr := json.Unmarshal(body, &proof); jsonErr == nil {
					if !proof.IsTor {
						last = errors.New("Tor Project check endpoint reported IsTor=false; full-device path was not adopted")
					} else if ip, ipErr := publicTorExit(proof.IP); ipErr == nil {
						return ip, nil
					} else {
						last = ipErr
					}
				} else {
					last = errors.New("Tor Project check endpoint returned invalid proof JSON")
				}
			} else if readErr != nil {
				last = readErr
			} else if len(body) > 4096 {
				last = errors.New("Tor Project check response exceeded safety limit")
			} else {
				last = errors.New("Tor Project check endpoint returned a non-success status")
			}
		} else {
			last = err
		}
		timer := time.NewTimer(300 * time.Millisecond)
		select {
		case <-proofCtx.Done():
			stopTimerWithoutBlocking(timer)
			continue
		case <-timer.C:
		}
	}
}

func (a *app) proveTorBridgeExit() (string, error) {
	ctx := a.connectionOperationContextOrBackground()
	ip, err := proveTorBridgeExitWithContext(ctx, 100*time.Second)
	if err != nil && ctx.Err() != nil {
		return "", errConnectionOperationCancelled
	}
	return ip, err
}
