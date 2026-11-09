package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

type speedLabImportedHopCallerKey struct{}

type speedLabImportedHopTransport func(*http.Request) (*http.Response, error)

func (transport speedLabImportedHopTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestSpeedLabImportedHopUsesOriginalEntryLaneAndActualTransferCounts(t *testing.T) {
	for _, fault := range []string{"none", "entry-proof", "post-load-proof", "short-download", "unread-upload", "source-replaced", "final-source-replaced", "owner-replaced", "network-replaced", "cancelled-probe", "redirect"} {
		t.Run(fault, func(t *testing.T) {
			// Retain the actual imported native graph, private original profiles,
			// owned TUN readback and tracker. Only the fixture's OS observation,
			// remote proof and HTTPS endpoint are modeled.
			session, _ := speedLabCurrentImportedSessionFixture(t)
			a := session.driver.a
			identity, _, captureErr := captureSpeedLabIdentityContext(context.Background(), a)
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			profile := cloneRouterProfile(session.selection.Entry)
			before := cloneRouterProfile(profile)
			callerIdentity := new(int)
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), speedLabImportedHopCallerKey{}, callerIdentity))
			defer cancel()
			proves, requests, closeCalls, invalidRoute := 0, 0, 0, false
			var sent, received int64
			driver := speedLabImportedHopRuntime{
				prove: func(call context.Context, captured common.RouterProfile, proxy string) error {
					proves++
					if call != ctx || proxy != "http://127.0.0.1:1098" || !reflect.DeepEqual(captured, before) {
						invalidRoute = true
						return errors.New("public proof acquired another entry or caller")
					}
					if fault == "entry-proof" || fault == "post-load-proof" && proves == 3 {
						return errors.New("public proof reached another exit identity")
					}
					return call.Err()
				},
				client: func(proxy string, timeout time.Duration) (*http.Client, func(), error) {
					client, closeIdle, err := newMultihopLaneHTTPClient(proxy, timeout)
					if err != nil {
						return nil, nil, err
					}
					request, _ := http.NewRequest(http.MethodGet, speedLabDownloadURL, nil)
					actual, err := client.Transport.(*http.Transport).Proxy(request)
					if err != nil || actual == nil || actual.String() != "http://127.0.0.1:1098" || !client.Transport.(*http.Transport).DisableCompression {
						invalidRoute = true
						return nil, nil, errors.New("transfer escaped the reserved original entry lane")
					}
					// The remote endpoint is modeled; the original request builder,
					// proxy selection, exact payload consumption and timed byte
					// accounting below are the shipping implementation.
					client.Transport = speedLabImportedHopTransport(func(request *http.Request) (*http.Response, error) {
						requests++
						if request.Context().Value(speedLabImportedHopCallerKey{}) != callerIdentity || request.URL.Scheme != "https" || request.URL.Host != "speed.cloudflare.com" ||
							request.Header.Get("Authorization") != "" || request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Cache-Control") != "no-store" {
							invalidRoute = true
							return nil, errors.New("public benchmark borrowed private credentials, another endpoint or an ambient caller")
						}
						if fault == "cancelled-probe" {
							cancel()
							return nil, request.Context().Err()
						}
						if fault == "redirect" {
							return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://different.invalid/"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: request}, nil
						}
						var body io.Reader
						if request.Method == http.MethodGet && request.URL.Path == "/__down" {
							count, err := strconv.ParseInt(request.URL.Query().Get("bytes"), 10, 64)
							if err != nil || count != 1 && count != 8<<20 {
								return nil, errors.New("unbounded imported-hop download")
							}
							if count > 1 {
								if fault == "short-download" {
									count--
								}
								received += count
								switch fault {
								case "source-replaced":
									a.mu.Lock()
									a.profiles.Profiles[0].External.Shadowsocks.Password += "replaced"
									a.mu.Unlock()
								case "final-source-replaced":
									a.mu.Lock()
									a.profiles.Profiles[1].AdGuardIPv4 = "192.168.50.155"
									a.mu.Unlock()
								case "owner-replaced":
									replacement := *identity.Imported
									nativeMultihopOwners.Store(a, &replacement)
								case "network-replaced":
									identity.Imported.networkIdentityContext = func(ctx context.Context) (string, error) { return "replacement-physical-network", ctx.Err() }
								}
							}
							body = io.LimitReader(&speedLabPatternReader{pattern: []byte(strings.Repeat("x", 1024))}, count)
						} else if request.Method == http.MethodPost && request.URL.Path == "/__up" {
							if request.ContentLength != 8<<20 {
								return nil, errors.New("unbounded imported-hop upload")
							}
							if fault != "unread-upload" {
								var err error
								sent, err = io.Copy(io.Discard, request.Body)
								if err != nil {
									return nil, err
								}
							}
							_ = request.Body.Close()
							body = strings.NewReader("ok")
						} else {
							invalidRoute = true
							return nil, errors.New("imported node was assigned a private Router benchmark")
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(body), Header: http.Header{}, Request: request}, nil
					})
					return client, func() { closeCalls++; closeIdle() }, nil
				},
			}
			hop, err := measureSpeedLabImportedEntryHopWithRuntime(ctx, profile, func(call context.Context) error {
				if call != ctx {
					return errors.New("original imported graph observer lost its caller")
				}
				return validateSpeedLabIdentityContext(call, a, identity)
			}, driver)
			if invalidRoute || !reflect.DeepEqual(profile, before) {
				t.Fatal("measurement changed its original route, caller or private profile")
			}
			if fault == "entry-proof" {
				if err == nil || requests != 0 || closeCalls != 0 {
					t.Fatal("wrong public identity reached a throughput request", err)
				}
				return
			}
			if closeCalls != 1 {
				t.Fatal("entry-lane HTTP client was not closed exactly once")
			}
			if fault == "post-load-proof" || fault == "source-replaced" || fault == "final-source-replaced" || fault == "owner-replaced" || fault == "network-replaced" || fault == "cancelled-probe" || fault == "redirect" {
				if err == nil || hop.Latency != nil || hop.Speed != nil {
					t.Fatal("stale, cancelled, redirected or wrong-entry measurements escaped", err)
				}
				return
			}
			if err != nil || proves != 3 || requests != 6 || hop.Latency == nil || hop.Latency.Samples != 4 ||
				hop.LatencyLabel != "Entry-routed HTTP response" || hop.SpeedLabel != "Entry-routed HTTPS transfer" || hop.RouterID != profile.ID {
				t.Fatal("independent entry response/transfer path did not complete with precise labels", hop, err)
			}
			if fault == "short-download" || fault == "unread-upload" {
				if hop.Speed != nil || hop.SpeedError == "" {
					t.Fatal("partial byte transfer acquired a Mbps result")
				}
				return
			}
			if hop.Speed == nil || received != 8<<20 || sent != 8<<20 || hop.Speed.Bytes != received ||
				hop.Speed.DownloadMbps <= 0 || hop.Speed.UploadMbps <= 0 || hop.Speed.ServerReceiveMs != 0 || !strings.Contains(hop.Speed.Proof, "public Speed Lab endpoint") {
				t.Fatal("imported throughput was inferred instead of measured from the actual byte counts", hop)
			}
		})
	}
}
