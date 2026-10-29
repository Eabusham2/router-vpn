package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testLocalControllerAccess = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testLocalControllerOwner() *linuxOwnedController {
	return &linuxOwnedController{processID: os.Getpid(), callerUID: 65534, accessToken: testLocalControllerAccess, ownerToken: testControllerOwner}
}

func testLocalControllerRequest(t *testing.T, client *http.Client, base, method, path, authorization string, change func(*http.Request)) (int, string, http.Header) {
	t.Helper()
	request, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = linuxOwnedControllerAddress
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if change != nil {
		change(request)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testLocalControllerAccess) {
		t.Fatal("controller returned its bearer secret")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("private controller response lost its cache/content restrictions")
	}
	return response.StatusCode, string(raw), response.Header
}

func TestLocalControllerActualHTTPProtectsEveryRoute(t *testing.T) {
	owner := testLocalControllerOwner()
	server := httptest.NewServer(owner.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, r.URL.Path)
	})))
	defer server.Close()
	for _, route := range []string{"/", "/api/status", "/api/info", "/api/profiles", "/api/connect", "/api/profile/import", "/api/forward", controllerShutdownPath, "/not-a-registered-route"} {
		for _, token := range []string{"", "Bearer " + strings.Repeat("a", 64), "bearer " + testLocalControllerAccess, "Bearer " + testLocalControllerAccess + "0", "Basic " + testLocalControllerAccess} {
			status, _, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, route, token, nil)
			if status != http.StatusForbidden {
				t.Fatalf("route %s accepted missing/wrong native bearer: %d", route, status)
			}
		}
		status, body, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, route, "Bearer "+testLocalControllerAccess, nil)
		if status != http.StatusAccepted || body != route {
			t.Fatalf("route %s did not retain its captured owner: %d %q", route, status, body)
		}
	}
}

func TestLocalControllerActualHTTPRejectsForeignOriginsHostsAndDuplicateHeaders(t *testing.T) {
	server := httptest.NewServer(testLocalControllerOwner().handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })))
	defer server.Close()
	cases := map[string]func(*http.Request){
		"foreign-host":         func(r *http.Request) { r.Host = "example.invalid:8788" },
		"hostname-alias":       func(r *http.Request) { r.Host = "localhost:8788" },
		"wrong-port":           func(r *http.Request) { r.Host = "127.0.0.1:8789" },
		"origin":               func(r *http.Request) { r.Header.Set("Origin", "https://example.invalid") },
		"same-origin":          func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8788") },
		"empty-origin":         func(r *http.Request) { r.Header["Origin"] = []string{""} },
		"fetch-metadata":       func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
		"empty-fetch-metadata": func(r *http.Request) { r.Header["Sec-Fetch-Site"] = []string{""} },
		"duplicate-bearer":     func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+testLocalControllerAccess) },
		"combined-bearers": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+testLocalControllerAccess+", Bearer "+testLocalControllerAccess)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			status, _, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodPost, "/api/connect", "Bearer "+testLocalControllerAccess, change)
			if status != http.StatusForbidden {
				t.Fatal("foreign or ambiguous request acquired native authority", status)
			}
		})
	}
	// RemoteAddr is supplied by the actual server, never by an HTTP header.
	// Check non-loopback/ambiguous socket peers directly at that boundary.
	for _, peer := range []string{"192.0.2.7:43322", "[::1]:43322", "127.0.0.2:43322", "127.0.0.1", ""} {
		request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		request.Host, request.RemoteAddr = linuxOwnedControllerAddress, peer
		request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
		request.Header.Set("X-Forwarded-For", "127.0.0.1")
		writer := httptest.NewRecorder()
		testLocalControllerOwner().handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("untrusted actual peer reached controller") })).ServeHTTP(writer, request)
		if writer.Code != http.StatusForbidden {
			t.Fatal("socket peer substitution was accepted", peer)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8788/api/status", nil)
	request.RemoteAddr = "127.0.0.1:43322"
	request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
	writer := httptest.NewRecorder()
	testLocalControllerOwner().handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("absolute proxy request reached controller") })).ServeHTTP(writer, request)
	if writer.Code != http.StatusForbidden {
		t.Fatal("absolute-form proxy request was accepted")
	}
}

func testIndependentControllerMAC(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestLocalControllerActualHTTPIdentityProvesRetainedPIDAndFreshChallenge(t *testing.T) {
	owner := testLocalControllerOwner()
	server := httptest.NewServer(owner.handler(http.NotFoundHandler()))
	defer server.Close()
	var previous string
	for _, challenge := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		authorization := "RouterVPN-Identity " + testIndependentControllerMAC(testLocalControllerAccess, "routervpn-controller-identity-request\n"+challenge)
		status, raw, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, controllerIdentityPath, authorization, func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", challenge) })
		var fields map[string]json.RawMessage
		var response struct {
			Schema    int    `json:"schema"`
			ProcessID int    `json:"process_id"`
			Challenge string `json:"challenge"`
			Proof     string `json:"proof"`
		}
		if status != http.StatusOK || json.Unmarshal([]byte(raw), &fields) != nil || len(fields) != 4 || json.Unmarshal([]byte(raw), &response) != nil || response.Schema != 1 || response.ProcessID != os.Getpid() || response.Challenge != challenge {
			t.Fatal("identity response changed its exact retained child/challenge", status, raw)
		}
		want := testIndependentControllerMAC(testLocalControllerAccess, "routervpn-controller-identity-response\n"+strconv.Itoa(os.Getpid())+"\n"+challenge)
		wrongPID := testIndependentControllerMAC(testLocalControllerAccess, "routervpn-controller-identity-response\n"+strconv.Itoa(os.Getpid()+1)+"\n"+challenge)
		if response.Proof != want || response.Proof == previous || response.Proof == wrongPID || strings.Contains(raw, testControllerOwner) {
			t.Fatal("identity proof did not bind the actual retained PID and fresh challenge")
		}
		previous = response.Proof
	}
}

func TestLocalControllerIdentityRejectsMalformedAndCrossPurposeProofs(t *testing.T) {
	owner := testLocalControllerOwner()
	server := httptest.NewServer(owner.handler(http.NotFoundHandler()))
	defer server.Close()
	challenge := strings.Repeat("a", 32)
	authorization := "RouterVPN-Identity " + testIndependentControllerMAC(testLocalControllerAccess, "routervpn-controller-identity-request\n"+challenge)
	cases := map[string]func(*http.Request){
		"wrong-challenge":     func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", strings.Repeat("b", 32)) },
		"missing-challenge":   func(r *http.Request) { r.Header.Del("X-RouterVPN-Challenge") },
		"uppercase-challenge": func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", strings.Repeat("A", 32)) },
		"duplicate-challenge": func(r *http.Request) { r.Header.Add("X-RouterVPN-Challenge", challenge) },
		"raw-bearer":          func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testLocalControllerAccess) },
		"wrong-secret": func(r *http.Request) {
			r.Header.Set("Authorization", "RouterVPN-Identity "+testIndependentControllerMAC(strings.Repeat("b", 64), "routervpn-controller-identity-request\n"+challenge))
		},
		"response-as-request": func(r *http.Request) {
			r.Header.Set("Authorization", "RouterVPN-Identity "+testIndependentControllerMAC(testLocalControllerAccess, "routervpn-controller-identity-response\n"+strconv.Itoa(os.Getpid())+"\n"+challenge))
		},
		"post":    func(r *http.Request) { r.Method = http.MethodPost },
		"query":   func(r *http.Request) { r.URL.RawQuery = "challenge=" + challenge },
		"body":    func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 },
		"chunked": func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = -1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			status, _, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, controllerIdentityPath, authorization, func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", challenge); change(r) })
			if status != http.StatusForbidden {
				t.Fatal("malformed/cross-purpose identity proof was accepted", status)
			}
		})
	}
	status, _, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, "/api/status", authorization, func(r *http.Request) { r.Header.Set("X-RouterVPN-Challenge", challenge) })
	if status != http.StatusForbidden {
		t.Fatal("identity-only proof acquired bearer-authorized control")
	}
}

func TestLocalControllerShutdownRequiresBothBearerAndCapturedShutdownOwner(t *testing.T) {
	owner := testLocalControllerOwner()
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owner}
	closing := newControllerShutdown(a, owner.ownerToken)
	server := httptest.NewServer(owner.handler(closing.handler(http.NotFoundHandler())))
	defer server.Close()
	for _, access := range []string{"", "Bearer " + strings.Repeat("a", 64), "Bearer " + testLocalControllerAccess} {
		request, _ := http.NewRequest(http.MethodPost, server.URL+controllerShutdownPath, strings.NewReader(controllerShutdownBody(closing)))
		request.Host = linuxOwnedControllerAddress
		if access != "" {
			request.Header.Set("Authorization", access)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if access != "Bearer "+testLocalControllerAccess {
			if response.StatusCode != http.StatusForbidden || a.controllerClosing() {
				t.Fatal("shutdown crossed bearer admission", response.StatusCode)
			}
		} else if response.StatusCode != http.StatusOK || !a.controllerClosing() || strings.Contains(string(raw), testLocalControllerAccess) {
			t.Fatal("authorized shutdown did not finish its captured owner", response.StatusCode, string(raw))
		}
	}
}

func TestLocalControllerOwnerEOFDrainsActualHTTPAndHeldOperation(t *testing.T) {
	privateOperationRoot(t)
	done := make(chan struct{})
	owner := testLocalControllerOwner()
	owner.ownerDone = done
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owner}
	operation, finish, err := a.beginConnectionOperation()
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(finish) }
	defer release()
	closing := newControllerShutdown(a, owner.ownerToken)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	arrived, cancelled := make(chan struct{}), make(chan struct{})
	served := make(chan error, 1)
	go func() {
		served <- serveClientHTTP(closing, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/forward" {
				close(arrived)
				<-r.Context().Done()
				close(cancelled)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}), make(chan os.Signal))
	}()
	defer func() { release(); closing.begin(); closing.requestExit(); listener.Close() }()
	request, _ := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/api/forward", nil)
	request.Host = linuxOwnedControllerAddress
	request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
	requestDone := make(chan error, 1)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	go func() {
		response, err := client.Do(request)
		if response != nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("owned actual HTTP request did not start")
	}
	close(done)
	select {
	case <-operation.Done():
	case <-time.After(time.Second):
		t.Fatal("owner EOF did not cancel the existing connection operation")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("owner EOF did not cancel actual HTTP work")
	}
	select {
	case err := <-served:
		t.Fatal("owner EOF exited before the retained operation drained", err)
	default:
	}
	if !a.controllerClosing() {
		t.Fatal("owner EOF did not latch terminal admission")
	}
	status, _, _ := testLocalControllerRequest(t, client, "http://"+listener.Addr().String(), http.MethodPost, "/api/connect", "Bearer "+testLocalControllerAccess, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatal("new work crossed owner EOF", status)
	}
	release()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owner EOF did not join the actual HTTP server")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("canceled HTTP request did not join")
	}
	if closing.operations.Err() != context.Canceled {
		t.Fatal("owner cancellation did not remain terminal")
	}
}
