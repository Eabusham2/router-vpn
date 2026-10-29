package controllertransport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testAccess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testShutdown = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type testProcess struct{ dead atomic.Bool }

func (*testProcess) PID() uint32 { return 731 }
func (process *testProcess) Alive() error {
	if process.dead.Load() {
		return errors.New("retained test process exited")
	}
	return nil
}

func testServer(t *testing.T, handler http.Handler) (*httptest.Server, *Identity) {
	t.Helper()
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	config, err := identity.Config()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = config
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, identity
}

func testClient(t *testing.T, server *httptest.Server, identity *Identity, owner *testProcess) *Client {
	t.Helper()
	client, err := newClient(owner, identity.Pin(), testAccess, testShutdown, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func independentMAC(secret, body string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(hash, body)
	return hex.EncodeToString(hash.Sum(nil))
}

func TestControllerTransportPinnedTLSAndSharedIdentity(t *testing.T) {
	owner := new(testProcess)
	var authenticated atomic.Int32
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.TLS.Version < 0x0303 {
			t.Error("private controller request did not use authenticated TLS")
		}
		if request.URL.Path == "/api/controller/identity" {
			challenge := request.Header.Get("X-RouterVPN-Challenge")
			want := independentMAC(testAccess, "routervpn-controller-identity-request\n"+challenge)
			if !validOwner(challenge) || request.Header.Get("Authorization") != "RouterVPN-Identity "+want {
				t.Error("native identity did not preserve the shared challenge request")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "process_id": owner.PID(), "challenge": challenge,
				"proof": independentMAC(testAccess, "routervpn-controller-identity-response\n731\n"+challenge)})
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+testAccess {
			t.Error("pinned private request lost its captured access token")
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"selected_node":"owned"}` {
			t.Error("pinned private request lost its exact body")
		}
		authenticated.Add(1)
		_, _ = io.WriteString(w, `{"phase":"off"}`)
	}))
	client := testClient(t, server, identity, owner)
	if err := client.VerifyIdentity(testContext(t)); err != nil {
		t.Fatal(err)
	}
	response, err := client.Request(testContext(t), http.MethodPost, "/api/profile/settings", []byte(`{"selected_node":"owned"}`), 1024)
	if err != nil || response.Status != 200 || string(response.Body) != `{"phase":"off"}` || authenticated.Load() != 1 {
		t.Fatal("actual pinned TLS request did not reach the captured controller:", err)
	}
}

func TestControllerTransportWrongPinSendsNoPrivateRequest(t *testing.T) {
	var received atomic.Int32
	server, _ := testServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := testClient(t, server, other, new(testProcess))
	if _, err := client.Request(testContext(t), http.MethodPost, "/api/import", []byte(`{"private_key":"must-not-arrive"}`), 1024); err == nil {
		t.Fatal("wrong TLS pin admitted a private controller request")
	}
	if received.Load() != 0 {
		t.Fatal("wrong TLS pin exposed bearer or private body before peer authentication")
	}
}

func TestControllerTransportReauthenticatesReplacementListener(t *testing.T) {
	owner := new(testProcess)
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "owned") }))
	address := server.Listener.Addr().String()
	client := testClient(t, server, identity, owner)
	if _, err := client.Request(testContext(t), http.MethodGet, "/api/status", nil, 1024); err != nil {
		t.Fatal(err)
	}
	// The real process handle can remain live while its old HTTP listener has
	// closed. A subsequent Transport reconnect must authenticate anew.
	server.CloseClientConnections()
	server.Close()
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	var received atomic.Int32
	replacement := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	_ = replacement.Listener.Close()
	replacement.Listener = listener
	replacement.Config.ErrorLog = log.New(io.Discard, "", 0)
	replacement.StartTLS()
	defer replacement.Close()
	if _, err := client.Request(testContext(t), http.MethodPost, "/api/import", []byte("private replacement control"), 1024); err == nil {
		t.Fatal("replacement listener acquired a retained controller session")
	}
	if received.Load() != 0 {
		t.Fatal("replacement listener received private request bytes")
	}
}

func TestControllerTransportNoPlaintextFallback(t *testing.T) {
	var received atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	defer plain.Close()
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClient(new(testProcess), identity.Pin(), testAccess, testShutdown, strings.Replace(plain.URL, "http:", "https:", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Request(testContext(t), http.MethodPost, "/api/import", []byte("private plaintext control"), 1024); err == nil {
		t.Fatal("plaintext listener acquired a pinned native session")
	}
	if received.Load() != 0 {
		t.Fatal("plaintext fallback exposed a private controller request")
	}
}

func TestControllerTransportRejectsRedirectAndForeignAddress(t *testing.T) {
	var received atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	defer destination.Close()
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL+"/private", http.StatusTemporaryRedirect)
	}))
	client := testClient(t, server, identity, new(testProcess))
	if _, err := client.Request(testContext(t), http.MethodPost, "/api/import", []byte("private redirect control"), 1024); err == nil {
		t.Fatal("native controller followed a redirect")
	}
	for _, path := range []string{destination.URL, "//localhost/api/status", "/api/../outside", "/outside", "/api/\\remote"} {
		if _, err := client.Request(testContext(t), http.MethodGet, path, nil, 1024); err == nil {
			t.Fatal("controller request accepted a foreign or ambiguous address")
		}
	}
	if received.Load() != 0 {
		t.Fatal("redirect destination received the captured controller request")
	}
}

func TestControllerTransportRetiredOwnerSendsNothing(t *testing.T) {
	owner := new(testProcess)
	var received atomic.Int32
	server, identity := testServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	client := testClient(t, server, identity, owner)
	owner.dead.Store(true)
	if _, err := client.Request(testContext(t), http.MethodPost, "/api/import", []byte("retired"), 1024); err == nil {
		t.Fatal("retired retained process sent a private request")
	}
	if received.Load() != 0 {
		t.Fatal("retired owner reached the listener")
	}
}

func TestControllerTransportCloseJoinsPendingRead(t *testing.T) {
	entered, handlerDone := make(chan struct{}), make(chan struct{})
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		defer close(handlerDone)
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		close(entered)
		<-request.Context().Done()
	}))
	client := testClient(t, server, identity, new(testProcess))
	done := make(chan error, 1)
	go func() {
		_, err := client.Request(context.Background(), http.MethodGet, "/api/status", nil, 1024)
		done <- err
	}()
	<-entered
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("retired transport published a partial response")
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("retired transport did not close its actual pending HTTP read")
	}
	if _, err := client.Request(testContext(t), http.MethodGet, "/api/status", nil, 1024); !errors.Is(err, ErrRetired) {
		t.Fatal("retired transport admitted a replacement operation:", err)
	}
}

func TestControllerTransportCloseJoinsDetachedDial(t *testing.T) {
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	client := testClient(t, server, identity, new(testProcess))
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	client.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, ctx.Err()
	}
	requestDone := make(chan error, 1)
	go func() {
		_, err := client.Request(context.Background(), http.MethodGet, "/api/status", nil, 1024)
		requestDone <- err
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.Close() }()
	<-cancelled
	if err := <-requestDone; err == nil {
		t.Fatal("cancelled request admitted a late dial")
	}
	select {
	case err := <-closeDone:
		close(release)
		t.Fatal("transport Close abandoned its detached native dial:", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestControllerTransportStaleResponseAndBoundedBodies(t *testing.T) {
	for _, mode := range []string{"stale", "oversize", "stream-oversize"} {
		t.Run(mode, func(t *testing.T) {
			owner := new(testProcess)
			server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if mode == "stale" {
					owner.dead.Store(true)
					_, _ = io.WriteString(w, "stale")
					return
				}
				if mode == "oversize" {
					w.Header().Set("Content-Length", "128")
				} else {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, strings.Repeat("x", 128))
			}))
			client := testClient(t, server, identity, owner)
			if _, err := client.Request(testContext(t), http.MethodGet, "/api/status", nil, 32); err == nil {
				t.Fatal("stale or oversized native result was published")
			}
		})
	}
}

func TestControllerTransportRejectsFalseIdentityReceipts(t *testing.T) {
	for _, mutation := range []string{"wrong-pid", "wrong-challenge", "wrong-proof", "duplicate", "extra", "missing", "trailing"} {
		t.Run(mutation, func(t *testing.T) {
			owner := new(testProcess)
			server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				challenge := request.Header.Get("X-RouterVPN-Challenge")
				pid := int(owner.PID())
				if mutation == "wrong-pid" {
					pid++
				}
				if mutation == "wrong-challenge" {
					challenge = strings.Repeat("c", 64)
				}
				proof := independentMAC(testAccess, "routervpn-controller-identity-response\n"+strconv.Itoa(pid)+"\n"+challenge)
				if mutation == "wrong-proof" {
					proof = strings.Repeat("d", 64)
				}
				value := map[string]any{"schema": 1, "process_id": pid, "challenge": challenge, "proof": proof}
				if mutation == "extra" {
					value["extra"] = true
				}
				if mutation == "missing" {
					delete(value, "schema")
				}
				raw, _ := json.Marshal(value)
				if mutation == "duplicate" {
					raw = append([]byte(`{"schema":1,`), raw[1:]...)
				}
				if mutation == "trailing" {
					raw = append(raw, []byte(` {}`)...)
				}
				_, _ = w.Write(raw)
			}))
			client := testClient(t, server, identity, owner)
			if err := client.VerifyIdentity(testContext(t)); err == nil {
				t.Fatal("native controller accepted a false or ambiguous identity receipt")
			}
		})
	}
}

func TestControllerTransportExactShutdownAndExitedReceipt(t *testing.T) {
	for _, mutation := range []string{"valid", "flushed-before-exit", "wrong-pid", "wrong-owner", "not-closed", "duplicate", "extra"} {
		t.Run(mutation, func(t *testing.T) {
			owner := new(testProcess)
			server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/api/controller/shutdown" || request.Header.Get("Authorization") != "Bearer "+testAccess {
					t.Error("shutdown request lost its private captured operation")
				}
				var received map[string]any
				if err := json.NewDecoder(request.Body).Decode(&received); err != nil || len(received) != 3 || received["owner_token"] != testShutdown || received["process_id"] != float64(owner.PID()) {
					t.Error("shutdown request lost its exact retained owner")
				}
				value := map[string]any{"schema": 1, "process_id": owner.PID(), "owner_token": testShutdown, "closed": true}
				switch mutation {
				case "wrong-pid":
					value["process_id"] = owner.PID() + 1
				case "wrong-owner":
					value["owner_token"] = testAccess
				case "not-closed":
					value["closed"] = false
				case "extra":
					value["extra"] = true
				}
				raw, _ := json.Marshal(value)
				if mutation == "duplicate" {
					raw = append([]byte(`{"closed":true,`), raw[1:]...)
				}
				if mutation == "flushed-before-exit" {
					// TCP response receipt may be fully available even though the
					// retained child exits before its caller decodes the frame.
					owner.dead.Store(true)
				}
				_, _ = w.Write(raw)
			}))
			client := testClient(t, server, identity, owner)
			err := client.Shutdown(testContext(t))
			valid := mutation == "valid" || mutation == "flushed-before-exit"
			if valid && err != nil {
				t.Fatal("authentic terminal cleanup receipt was lost:", err)
			}
			if !valid && err == nil {
				t.Fatal("false shutdown receipt closed another owner")
			}
		})
	}
}

func TestControllerTransportInvalidCaptureNeverDials(t *testing.T) {
	identity, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, captured := range []struct{ pin, access, shutdown, endpoint string }{
		{"", testAccess, testShutdown, BaseURL},
		{identity.Pin(), "bad", testShutdown, BaseURL},
		{identity.Pin(), testAccess, testAccess, BaseURL},
		{identity.Pin(), testAccess, testShutdown, "http://127.0.0.1:8788"},
		{identity.Pin(), testAccess, testShutdown, "https://localhost:8788"},
		{identity.Pin(), testAccess, testShutdown, "https://127.0.0.1:8788/api"},
	} {
		if client, err := newClient(new(testProcess), captured.pin, captured.access, captured.shutdown, captured.endpoint); err == nil {
			_ = client.Close()
			t.Fatal("invalid native TLS capture acquired a transport")
		}
	}
}

func TestControllerTransportPreservesExactBundleImportLimit(t *testing.T) {
	// Use the existing complete 32 MiB UI/handler boundary, with binary bytes
	// that cannot survive an accidental string conversion or truncation.
	body := bytes.Repeat([]byte{0, 0xc3, 0xa9, '\n', '\r', '\\', '"', 0xff}, (32<<20)/8)
	want := sha256.Sum256(body)
	var received atomic.Int32
	server, identity := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		received.Add(1)
		if request.Method != http.MethodPost || request.RequestURI != "/api/profile/import" || request.Header.Get("Authorization") != "Bearer "+testAccess {
			t.Error("bundle import lost its exact pinned route or access token")
		}
		digest := sha256.New()
		count, err := io.Copy(digest, request.Body)
		if err != nil || count != 32<<20 || !bytes.Equal(digest.Sum(nil), want[:]) {
			t.Error("complete bundle import changed its original bytes")
		}
		_, _ = io.WriteString(w, `{"imported":true}`)
	}))
	client := testClient(t, server, identity, new(testProcess))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Request(ctx, http.MethodPost, "/api/profile/import", body, 256<<10)
	if err != nil || result.Status != 200 || string(result.Body) != `{"imported":true}` || received.Load() != 1 {
		t.Fatal("existing 32 MiB bundle import did not reach the pinned controller unchanged:", err)
	}
	for _, invalid := range []struct{ method, path string }{
		{http.MethodPost, "/api/profile/settings"},
		{http.MethodPost, "/api/external-profile/import"},
		{http.MethodPost, "/api/%70rofile/import"},
		{http.MethodPost, "/api/profile/import?other=1"},
		{http.MethodGet, "/api/profile/import"},
	} {
		if _, err := client.Request(ctx, invalid.method, invalid.path, body, 256<<10); err == nil {
			t.Fatal("bundle import request budget escaped its exact supported operation")
		}
	}
	if _, err := client.Request(ctx, http.MethodPost, "/api/profile/import", append(body, 0), 256<<10); err == nil {
		t.Fatal("oversized bundle import reached the pinned controller")
	}
	if received.Load() != 1 {
		t.Fatal("rejected oversized or aliased import transmitted private bytes")
	}
}
