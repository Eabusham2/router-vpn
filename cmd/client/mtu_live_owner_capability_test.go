package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This double represents a retained kernel handle, not a live device. The
// controller and utility still use their actual loopback HTTP protocol.
type mtuCapabilityKernel struct {
	mu              sync.Mutex
	state           mtuKernelState
	changes, closes int
	closeFailures   int
	wrongReadback   bool
	rollbackFailure bool
	entered         chan struct{}
	release         chan struct{}
}

func (kernel *mtuCapabilityKernel) Read() (mtuKernelState, error) {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	return kernel.state, nil
}
func (kernel *mtuCapabilityKernel) Change(expected mtuKernelState, value int) (mtuKernelState, error) {
	kernel.mu.Lock()
	if kernel.state != expected {
		kernel.mu.Unlock()
		return mtuKernelState{}, errors.New("fixture rejected a foreign kernel owner")
	}
	kernel.changes++
	entered, release := kernel.entered, kernel.release
	kernel.entered, kernel.release = nil, nil
	kernel.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if kernel.state != expected {
		return mtuKernelState{}, errors.New("fixture owner changed while mutation drained")
	}
	kernel.state.MTU = value
	kernel.state.Index++
	kernel.state.Identity = fmt.Sprintf("retained-reader-%d", kernel.state.Index)
	if kernel.rollbackFailure {
		kernel.state.MTU = 1420
		return kernel.state, errors.New("fixture returned its verified rollback reader")
	}
	reported := kernel.state
	if kernel.wrongReadback {
		kernel.state.MTU -= 4
	}
	return reported, nil
}
func (kernel *mtuCapabilityKernel) Close() error {
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	kernel.closes++
	if kernel.closeFailures > 0 {
		kernel.closeFailures--
		return errors.New("fixture cleanup has not drained")
	}
	return nil
}

func newMTUCapabilityFixture(t *testing.T) (*mtuLiveOwner, *mtuCapabilityKernel) {
	t.Helper()
	a, snapshot := newMTUTransactionFixture(t)
	a.cmd = &exec.Cmd{}
	kernel := &mtuCapabilityKernel{state: mtuKernelState{Interface: "tun-captured", Family: 4, Index: 7, MTU: 1420, Identity: "retained-reader-7"}}
	owner := &mtuLiveOwner{a: a, snapshot: snapshot, command: a.cmd, kernel: kernel, initial: kernel.state, current: kernel.state, token: strings.Repeat("a", 32), done: make(chan struct{})}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner.endpoint = "http://" + listener.Addr().String() + "/mtu"
	owner.server = &http.Server{Handler: http.HandlerFunc(owner.serve), ReadHeaderTimeout: time.Second}
	mtuLiveOwners.Store(a, owner)
	go func() { defer close(owner.done); _ = owner.server.Serve(listener) }()
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error("fixture retained an undrained owner:", err)
		}
		mtuLiveOwners.Delete(a)
	})
	return owner, kernel
}

func mtuCapabilityCall(ctx context.Context, owner *mtuLiveOwner, method, suffix, authorization, body string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, owner.endpoint+suffix, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", authorization)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	return response.StatusCode, raw, err
}

func TestMTULiveCapabilityActualHTTPExactReadbackAndRetirement(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	for _, body := range []string{`{"action":"read"}`, `{"action":"set","mtu":1380}`, `{"action":"read"}`} {
		code, raw, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, body)
		var reply mtuOwnerReply
		if err != nil || code != http.StatusOK || json.Unmarshal(raw, &reply) != nil {
			t.Fatalf("owned HTTP operation rejected: %d %s %v", code, raw, err)
		}
		actual, _ := kernel.Read()
		if reply.Owner != owner.token || reply.Interface != actual.Interface || reply.Family != actual.Family || reply.Index != actual.Index || reply.Identity != actual.Identity || reply.MTU != actual.MTU {
			t.Fatal("capability response differs from retained kernel readback", reply, actual)
		}
	}
	if err := owner.ValidateMTU(1380); err != nil {
		t.Fatal(err)
	}
	if err := owner.ValidateMTU(1420); err == nil {
		t.Fatal("historical MTU was accepted as current readback")
	}
	if err := owner.Restore(); err != nil {
		t.Fatal(err)
	}
	actual, _ := kernel.Read()
	if actual.MTU != 1420 || actual.Index != 9 || owner.current != actual {
		t.Fatal("rollback lost its new retained reader", actual, owner.current)
	}
	if _, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1300}`); err == nil {
		t.Fatal("retired loopback capability remained reachable")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, present := mtuLiveOwners.Load(owner.a); present {
		t.Fatal("closed capability retained its app registry entry")
	}
}

func TestMTULiveCapabilityRejectsUnauthorizedAmbiguousAndUnboundedHTTP(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	tests := []struct {
		name, method, suffix, authorization, body string
		code                                      int
	}{
		{"missing-token", "POST", "", "", `{"action":"set","mtu":1380}`, 403},
		{"wrong-token", "POST", "", "Bearer " + strings.Repeat("b", 32), `{"action":"set","mtu":1380}`, 403},
		{"method", "GET", "", "Bearer " + owner.token, `{"action":"read"}`, 403},
		{"query", "POST", "?owner=replacement", "Bearer " + owner.token, `{"action":"set","mtu":1380}`, 403},
		{"path", "POST", "/another", "Bearer " + owner.token, `{"action":"set","mtu":1380}`, 403},
	}
	for _, body := range []string{`null`, `[]`, `{}`, `{} {}`, `{"action":"set","mtu":null}`, `{"action":"set","mtu":575}`, `{"action":"set","mtu":9001}`, `{"action":"set","mtu":1380,"mtu":1400}`, `{"action":"read","action":"set","mtu":1380}`, `{"action":"read","mtu":1380}`, `{"action":"set","mtu":1380,"interface":"replacement"}`, strings.Repeat(" ", 257) + `{"action":"read"}`} {
		tests = append(tests, struct {
			name, method, suffix, authorization, body string
			code                                      int
		}{body[:min(len(body), 40)], "POST", "", "Bearer " + owner.token, body, 400})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, err := mtuCapabilityCall(context.Background(), owner, test.method, test.suffix, test.authorization, test.body)
			if err != nil || code != test.code {
				t.Fatalf("invalid capability call: code=%d expected=%d err=%v", code, test.code, err)
			}
		})
	}
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if kernel.changes != 0 || kernel.state.MTU != 1420 {
		t.Fatal("invalid HTTP operation mutated the retained interface")
	}
}

func TestMTULiveCapabilityCannotFollowAReplacedConnectionOrReadback(t *testing.T) {
	for _, changed := range []string{"command", "session", "profile", "mode", "kernel-index", "kernel-identity", "kernel-mtu"} {
		t.Run(changed, func(t *testing.T) {
			owner, kernel := newMTUCapabilityFixture(t)
			switch changed {
			case "command":
				owner.a.mu.Lock()
				owner.a.cmd = &exec.Cmd{}
				owner.a.mu.Unlock()
			case "session":
				tracker := sessionTrackerFor(owner.a)
				tracker.mu.Lock()
				tracker.session.ID = "replacement"
				tracker.mu.Unlock()
			case "profile":
				owner.a.mu.Lock()
				owner.a.profiles.Profiles[0].DNSMode = "system"
				owner.a.mu.Unlock()
			case "mode":
				owner.a.mu.Lock()
				owner.a.state.Mode = "replacement"
				owner.a.mu.Unlock()
			default:
				kernel.mu.Lock()
				switch changed {
				case "kernel-index":
					kernel.state.Index++
				case "kernel-identity":
					kernel.state.Identity = "replacement"
				case "kernel-mtu":
					kernel.state.MTU = 1380
				}
				kernel.mu.Unlock()
			}
			code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1300}`)
			if err != nil || code != http.StatusConflict || owner.Validate() == nil {
				t.Fatal("stale owner reached a replacement", code, err)
			}
			kernel.mu.Lock()
			changes := kernel.changes
			kernel.mu.Unlock()
			if changes != 0 {
				t.Fatal("stale owner invoked kernel Change")
			}
			if err := owner.Restore(); err == nil {
				t.Fatal("stale owner reported replacement rollback")
			}
		})
	}
}

func TestMTULiveCapabilityChecksMutationReadbackAndRetainsFailedRollbackReader(t *testing.T) {
	for _, kind := range []string{"wrong-readback", "verified-rollback"} {
		t.Run(kind, func(t *testing.T) {
			owner, kernel := newMTUCapabilityFixture(t)
			kernel.wrongReadback = kind == "wrong-readback"
			kernel.rollbackFailure = kind == "verified-rollback"
			before := owner.current
			code, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
			if err != nil || code != http.StatusConflict {
				t.Fatal("unconfirmed change was accepted", code, err)
			}
			actual, _ := kernel.Read()
			if kind == "wrong-readback" {
				if owner.current != before || owner.Validate() == nil {
					t.Fatal("mismatched readback became authoritative")
				}
				if owner.Close() == nil || owner.closed {
					t.Fatal("unconfirmed mutation discarded its retained kernel handle")
				}
				if retained, ok := mtuLiveOwners.Load(owner.a); !ok || retained != owner {
					t.Fatal("unconfirmed mutation discarded its cleanup owner")
				}
				// Restore this deliberately inconsistent kernel double after the
				// negative assertion, so fixture teardown can join its real server.
				kernel.mu.Lock()
				kernel.state, kernel.wrongReadback = before, false
				kernel.mu.Unlock()
			} else if owner.current != actual || actual.MTU != 1420 || actual.Identity == before.Identity || owner.Validate() != nil {
				t.Fatal("verified rollback reader was discarded", actual, owner.current)
			}
		})
	}
}

func TestMTULiveCapabilityCancellationDrainsBeforeRestoring(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	kernel.entered, kernel.release = entered, release
	var once sync.Once
	defer once.Do(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requestDone := make(chan error, 1)
	go func() {
		_, _, err := mtuCapabilityCall(ctx, owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1380}`)
		requestDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual HTTP mutation did not enter the retained handle")
	}
	cancel()
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("canceled request completed successfully")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled client did not drain")
	}
	restoreDone := make(chan error, 1)
	go func() { restoreDone <- owner.Restore() }()
	select {
	case err := <-restoreDone:
		t.Fatal("rollback completed before the owned kernel mutation drained", err)
	case <-time.After(30 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case err := <-restoreDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rollback did not drain")
	}
	actual, _ := kernel.Read()
	if actual.MTU != 1420 || owner.current != actual {
		t.Fatal("canceled mutation survived rollback", actual)
	}
	if _, _, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"read"}`); err == nil {
		t.Fatal("canceled operation capability still accepts work")
	}
}

func TestMTULiveCapabilityCanceledContextCannotStartMutation(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/mtu", strings.NewReader(`{"action":"set","mtu":1380}`)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+owner.token)
	response := httptest.NewRecorder()
	owner.serve(response, request)
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if response.Code != http.StatusConflict || kernel.changes != 0 || kernel.state.MTU != 1420 {
		t.Fatal("canceled capability request began a kernel mutation")
	}
}

func TestMTULiveCapabilityFailedCloseRetainsExactRegistryOwnerForRetry(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	kernel.closeFailures = 1
	if err := owner.Close(); err == nil || owner.closed {
		t.Fatal("failed cleanup was reported as completed")
	}
	if retained, ok := mtuLiveOwners.Load(owner.a); !ok || retained != owner {
		t.Fatal("failed cleanup discarded its retry owner")
	}
	if err := owner.Close(); err != nil || !owner.closed {
		t.Fatal("checked cleanup could not be retried", err)
	}
	if _, ok := mtuLiveOwners.Load(owner.a); ok {
		t.Fatal("successful retry did not release its registry entry")
	}
	// An old owner must never delete the registry entry of its replacement.
	next := &mtuLiveOwner{}
	mtuLiveOwners.Store(owner.a, next)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if retained, _ := mtuLiveOwners.Load(owner.a); retained != next {
		t.Fatal("old cleanup removed a replacement owner")
	}
}

func TestMTULiveCapabilityCleanupCannotEraseReplacementRegistryOwner(t *testing.T) {
	owner, kernel := newMTUCapabilityFixture(t)
	next := &mtuLiveOwner{}
	mtuLiveOwners.Store(owner.a, next)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if retained, _ := mtuLiveOwners.Load(owner.a); retained != next || !owner.closed {
		t.Fatal("old capability cleanup erased the replacement registry entry")
	}
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if kernel.closes != 1 {
		t.Fatal("cleanup did not close exactly its own retained handle")
	}
}

func TestMTUOwnerUtilityRejectsForeignEndpointsAndMalformedCommands(t *testing.T) {
	t.Setenv("HOMEVPN_MTU_OWNER_TOKEN", strings.Repeat("a", 32))
	for _, endpoint := range []string{"http://localhost:9000/mtu", "http://127.0.0.2:9000/mtu", "https://127.0.0.1:9000/mtu", "http://127.0.0.1/mtu", "http://user@127.0.0.1:9000/mtu", "http://127.0.0.1:0/mtu", "http://127.0.0.1:65536/mtu", "http://127.0.0.1:9000/foreign", "http://127.0.0.1:9000/mtu?owner=next", "http://127.0.0.1:9000/mtu#foreign"} {
		t.Setenv("HOMEVPN_MTU_OWNER_URL", endpoint)
		if handled, err := mtuOwnerUtility([]string{"--mtu-owner-read"}); !handled || err == nil {
			t.Fatal("utility accepted an uncaptured endpoint", endpoint)
		}
	}
	t.Setenv("HOMEVPN_MTU_OWNER_URL", "http://127.0.0.1:9000/mtu")
	for _, args := range [][]string{{"--mtu-owner-read", "extra"}, {"--mtu-owner-set"}, {"--mtu-owner-set", "575"}, {"--mtu-owner-set", "9001"}, {"--mtu-owner-set", "bad"}, {"--mtu-owner-set", "1380", "extra"}} {
		if handled, err := mtuOwnerUtility(args); !handled || err == nil {
			t.Fatal("utility accepted malformed mutation", args)
		}
	}
	for _, token := range []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		t.Setenv("HOMEVPN_MTU_OWNER_TOKEN", token)
		if handled, err := mtuOwnerUtility([]string{"--mtu-owner-read"}); !handled || err == nil {
			t.Fatal("utility accepted malformed owner token")
		}
	}
}

func TestMTUOwnerUtilityUsesActualCapabilityAndRejectsForeignReplies(t *testing.T) {
	token := strings.Repeat("a", 32)
	for _, kind := range []string{"valid-read", "valid-set", "wrong-token", "wrong-value", "invalid-interface", "invalid-identity", "wrong-family", "duplicate", "unknown", "null", "oversize", "redirect", "failure"} {
		t.Run(kind, func(t *testing.T) {
			var requestSeen atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestSeen.Store(true)
				if r.Method != http.MethodPost || r.URL.Path != "/mtu" || r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("utility failed to use its exact captured capability")
				}
				raw, _ := io.ReadAll(io.LimitReader(r.Body, 512))
				if !bytes.Contains(raw, []byte(`"action"`)) {
					t.Error("utility did not send its operation")
				}
				reply := mtuOwnerReply{Owner: token, Interface: "tun-captured", Family: 4, Index: 7, MTU: 1380, Identity: "reader-7"}
				switch kind {
				case "wrong-token":
					reply.Owner = strings.Repeat("b", 32)
				case "wrong-value":
					reply.MTU = 1400
				case "invalid-interface":
					reply.Interface = "../replacement"
				case "invalid-identity":
					reply.Identity = "reader\nreplacement"
				case "wrong-family":
					reply.Family = 5
				case "redirect":
					w.Header().Set("Location", "/replacement")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				case "failure":
					w.WriteHeader(http.StatusConflict)
				}
				encoded, _ := json.Marshal(reply)
				switch kind {
				case "duplicate":
					encoded = append([]byte(`{"owner_token":"foreign",`), encoded[1:]...)
				case "unknown":
					encoded = append([]byte(`{"unexpected":true,`), encoded[1:]...)
				case "null":
					encoded = []byte(`null`)
				case "oversize":
					encoded = append(bytes.Repeat([]byte(" "), 4097), encoded...)
				}
				_, _ = w.Write(encoded)
			}))
			defer server.Close()
			t.Setenv("HOMEVPN_MTU_OWNER_URL", server.URL+"/mtu")
			t.Setenv("HOMEVPN_MTU_OWNER_TOKEN", token)
			arguments := []string{"--mtu-owner-set", "1380"}
			if kind == "valid-read" {
				arguments = []string{"--mtu-owner-read"}
			}
			handled, err := mtuOwnerUtility(arguments)
			if !handled || !requestSeen.Load() || (err == nil) != strings.HasPrefix(kind, "valid-") {
				t.Fatalf("utility accepted a foreign reply or rejected its own: handled=%v err=%v", handled, err)
			}
		})
	}
}
