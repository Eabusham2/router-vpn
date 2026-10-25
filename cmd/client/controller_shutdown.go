package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const controllerOwnerEnvironment = "HOMEVPN_CONTROLLER_OWNER"
const controllerShutdownPath = "/api/controller/shutdown"

var errControllerClosing = errors.New("Router VPN controller is shutting down; new work is not accepted")

type controllerShutdownRequest struct {
	Schema     int    `json:"schema"`
	ProcessID  int    `json:"process_id"`
	OwnerToken string `json:"owner_token"`
}

type controllerShutdownReceipt struct {
	Schema     int    `json:"schema"`
	ProcessID  int    `json:"process_id"`
	OwnerToken string `json:"owner_token"`
	Closed     bool   `json:"closed"`
}

// An HTTP owner may time out while a native lease is closing. Keep both the
// terminal admission barrier and the completed receipt until that same owner
// receives it. Signals have no HTTP recipient and may exit as soon as cleanup
// has drained. In neither case may a failed Close become permission to exit.
type controllerShutdown struct {
	a            *app
	processID    int
	ownerToken   string
	beginOnce    sync.Once
	exitOnce     sync.Once
	done         chan struct{}
	exit         chan struct{}
	responseWait time.Duration
	retryDelay   time.Duration
	operations   context.Context
	cancelWork   context.CancelFunc
}

func newControllerShutdown(a *app, ownerToken string) *controllerShutdown {
	operations, cancelWork := context.WithCancel(context.Background())
	return &controllerShutdown{
		a: a, processID: os.Getpid(), ownerToken: ownerToken,
		done: make(chan struct{}), exit: make(chan struct{}),
		responseWait: 30 * time.Second, retryDelay: time.Second,
		operations: operations, cancelWork: cancelWork,
	}
}

func validControllerOwnerToken(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, value := range value {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}

func (a *app) controllerClosing() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closing
}

func (c *controllerShutdown) begin() {
	c.beginOnce.Do(func() {
		// Publish the permanent latch before canceling anything. A startup timer,
		// temporary test, or queued connection cannot replace the retiring owner.
		c.a.mu.Lock()
		c.a.closing = true
		c.a.mu.Unlock()
		c.cancelWork()
		c.a.cancelConnectionOperation()
		cancelCapturedMTU(c.a)
		go c.drain()
	})
}

func (c *controllerShutdown) drain() {
	reported := false
	for {
		if err := c.a.drainControllerOwner(); err == nil {
			close(c.done)
			return
		}
		if !reported {
			// Native errors can contain private provider details. The existing
			// status owns those diagnostics; never log the owner nonce or a bundle.
			log.Print("Router VPN controller shutdown is waiting for checked owned cleanup; retrying")
			reported = true
		}
		timer := time.NewTimer(c.retryDelay)
		<-timer.C
	}
}

func (a *app) drainControllerOwner() error {
	// Cancel before waiting for operationMu: Connect and Speed Lab own it until
	// their captured contexts and temporary children have retired. Cancel MTU
	// as well, because its durable adoption can otherwise wait for the same lock.
	a.cancelConnectionOperation()
	cancelCapturedMTU(a)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := finishViaEntryCancellation(a); err != nil {
		return err
	}
	a.mu.Lock()
	needsStop := a.cmd != nil || a.daitaCancel != nil || a.state.Connected ||
		a.state.Mode != "" && a.state.Mode != "off" || a.state.RuntimeMode != "" ||
		a.state.Phase != "" && a.state.Phase != "off"
	a.mu.Unlock()
	_, nativeOwned := desktopNodeOwners.Load(a)
	_, relayOwned := desktopRelays.Load(a)
	_, mtuOwned := mtuLiveOwners.Load(a)
	if !needsStop && !nativeOwned && !relayOwned && !mtuOwned {
		// A second controller that cannot bind its listener has no authority to
		// release a first controller's persisted firewall. No owned connection
		// means there is nothing to stop or reconfigure on this process's exit.
		return nil
	}
	return a.stopMode()
}

func (c *controllerShutdown) requestExit() {
	c.exitOnce.Do(func() { close(c.exit) })
}

func (c *controllerShutdown) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == controllerShutdownPath {
			c.shutdownHTTP(w, r)
			return
		}
		if c.a.controllerClosing() && !(r.URL.Path == "/api/status" && (r.Method == http.MethodGet || r.Method == http.MethodHead)) {
			http.Error(w, errControllerClosing.Error(), http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(c.operations, cancel)
		defer stop()
		defer cancel()
		if c.operations.Err() != nil {
			cancel()
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *controllerShutdown) shutdownHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	var request controllerShutdownRequest
	var fields map[string]json.RawMessage
	if err != nil || decodeRelayControlJSON(data, &request) != nil || json.Unmarshal(data, &fields) != nil ||
		len(fields) != 3 || fields["schema"] == nil || fields["process_id"] == nil || fields["owner_token"] == nil || request.Schema != 1 {
		http.Error(w, "bounded exact controller shutdown identity is required", http.StatusBadRequest)
		return
	}
	if !validControllerOwnerToken(c.ownerToken) || !validControllerOwnerToken(request.OwnerToken) ||
		request.ProcessID != c.processID || subtle.ConstantTimeCompare([]byte(request.OwnerToken), []byte(c.ownerToken)) != 1 {
		http.Error(w, "controller shutdown owner does not match", http.StatusForbidden)
		return
	}
	c.begin()
	timer := time.NewTimer(c.responseWait)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return // Cancellation of this request does not abandon native cleanup.
	case <-timer.C:
		http.Error(w, "controller cleanup is pending; retry this owned shutdown request", http.StatusServiceUnavailable)
		return
	case <-c.done:
	}
	if r.Context().Err() != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	receipt := controllerShutdownReceipt{Schema: 1, ProcessID: c.processID, OwnerToken: c.ownerToken, Closed: true}
	if err := json.NewEncoder(w).Encode(receipt); err != nil {
		return
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	if r.Context().Err() != nil {
		return
	}
	// The server's graceful shutdown waits for this handler to return. A prior
	// timeout or failed write never requests exit and can be retried by its owner.
	c.requestExit()
}

func runClientHTTP(a *app, address string, handler http.Handler) error {
	closing := newControllerShutdown(a, os.Getenv(controllerOwnerEnvironment))
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		closing.begin()
		<-closing.done
		return err
	}
	return serveClientHTTP(closing, listener, handler, signals)
}

func serveClientHTTP(closing *controllerShutdown, listener net.Listener, handler http.Handler, signals <-chan os.Signal) error {
	server := &http.Server{Handler: closing.handler(handler)}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	var serveErr error
	select {
	case <-signals:
		closing.begin()
	case <-closing.exit:
		closing.begin()
	case serveErr = <-served:
		closing.begin()
	}
	// Keep signal interception installed and the controller process alive while
	// any checked cleanup is ambiguous. HTTP remains available for the exact
	// terminal owner and status reads, with new work refused by admission guards.
	<-closing.done
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		// All connection/MTU/lease owners have already drained. Only HTTP readers
		// remain; do not let an idle or abandoned HTTP socket prevent normal exit.
		_ = server.Close()
	}
	if serveErr == nil {
		serveErr = <-served
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
