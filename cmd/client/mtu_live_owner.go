package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// The optimizer holds a capability for this captured interface operation. All
// mutations remain in the controller that owns the kernel handle; subprocesses
// never rediscover a device by alias and cannot follow a replacement session.
type mtuLiveOwner struct {
	mu                         sync.Mutex
	a                          *app
	snapshot                   mtuRetestSnapshot
	command                    *exec.Cmd
	kernel                     mtuKernelOwner
	initial, current           mtuKernelState
	token, endpoint            string
	network                    string
	server                     *http.Server
	done                       chan struct{}
	cleanupOnce                sync.Once
	stopped, committed, closed bool
	changed, restored          bool
}

type mtuOwnerReply struct {
	Owner     string `json:"owner_token"`
	Interface string `json:"interface"`
	Family    int    `json:"family"`
	Index     int    `json:"index"`
	MTU       int    `json:"mtu"`
	Identity  string `json:"identity"`
}

// A failed begin/close still owns its native command. Keep that handle until
// checked cleanup succeeds, including after the HTTP requester goes away.
var mtuLiveOwners sync.Map // map[*app]*mtuLiveOwner
var mtuLiveCaptureMu sync.Mutex

func captureMTULiveOwner(a *app, snapshot mtuRetestSnapshot, live mtuLiveSnapshot) (*mtuLiveOwner, error) {
	mtuLiveCaptureMu.Lock()
	defer mtuLiveCaptureMu.Unlock()
	if raw, exists := mtuLiveOwners.Load(a); exists {
		previous, ok := raw.(*mtuLiveOwner)
		if !ok || previous.Close() != nil {
			return nil, errors.New("previous MTU interface owner is still draining")
		}
	}
	token, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	if command == nil {
		return nil, errors.New("MTU capture has no owned connection runtime")
	}
	var kernel mtuKernelOwner
	if raw, found := desktopNodeOwners.Load(a); found {
		launch, ok := raw.(*desktopNodeLaunch)
		if !ok || launch.command != command || launch.external != nil {
			return nil, errors.New("MTU capture belongs to another native runtime")
		}
		kernel, err = openDesktopNodeMTUOwner(launch, live, token)
	} else {
		kernel, err = openMTUKernelOwner(live)
	}
	owner := &mtuLiveOwner{a: a, snapshot: snapshot, command: command, kernel: kernel, token: token, network: physicalNetworkIdentity(), done: make(chan struct{})}
	if kernel == nil {
		return nil, errors.Join(errors.New("MTU capture returned no kernel owner"), err)
	}
	mtuLiveOwners.Store(a, owner)
	if err != nil {
		return owner, err
	}
	if owner.network == "" {
		return owner, errors.New("MTU capture has no physical network identity")
	}
	owner.initial, err = kernel.Read()
	if err != nil || owner.initial.Interface != live.Interface || owner.initial.Family != live.Family || owner.initial.MTU != live.OriginalMTU || !validMTUKernelState(owner.initial) {
		return owner, errors.New("MTU kernel owner differs from the captured interface")
	}
	owner.current = owner.initial
	if err = owner.Validate(); err != nil {
		return owner, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return owner, err
	}
	owner.endpoint = "http://" + listener.Addr().String() + "/mtu"
	owner.server = &http.Server{Handler: http.HandlerFunc(owner.serve), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 2048}
	go func() { defer close(owner.done); _ = owner.server.Serve(listener) }()
	return owner, nil
}

func (owner *mtuLiveOwner) validLocked() error {
	return owner.ownershipLocked(true)
}

func (owner *mtuLiveOwner) ownershipLocked(requireNetwork bool) error {
	if owner.closed {
		return errors.New("MTU interface owner is closed")
	}
	if err := validateMTURetestSnapshot(owner.a, owner.snapshot); err != nil {
		return err
	}
	owner.a.mu.Lock()
	current := owner.a.cmd
	owner.a.mu.Unlock()
	if current != owner.command {
		return errors.New("MTU runtime process was replaced")
	}
	if requireNetwork && owner.network != "" && owner.network != physicalNetworkIdentity() {
		return errors.New("physical network changed during the captured MTU operation")
	}
	state, err := owner.kernel.Read()
	if err != nil || state != owner.current {
		return errors.New("MTU kernel interface or readback changed outside its captured operation")
	}
	return nil
}

func (owner *mtuLiveOwner) Validate() error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.validLocked()
}

func (owner *mtuLiveOwner) ValidateMTU(expected int) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validLocked(); err != nil {
		return err
	}
	if owner.current.MTU != expected {
		return errors.New("captured interface did not adopt the measured MTU")
	}
	return nil
}
func (owner *mtuLiveOwner) Environment() []string {
	executable, _ := os.Executable()
	minimum := "576"
	if _, native := owner.kernel.(*desktopNodeMTUOwner); native || owner.initial.Family == 6 {
		minimum = "1280"
	}
	return []string{"HOMEVPN_MTU_OWNER_URL=" + owner.endpoint, "HOMEVPN_MTU_OWNER_TOKEN=" + owner.token, "HOMEVPN_MTU_OWNER_HELPER=" + executable, "HOMEVPN_MTU_MINIMUM=" + minimum}
}

func (owner *mtuLiveOwner) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/mtu" || r.URL.RawQuery != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+owner.token)) != 1 {
		http.Error(w, "unrecognized MTU operation", http.StatusForbidden)
		return
	}
	var request struct {
		Action string `json:"action"`
		MTU    int    `json:"mtu,omitempty"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256))
	if err != nil || decodeRelayControlJSON(raw, &request) != nil || request.Action != "read" && request.Action != "set" || request.Action == "read" && request.MTU != 0 || request.Action == "set" && (request.MTU < 576 || request.MTU > 9000) {
		http.Error(w, "invalid MTU interface operation", http.StatusBadRequest)
		return
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.stopped || r.Context().Err() != nil || owner.validLocked() != nil {
		http.Error(w, "captured MTU operation retired", http.StatusConflict)
		return
	}
	if request.Action == "set" {
		owner.changed = true // A failed write may still require owned rollback.
		next, changeErr := owner.kernel.Change(owner.current, request.MTU)
		// A native transaction may return its own rollback reader on failure.
		// Retain it only when its exact kernel readback confirms that identity.
		actual, readErr := owner.kernel.Read()
		if readErr == nil && next == actual && next.Interface == owner.initial.Interface && next.Family == owner.initial.Family && next.Index > 0 && next.Identity != "" {
			owner.current = next
		}
		if changeErr != nil || readErr != nil || next != actual || actual.MTU != request.MTU || owner.validLocked() != nil {
			http.Error(w, "captured MTU change was not confirmed", http.StatusConflict)
			return
		}
	}
	state := owner.current
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(mtuOwnerReply{Owner: owner.token, Interface: state.Interface, Family: state.Family, Index: state.Index, MTU: state.MTU, Identity: state.Identity})
}

// Stop requests first, then acquire the same mutation lock before rollback.
// A late optimizer completion cannot race the restore or a replacement owner.
func (owner *mtuLiveOwner) stopRequests() {
	owner.mu.Lock()
	owner.stopped = true
	owner.mu.Unlock()
	if owner.server != nil {
		_ = owner.server.Close()
		<-owner.done
	}
}
func (owner *mtuLiveOwner) Restore() error {
	owner.stopRequests()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if native, ok := owner.kernel.(interface {
		Restore() (mtuKernelState, error)
	}); ok {
		state, err := native.Restore()
		if err != nil {
			return err
		}
		owner.current = state
		if state.MTU != owner.initial.MTU || owner.ownershipLocked(false) != nil {
			return errors.New("native MTU rollback returned a different captured state")
		}
		owner.changed, owner.restored = false, true
		return nil
	}
	if err := owner.ownershipLocked(false); err != nil {
		return err
	}
	state, err := owner.kernel.Change(owner.current, owner.initial.MTU)
	actual, readErr := owner.kernel.Read()
	if readErr == nil && state == actual {
		owner.current = actual
	}
	if err != nil || readErr != nil || actual.MTU != owner.initial.MTU || owner.ownershipLocked(false) != nil {
		return errors.New("captured kernel MTU rollback was not confirmed")
	}
	owner.changed, owner.restored = false, true
	return nil
}
func (owner *mtuLiveOwner) Commit() error {
	owner.stopRequests()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.validLocked(); err != nil {
		return err
	}
	if native, ok := owner.kernel.(interface{ Commit() error }); ok {
		if err := native.Commit(); err != nil {
			return err
		}
	}
	owner.committed = true
	owner.changed, owner.restored = false, false
	return nil
}

// A changed profile cannot authorize a new measurement. It must not prevent
// closing this operation's still-owned legacy kernel mutation, either. The
// exact command, registry owner and retained readback are required here; no
// profile selection, network name or interface alias can retarget this write.
func (owner *mtuLiveOwner) restoreKernelForCloseLocked() error {
	owner.a.mu.Lock()
	currentCommand := owner.a.cmd
	owner.a.mu.Unlock()
	registered, exists := mtuLiveOwners.Load(owner.a)
	if owner.command == nil || currentCommand != owner.command || !exists || registered != owner {
		return errors.New("captured MTU cleanup cannot change a replacement runtime")
	}
	actual, err := owner.kernel.Read()
	if err != nil || actual != owner.current || !validMTUKernelState(owner.initial) {
		return errors.New("captured MTU cleanup has an unconfirmed kernel mutation")
	}
	if actual.MTU != owner.initial.MTU {
		next, changeErr := owner.kernel.Change(actual, owner.initial.MTU)
		readback, readErr := owner.kernel.Read()
		if readErr == nil && next == readback {
			owner.current = readback
		}
		if changeErr != nil || readErr != nil || next != readback || readback.MTU != owner.initial.MTU {
			return errors.New("captured MTU cleanup rollback was not confirmed")
		}
	}
	owner.changed, owner.restored = false, true
	return nil
}

func (owner *mtuLiveOwner) Close() error {
	owner.stopRequests()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if owner.changed && !owner.committed {
		// The native lease implements its own checked rollback in Close. Legacy
		// kernel owners only release handles, so the parent must restore first.
		if _, native := owner.kernel.(interface {
			Restore() (mtuKernelState, error)
		}); !native {
			if err := owner.restoreKernelForCloseLocked(); err != nil {
				return err
			}
		}
	}
	if err := owner.kernel.Close(); err != nil {
		return err
	}
	if native, ok := owner.kernel.(interface{ CleanupRestored() (mtuKernelState, bool) }); ok {
		state, restored := native.CleanupRestored()
		if restored && validMTUKernelState(owner.initial) {
			if !validMTUKernelState(state) || state.MTU != owner.initial.MTU || state.Interface != owner.initial.Interface || state.Family != owner.initial.Family {
				return errors.New("native cleanup returned a different captured rollback receipt")
			}
			owner.current, owner.changed, owner.restored = state, false, true
		}
	}
	owner.closed = true
	mtuLiveOwners.CompareAndDelete(owner.a, owner)
	retainCompletedRouterNodeMTU(owner)
	return nil
}

func finishMTULiveOwner(w http.ResponseWriter, owner *mtuLiveOwner) {
	if owner.Close() == nil {
		owner.publishCleanupRollback(w)
		return
	}
	writer, ok := w.(*mtuViewResponse)
	if !ok {
		return // The registry still retains the owner for an explicit retry.
	}
	operation := writer.operation
	operation.mu.Lock()
	operation.cleanupPending = true
	operation.status.Running, operation.status.Complete, operation.status.Measured = true, false, false
	operation.status.Phase = "cleanup-pending"
	operation.status.Failure = "captured MTU cleanup is still draining; ownership retained"
	operation.mu.Unlock()
	owner.cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				if owner.Close() != nil {
					continue
				}
				owner.publishCleanupRollback(writer)
				operation.mu.Lock()
				operation.cleanupPending = false
				operation.status.Running, operation.status.Complete = false, true
				operation.status.Phase = "failed"
				if operation.status.Restored {
					operation.status.Phase = "restored"
				}
				operation.mu.Unlock()
				return
			}
		}()
	})
}

func (owner *mtuLiveOwner) publishCleanupRollback(w http.ResponseWriter) {
	owner.mu.Lock()
	restored, original := owner.restored, owner.initial.MTU
	owner.mu.Unlock()
	if restored {
		recordMTUViewRollback(w, mtuLiveSnapshot{OriginalMTU: original}, nil)
	}
}

func mtuOwnerUtility(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--mtu-owner-read" && args[0] != "--mtu-owner-set" {
		return false, nil
	}
	if len(args) != 1 && args[0] == "--mtu-owner-read" || len(args) != 2 && args[0] == "--mtu-owner-set" {
		return true, errors.New("invalid MTU owner utility arguments")
	}
	request := map[string]any{"action": "read"}
	if args[0] == "--mtu-owner-set" {
		value, err := strconv.Atoi(args[1])
		if err != nil || value < 576 || value > 9000 {
			return true, errors.New("invalid captured MTU value")
		}
		request["action"], request["mtu"] = "set", value
	}
	endpoint, err := url.Parse(os.Getenv("HOMEVPN_MTU_OWNER_URL"))
	token := os.Getenv("HOMEVPN_MTU_OWNER_TOKEN")
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "/mtu" || endpoint.RawQuery != "" || endpoint.Fragment != "" || !desktopMTURequestPattern.MatchString(token) {
		return true, errors.New("missing captured MTU operation capability")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return true, errors.New("invalid MTU operation endpoint")
	}
	encoded, _ := json.Marshal(request)
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
	defer cancel()
	call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return true, err
	}
	call.Header.Set("Authorization", "Bearer "+token)
	call.Header.Set("content-type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("MTU owner redirect rejected") }}
	response, err := client.Do(call)
	if err != nil {
		return true, errors.New("captured MTU controller is unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var result mtuOwnerReply
	if err != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || decodeRelayControlJSON(body, &result) != nil || result.Owner != token || !validMTUKernelState(mtuKernelState{Interface: result.Interface, Family: result.Family, Index: result.Index, MTU: result.MTU, Identity: result.Identity}) {
		return true, errors.New("captured MTU operation was rejected or its readback was invalid")
	}
	if request["action"] == "set" && result.MTU != request["mtu"] {
		return true, errors.New("MTU operation returned a different value")
	}
	_, err = fmt.Fprintln(os.Stdout, string(bytes.TrimSpace(body)))
	return true, err
}
