package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"

	"router-vpn/internal/common"
)

type internalMutationContextKey struct{}

var errConnectionOperationCancelled = errors.New("connection request was cancelled before it could adopt a runtime")

func withInternalMutationContext(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), internalMutationContextKey{}, true))
}

func hasInternalMutationContext(r *http.Request) bool {
	value, _ := r.Context().Value(internalMutationContextKey{}).(bool)
	return value
}

func (a *app) beginNodeBoundOperation() (func(), error) {
	if !a.operationMu.TryLock() {
		return nil, errors.New("another Router VPN connection or settings transaction is already in progress")
	}
	return a.operationMu.Unlock, nil
}

func (a *app) beginMutationOperation(r *http.Request) (func(), error) {
	if hasInternalMutationContext(r) {
		return func() {}, nil
	}
	if !a.operationMu.TryLock() {
		return nil, errors.New("another Router VPN connection or settings transaction is already in progress")
	}
	a.mu.Lock()
	busy := profileSettingsBusy(a.state.Connected, a.state.Phase)
	a.mu.Unlock()
	if busy {
		a.operationMu.Unlock()
		return nil, errors.New("disconnect and wait for Router VPN to become fully idle before changing session or profile state")
	}
	return a.operationMu.Unlock, nil
}

func preflightPrivateConnectionRuntime() error {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	for _, category := range []string{
		"native-standard-exit",
		"native-multihop",
		"openvpn-standard-exit",
	} {
		if _, err := privateRuntimeBase(root, category); err != nil {
			return fmt.Errorf("private connection runtime %s is unsafe: %w", category, err)
		}
	}
	return nil
}

func (a *app) beginConnectionOperation() (context.Context, func(), error) {
	if !a.operationMu.TryLock() {
		return nil, nil, errors.New("another Router VPN connection or settings transaction is already in progress")
	}
	a.mu.Lock()
	busy := profileSettingsBusy(a.state.Connected, a.state.Phase)
	a.mu.Unlock()
	if busy {
		a.operationMu.Unlock()
		return nil, nil, errors.New("Router VPN is connected or transitioning; disconnect before starting another connection")
	}

	// Validate/create every secret-bearing desktop runtime root before recording
	// Phase=requested or starting any helper. A poisoned run/ tree therefore
	// fails closed without changing connection state or touching the network.
	if err := preflightPrivateConnectionRuntime(); err != nil {
		a.operationMu.Unlock()
		return nil, nil, err
	}

	// Re-check under the app lock after filesystem validation before publishing
	// connection context/state. operationMu keeps competing Router VPN operations
	// out, while this second check protects against any independent state change.
	a.mu.Lock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		a.operationMu.Unlock()
		return nil, nil, errors.New("Router VPN state changed while validating private connection runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.connectionContext = ctx
	a.connectionCancel = cancel
	a.state.Phase = "requested"
	a.mu.Unlock()
	finish := func() {
		cancel()
		a.mu.Lock()
		if a.connectionContext == ctx {
			a.connectionContext = nil
			a.connectionCancel = nil
			if !a.state.Connected && a.state.Phase == "requested" {
				a.state.Phase = "off"
			}
		}
		a.mu.Unlock()
		a.operationMu.Unlock()
	}
	return ctx, finish, nil
}

func (a *app) connectionOperationContextOrBackground() context.Context {
	a.mu.Lock()
	ctx := a.connectionContext
	a.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (a *app) checkConnectionOperation() error {
	if err := a.connectionOperationContextOrBackground().Err(); err != nil {
		return errConnectionOperationCancelled
	}
	return nil
}

func (a *app) cancelConnectionOperation() {
	a.mu.Lock()
	cancel := a.connectionCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func cloneRouterProfileStore(store common.RouterProfileStore) common.RouterProfileStore {
	cloned := store
	cloned.Profiles = append([]common.RouterProfile(nil), store.Profiles...)
	return cloned
}

func (a *app) rollbackProfilesLocked(previous common.RouterProfileStore) {
	a.profiles = cloneRouterProfileStore(previous)
}

func (a *app) ownsConnectionRuntime(cmd *exec.Cmd) bool {
	a.mu.Lock()
	owned := cmd != nil && a.cmd == cmd
	a.mu.Unlock()
	return owned
}

func (a *app) stopOwnedConnectionRuntime(cmd *exec.Cmd) {
	if a.ownsConnectionRuntime(cmd) {
		_ = a.stopMode()
	}
}
