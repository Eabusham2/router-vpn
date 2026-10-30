package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
)

type nativeControllerAdmissionFixture struct {
	captured, alive atomic.Bool
	closed          atomic.Int32
	config          common.ClientConfig
}

func (f *nativeControllerAdmissionFixture) Captured() bool { return f.captured.Load() }
func (f *nativeControllerAdmissionFixture) Alive() error {
	if !f.alive.Load() {
		return errors.New("captured parent ended")
	}
	return nil
}
func (f *nativeControllerAdmissionFixture) Close() error { f.closed.Add(1); return nil }
func (f *nativeControllerAdmissionFixture) CaptureConfiguration(config common.ClientConfig) (common.ClientConfig, error) {
	f.config = config
	config.StateFile = "canonical-captured-state"
	return config, nil
}
func (f *nativeControllerAdmissionFixture) CaptureModes(modes []common.Mode) ([]common.Mode, error) {
	return modes, nil
}

func TestLocalControllerNativeOwnerRevokesWritesButRetainsPinnedDrain(t *testing.T) {
	native := &nativeControllerAdmissionFixture{}
	native.captured.Store(true)
	native.alive.Store(true)
	owner := testLocalControllerOwner()
	owner.callerUID = 0
	owner.nativeOwner = native
	identity, err := controllertransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner.pinnedTLS = identity
	server := httptest.NewTLSServer(owner.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })))
	defer server.Close()
	request := func(path, authorization string) int {
		status, _, _ := testLocalControllerRequest(t, server.Client(), server.URL, http.MethodGet, path, authorization, nil)
		return status
	}
	if status := request("/api/status", "Bearer "+owner.accessToken); status != http.StatusAccepted {
		t.Fatal("captured native caller was replaced by a fabricated Unix UID", status)
	}
	native.alive.Store(false)
	if status := request("/api/status", "Bearer "+owner.accessToken); status != http.StatusServiceUnavailable {
		t.Fatal("retired native caller retained bearer authority", status)
	}
	if status := request(controllertransport.DrainPath, ""); status != http.StatusAccepted {
		t.Fatal("parent retirement blocked the exact pinned read-only drain", status)
	}
	native.captured.Store(false)
	if status := request(controllertransport.DrainPath, ""); status != http.StatusForbidden {
		t.Fatal("missing native capture acquired read-only authority", status)
	}
	native.captured.Store(true)
	native.alive.Store(true)
	owner.callerUID = 1234
	if status := request("/api/status", "Bearer "+owner.accessToken); status != http.StatusForbidden {
		t.Fatal("mixed Unix/native identity acquired controller authority", status)
	}
}

func TestLocalControllerNativeOwnerOwnsConfigurationAndClose(t *testing.T) {
	native := &nativeControllerAdmissionFixture{}
	owner := &ownedDesktopController{nativeOwner: native}
	config := common.ClientConfig{Listen: linuxOwnedControllerAddress, StateFile: "captured-state"}
	if err := owner.validateConfiguration(&config); err != nil || native.config.StateFile != "captured-state" || config.StateFile != "canonical-captured-state" {
		t.Fatal("native data-layout validator was bypassed", err)
	}
	owner.close()
	owner.close()
	if native.closed.Load() != 1 {
		t.Fatal("controller close lost its exact native resource owner")
	}
}
