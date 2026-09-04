package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type torBridgeConnectRequest struct {
	ProfileID string `json:"profile_id"`
}

func registerTorBridgeRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/tor-bridge/connect", a.torBridgeConnect)
}

func (a *app) torBridgeConnect(w http.ResponseWriter, r *http.Request) {
	_, finish, guardErr := a.beginConnectionOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer finish()
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q torBridgeConnectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	profileID := strings.TrimSpace(q.ProfileID)
	if !validProfileID(profileID) {
		http.Error(w, "Tor bridge connect requires an explicit valid profile_id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "Tor bridge profile not found", http.StatusNotFound)
		return
	}
	a.torBridgeConnectOwned(w, profile)
}

// torBridgeConnectOwned assumes the caller already owns beginConnectionOperation.
// This lets the unified external-profile route dispatch Tor without nested locks.
func (a *app) torBridgeConnectOwned(w http.ResponseWriter, profile common.RouterProfile) {
	_, torCfg, _, _, profileErr := torBridgeProfile(profile)
	if profileErr != nil {
		http.Error(w, profileErr.Error(), http.StatusBadRequest)
		return
	}
	cap := torBridgeRuntimeCapability()
	if !cap.Supported {
		http.Error(w, cap.Reason, http.StatusNotImplemented)
		return
	}
	policy, err := externalRuntimePolicy(profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionTrackerFor(a).declareRequest("external-node", "tor")
	if err = a.stopMode(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cmd, err := torBridgeCommand(a, policy, profile)
	if err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err = a.checkConnectionOperation(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err = cmd.Start(); err != nil {
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.cmd = cmd
	a.state.Mode = "external-node"
	a.state.LogicalMode = "external-node"
	a.state.RuntimeMode = "external-tor-bridge"
	a.state.Base = "tor"
	a.state.RouterID = profile.ID
	a.state.Connected = false
	a.state.Phase = "tor-bridge:bootstrapping"
	a.state.LastError = ""
	a.mu.Unlock()
	if err = a.checkConnectionOperation(); err != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	a.mu.Lock()
	if a.cmd == cmd {
		a.state.Phase = "tor-bridge:proving-exit"
	}
	a.mu.Unlock()
	actualIP, proofErr := a.proveTorBridgeExit()
	if cancelErr := a.checkConnectionOperation(); cancelErr != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(cancelErr.Error())
		http.Error(w, cancelErr.Error(), http.StatusConflict)
		return
	}
	if proofErr != nil {
		a.stopOwnedConnectionRuntime(cmd)
		message := "Tor bridge public-exit proof failed: " + proofErr.Error()
		a.mu.Lock()
		a.state.Mode = "external-node"
		a.state.LogicalMode = "external-node"
		a.state.RuntimeMode = "external-tor-bridge"
		a.state.Base = "tor"
		a.state.RouterID = profile.ID
		a.state.Connected = false
		a.state.Phase = "failed"
		a.state.LastError = message
		a.mu.Unlock()
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusBadGateway)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	a.mu.Lock()
	if a.cmd != cmd {
		a.mu.Unlock()
		a.stopOwnedConnectionRuntime(cmd)
		message := "Tor bridge runtime changed before dynamic exit proof could be adopted"
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	found := false
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == profile.ID {
			a.profiles.Profiles[i].UseCount++
			a.profiles.Profiles[i].LastUsedAt = now
			a.profiles.Profiles[i].PublicIP = actualIP
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		a.stopOwnedConnectionRuntime(cmd)
		message := "Tor bridge profile disappeared before result adoption"
		sessionTrackerFor(a).markRequestFailure(message)
		http.Error(w, message, http.StatusConflict)
		return
	}
	a.state.Connected = true
	a.state.Phase = "connected"
	a.state.LastError = ""
	persistErr := a.persistProfilesLocked()
	if persistErr != nil {
		a.rollbackProfilesLocked(previousStore)
		a.state.Connected = false
		a.state.Phase = "failed"
		a.state.LastError = persistErr.Error()
	}
	a.mu.Unlock()
	if persistErr != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(persistErr.Error())
		http.Error(w, "Tor bridge path was proved but observed-exit/usage persistence failed; runtime was torn down: "+persistErr.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.checkConnectionOperation(); err != nil {
		a.stopOwnedConnectionRuntime(cmd)
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	transport := strings.TrimSpace(torCfg.Transport)
	if transport == "" {
		transport = "custom"
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true,
		"mode": "external-node",
		"profile_id": profile.ID,
		"profile_name": profile.Name,
		"protocol": "tor-bridge",
		"tor_transport": transport,
		"direct": true,
		"actual_public_ip": actualIP,
		"actual_exit_proof": "tor-project-is-tor-passed",
		"dns_mode": policy.DNSMode,
		"route": "client full-device TUN -> local Tor SOCKS -> " + transport + " circumvention transport -> Tor circuit -> dynamic Tor exit -> Internet",
	})
}
