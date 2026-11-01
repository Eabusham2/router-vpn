//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	"router-vpn/internal/mobilemtu"
)

type linuxHostTUNMTUViewResult struct {
	EffectiveMTU int    `json:"effective_mtu"`
	Automatic    bool   `json:"automatic"`
	Source       string `json:"source"`
}

// This enters the same status route as the application while the completed
// native bundle owns its real TUN. Fixed and Auto both report kernel-backed
// readback; neither historical9000 nor the configured value substitutes for it.
func linuxHostTUNMTUView(ctx context.Context, a *app, host *desktopLinuxNodeHost) (linuxHostTUNMTUViewResult, error) {
	var empty linuxHostTUNMTUViewResult
	if err := host.Current(ctx); err != nil {
		return empty, err
	}
	tracker := sessionTrackerFor(a)
	tracker.observe(tracker.capture())
	session := tracker.snapshot(0)
	read := func(query string) (*httptest.ResponseRecorder, mobilemtu.Status, bool, bool, error) {
		response := httptest.NewRecorder()
		a.desktopMTUStatus(response, httptest.NewRequest(http.MethodGet, "/api/mtu/status"+query, nil).WithContext(ctx))
		var value struct {
			Session   string           `json:"session_id"`
			Profile   string           `json:"profile_id"`
			Requested bool             `json:"requested"`
			Waiting   bool             `json:"waiting_commit"`
			Allowed   *bool            `json:"optimization_allowed"`
			Status    mobilemtu.Status `json:"status"`
		}
		if response.Code != http.StatusOK {
			return response, value.Status, false, false, nil
		}
		if json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Session != session.ID || value.Profile != host.launch.profileID || value.Allowed == nil || value.Waiting {
			return response, value.Status, false, false, errors.New("installed MTU view changed its proved session or policy identity")
		}
		return response, value.Status, *value.Allowed, value.Requested, nil
	}
	response, status, allowed, requested, err := read("?session_id=" + session.ID)
	if err != nil || response.Code != http.StatusOK || status.Phase != "idle" || status.Source != "live-captured-interface" || status.Measured || status.Complete || status.Running || status.Restored || status.Request != "" || requested || len(status.Candidates) != 0 {
		return empty, errors.Join(err, errors.New("installed MTU view did not return its actual idle interface readback: "+response.Body.String()))
	}
	if err := host.enter(ctx); err != nil {
		return empty, err
	}
	_, native, readErr := host.readReadyLocked(ctx, false)
	profile, profileErr := host.capturedProofProfile()
	host.gate <- struct{}{}
	if readErr != nil || profileErr != nil || status.EffectiveMTU != native.MTU || status.EffectiveMTU == 9000 || allowed != strings.EqualFold(strings.TrimSpace(profile.MTUPolicy), "auto") {
		return empty, errors.Join(readErr, profileErr, errors.New("installed MTU view substituted a saved value or changed Fixed/Auto authority"))
	}
	for query, expected := range map[string]int{"?session_id=replacement-session": http.StatusConflict, "?request_id=" + strings.Repeat("c", 32): http.StatusNotFound} {
		response, _, _, _, err := read(query)
		if err != nil || response.Code != expected {
			return empty, errors.New("installed MTU view adopted a foreign session or request")
		}
	}
	if err := host.Current(ctx); err != nil {
		return empty, err
	}
	return linuxHostTUNMTUViewResult{EffectiveMTU: status.EffectiveMTU, Automatic: allowed, Source: status.Source}, nil
}
