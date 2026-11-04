//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"time"
)

// The namespace caller installed a real executable fixture for engine
// lifetime. Only Internet/DNS proof is outside this lifecycle case; the public
// route, production remote constructor/RPC and native owner/Stop all execute.
func linuxStandardServiceControllerRouteFixture(owned *linuxOwnedController, action string) error {
	root := linuxOwnedControllerRoot
	a := &app{localController: owned, cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes"), StateFile: filepath.Join(root, "state.json")}}
	body, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
	if err != nil {
		return err
	}
	if err = decodeRelayControlJSON(body, &a.profiles); err != nil {
		return err
	}
	for i := range a.profiles.Profiles {
		applyProfileDefaults(&a.profiles.Profiles[i])
	}
	a.state = state{Mode: "off", Phase: "off"}
	if action == "off" {
		get := httptest.NewRecorder()
		a.profileProtectionSettings(get, httptest.NewRequest(http.MethodGet, "/api/profile/protection", nil))
		var view profileProtectionSettings
		if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &view) != nil || view.ProtectionStatus != "retained" || view.EffectivePolicy != "always" {
			return fmt.Errorf("actual service-held boot Always was invisible: %d %s", get.Code, get.Body.String())
		}
		body, _ := json.Marshal(map[string]string{"profile_id": view.ProfileID, "profile_token": view.ProfileToken, "kill_switch_policy": "off"})
		post := httptest.NewRecorder()
		a.profileProtectionSettings(post, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)))
		if post.Code != http.StatusOK {
			return fmt.Errorf("actual boot creator UI Off failed: %d %s", post.Code, post.Body.String())
		}
		if _, err := os.Lstat(filepath.Join(root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("UI Off did not retire original native saved state")
		}
		saved, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
		var store common.RouterProfileStore
		if err != nil || json.Unmarshal(saved, &store) != nil || len(store.Profiles) != 1 || store.Profiles[0].KillSwitch || store.Profiles[0].KillSwitchPolicy != "off" {
			return errors.New("UI Off did not persist actual original result")
		}
		fmt.Fprintln(os.Stdout, "standard-service-route-joined")
		return nil
	}
	if action != "1" && action != "failure" {
		return errors.New("unknown native service fixture action")
	}
	body, err = os.ReadFile(filepath.Join(root, "modes.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(body, &a.modes); err != nil {
		return err
	}
	exit := validTestStandardExit("socks5")
	request, _ := json.Marshal(standardExitConnectRequest{StandardExitID: exit.ID, Direct: true})
	response := httptest.NewRecorder()
	a.platformStandardExitConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(request)), platformStandardExitRuntime{
		prepareLegacy: prepareLegacyStandardExitOwner,
		prove:         func(*app, string) error { return nil },
		proveDNS: func(_ context.Context, captured legacyStandardExitLaunch) error {
			// This case proves process/protection/RPC lifecycle only. The
			// separate pinned-core native gate exercises real selected DNS.
			owner := captured.(*linuxStandardServiceLaunch)
			owner.mu.Lock()
			owner.dnsProved = true
			owner.mu.Unlock()
			return nil
		},
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	})
	if response.Code != http.StatusOK {
		return fmt.Errorf("shipping service Connect failed: %d %s", response.Code, response.Body.String())
	}
	raw, exists := linuxStandardServiceOwners.Load(a)
	owner, ok := raw.(*linuxStandardServiceLaunch)
	if !exists || !ok || owner.Command().Process != nil || !a.state.Connected {
		return errors.New("shipping controller did not retain actual remote engine ownership")
	}
	if action == "failure" {
		if err = linuxStandardServiceControllerFailureFixture(a, owner); err != nil {
			return err
		}
	}
	if err = a.stopMode(); err != nil {
		return fmt.Errorf("shipping service Stop failed: %w", err)
	}
	if a.state.Connected || a.cmd != nil || !owner.joined {
		return errors.New("shipping original remote cleanup did not join before Off")
	}
	if _, err = os.Stat(filepath.Join(root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("shipping On-connect Stop retained its state after acknowledged service release")
	}
	if action == "failure" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		view := a.captureLinuxStandardServiceProtection(ctx)
		if view == nil || !view.Available || view.Failure != nil || view.Owned || view.Active || !view.AbsenceProved {
			return errors.New("explicit Stop did not prove original service protection absence")
		}
	}
	fmt.Fprintln(os.Stdout, "standard-service-route-joined")
	return nil
}

// The controller monitor is joined before the cooperative child exit, so only
// the original service watcher can perform this automatic retirement. The
// protection-view RPC validates the service's live creator, not saved metadata.
func linuxStandardServiceControllerFailureFixture(a *app, owner *linuxStandardServiceLaunch) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, exists := linuxStandardServiceMonitors.Load(owner)
	monitor, ok := raw.(*linuxStandardServiceMonitor)
	if !exists || !ok || monitor.owner != owner {
		return errors.New("service failure fixture lost original controller monitor")
	}
	if err := owner.stopMonitor(ctx); err != nil {
		return err
	}
	select {
	case <-monitor.finished:
	case <-ctx.Done():
		return errors.New("original controller monitor did not join before engine exit")
	}
	owner.mu.Lock()
	joined := owner.joined
	owner.mu.Unlock()
	if joined {
		return errors.New("controller cleanup substituted for service-side retirement")
	}
	original := a.captureLinuxStandardServiceProtection(ctx)
	if original == nil || !original.Available || original.Failure != nil || !original.Owned || !original.Active || original.Pending || original.Removed || original.Policy != "on-connect" {
		return errors.New("actual service had no original active On-connect creator")
	}
	owner.mu.Lock()
	sameService := original.client != nil && original.client.peer != nil && owner.peer != nil && original.client.peer.record == owner.peer.record
	owner.mu.Unlock()
	if !sameService {
		return errors.New("protection observation replaced the original engine service peer")
	}
	statePath := filepath.Join(linuxOwnedControllerRoot, "run", "kill-switch.json")
	saved, err := os.Open(statePath)
	if err != nil {
		return err
	}
	defer saved.Close()
	info, err := saved.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return errors.New("original native saved protection was not bounded and regular")
	}
	body, err := io.ReadAll(io.LimitReader(saved, (64<<10)+1))
	var state legacyExitProtectionState
	if err != nil || json.Unmarshal(body, &state) != nil || state.Policy != "on-connect" || state.Owner.Receipt.Session != owner.request.Session || state.Owner.Receipt.ConfigSHA256 != owner.request.ConfigSHA256 || state.Owner.Receipt.TableHandle == 0 {
		return errors.New("original service saved protection lost its acknowledged creation")
	}
	sentinel, err := os.OpenFile(filepath.Join(linuxOwnedControllerRoot, "run", "standard-service-fixture-exit"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = sentinel.Close(); err != nil {
		return err
	}
	for {
		view := a.captureLinuxStandardServiceProtection(ctx)
		if !original.same(view) || !view.Owned || view.Pending || view.Removed || view.AbsenceProved {
			return errors.New("automatic service retirement released or replaced original On-connect creator")
		}
		if !view.Active {
			break // The service reports this only after its original retirement joined.
		}
		select {
		case <-ctx.Done():
			return errors.New("service did not join the original cooperatively retired engine")
		case <-time.After(20 * time.Millisecond):
		}
	}
	named, err := os.Lstat(statePath)
	after, readErr := os.ReadFile(statePath)
	if err != nil || readErr != nil || !os.SameFile(info, named) || !bytes.Equal(body, after) {
		return errors.New("automatic retirement lost the exact original saved protection inode or body")
	}
	stopped, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "engine-stopped"))
	if err != nil || string(stopped) != "closed" {
		return errors.New("service retirement missed actual cooperative fixture exit")
	}
	if _, err = os.Lstat(owner.request.Directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("service claimed joined engine before original workspace retirement")
	}
	owner.mu.Lock()
	err = owner.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "current", Session: owner.request.Session}, nil)
	joined = owner.joined
	owner.mu.Unlock()
	if err == nil || joined {
		return errors.New("retired service engine stayed current or controller cleanup substituted for service watch")
	}
	return nil
}
