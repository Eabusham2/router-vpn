//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
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
	if action != "1" {
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
	if err = a.stopMode(); err != nil {
		return fmt.Errorf("shipping service Stop failed: %w", err)
	}
	if a.state.Connected || a.cmd != nil || !owner.joined {
		return errors.New("shipping original remote cleanup did not join before Off")
	}
	if _, err = os.Stat(filepath.Join(root, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("shipping On-connect Stop retained its state after acknowledged service release")
	}
	fmt.Fprintln(os.Stdout, "standard-service-route-joined")
	return nil
}
