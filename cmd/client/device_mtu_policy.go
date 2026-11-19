package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
)

// Device policy is separate from imported nodes and saved connection profiles.
// Zero keeps their original per-configuration policy. A fixed value applies to
// the one client interface; it never rewrites any independent peer envelope.
type deviceMTUPolicy struct {
	Schema   int    `json:"schema"`
	Revision string `json:"revision"`
	FixedMTU int    `json:"fixed_mtu"`
}

type deviceMTUCapture struct {
	app    *app
	path   string
	policy deviceMTUPolicy
	token  string
}

type deviceMTUContextKey struct{}

var deviceMTURevisionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func deviceMTUPolicyPath(a *app) string {
	if a == nil || strings.TrimSpace(a.cfg.ProfilesFile) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Clean(a.cfg.ProfilesFile)), "device-mtu.json")
}

func deviceMTUValueValid(value int) bool { return value == 0 || value >= 1280 && value <= 9000 }

func (p deviceMTUPolicy) token() string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Reject duplicate fields as well as unknown fields and trailing objects.
// These small settings objects do not have an extension or merge namespace.
func decodeDeviceMTUObject(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("device MTU settings require a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		field, err := decoder.Token()
		key, valid := field.(string)
		if err != nil || !valid || seen[key] {
			return errors.New("device MTU settings contain a repeated or invalid field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("device MTU settings contain trailing data")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func captureDeviceMTUPolicy(a *app) (*deviceMTUCapture, error) {
	path := deviceMTUPolicyPath(a)
	policy := deviceMTUPolicy{Schema: 1}
	if path != "" {
		raw, err := readPrivateRegular(path, 4096)
		if err == nil {
			var stored struct {
				Schema   *int    `json:"schema"`
				Revision *string `json:"revision"`
				FixedMTU *int    `json:"fixed_mtu"`
			}
			if err := decodeDeviceMTUObject(raw, &stored); err != nil || stored.Schema == nil || *stored.Schema != 1 ||
				stored.Revision == nil || !deviceMTURevisionPattern.MatchString(*stored.Revision) || stored.FixedMTU == nil || !deviceMTUValueValid(*stored.FixedMTU) {
				return nil, errors.New("device MTU preference is invalid; restore its saved settings before connecting")
			}
			policy = deviceMTUPolicy{Schema: *stored.Schema, Revision: *stored.Revision, FixedMTU: *stored.FixedMTU}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return &deviceMTUCapture{app: a, path: path, policy: policy, token: policy.token()}, nil
}

func (capture *deviceMTUCapture) current() error {
	if capture == nil || capture.app == nil || capture.path != deviceMTUPolicyPath(capture.app) {
		return errors.New("connection lost its captured device MTU preference")
	}
	current, err := captureDeviceMTUPolicy(capture.app)
	if err != nil || current.token != capture.token {
		return errors.Join(err, errors.New("device MTU preference changed after this connection was captured"))
	}
	return nil
}

func deviceMTUForContext(ctx context.Context) *deviceMTUCapture {
	if ctx == nil {
		return nil
	}
	capture, _ := ctx.Value(deviceMTUContextKey{}).(*deviceMTUCapture)
	return capture
}

func (capture *deviceMTUCapture) requireConfig(raw []byte) error {
	if err := capture.current(); err != nil {
		return err
	}
	if capture.policy.FixedMTU == 0 {
		return nil
	}
	plan, err := mobilemtu.NewDeviceFixedPlan(string(raw), capture.policy.FixedMTU)
	if err != nil {
		return err
	}
	if _, err := plan.Config(capture.policy.FixedMTU); err != nil {
		return err
	}
	return capture.current()
}

// Temporary comparisons retain the running connection's original preference.
// Their restoration lifetime must not capture a newer device setting after a
// test has already stopped the original tunnel.
func (a *app) captureTemporaryDeviceMTU() (*deviceMTUCapture, error) {
	return a.captureCurrentDeviceMTU(context.Background())
}

func (a *app) captureCurrentDeviceMTU(ctx context.Context) (*deviceMTUCapture, error) {
	if a == nil {
		return nil, errors.New("device MTU preference has no controller")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	capture := a.deviceMTU
	a.mu.Unlock()
	return a.recheckDeviceMTU(ctx, capture)
}

// A temporary operation supplies the exact pointer observed alongside its
// original session state, before it released the application lock.
func (a *app) recheckDeviceMTU(ctx context.Context, capture *deviceMTUCapture) (*deviceMTUCapture, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var err error
	if capture == nil {
		capture, err = captureDeviceMTUPolicy(a)
		if err != nil {
			return nil, err
		}
	}
	if capture.app != a {
		return nil, errors.New("device MTU belongs to another controller")
	}
	err = capture.current()
	if err = errors.Join(err, ctx.Err()); err != nil {
		return nil, err
	}
	return capture, nil
}

// Only the disposable client TUN projection changes. The original profile,
// packet peers, imported credentials and intermediate envelopes stay intact.
func projectCapturedDeviceMTU(ctx context.Context, graph map[string]any, profile common.RouterProfile) (map[string]any, error) {
	capture := deviceMTUForContext(ctx)
	if capture == nil {
		return graph, nil
	}
	if err := capture.current(); err != nil {
		return nil, err
	}
	value := capture.policy.FixedMTU
	if value == 0 {
		return graph, nil
	}
	if profile.SocksEnabled || profile.JumboTUN && value != 9000 {
		return nil, errors.New("device-wide fixed MTU conflicts with this connection's SOCKS-only or Jumbo choice")
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	// Reopen JSON to use exactly the same numeric representation as the native
	// compiler rather than accepting unrelated in-memory map shapes.
	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		return nil, err
	}
	inbounds, ok := original["inbounds"].([]any)
	if !ok {
		return nil, errors.New("device-wide fixed MTU requires its actual client TUN")
	}
	actual := 0
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || inbound["type"] != "tun" {
			continue
		}
		number, ok := inbound["mtu"].(float64)
		if actual != 0 || !ok || number != float64(int(number)) || number < 1280 || number > 9000 {
			return nil, errors.New("device-wide fixed MTU needs one exactly configured client TUN")
		}
		actual = int(number)
	}
	if profile.JumboTUN && value == 9000 && actual == 9000 {
		return graph, capture.current()
	}
	plan, err := mobilemtu.NewDeviceFixedPlan(string(raw), actual)
	if err != nil {
		return nil, err
	}
	projected, err := plan.Config(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(projected), &result); err != nil {
		return nil, err
	}
	return result, capture.current()
}

// Reject an older unowned adapter before it can retire a live connection.
// Its per-configuration behavior is unchanged; a global fixed choice requires
// the same native proof and actual interface readback as the shipped app.
func (a *app) requireDeviceMTUNativeOwner(ctx context.Context, owned bool) error {
	if a == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("fixed MTU admission requires its original live connection")
	}
	capture := deviceMTUForContext(ctx)
	if capture == nil {
		var err error
		capture, err = captureDeviceMTUPolicy(a)
		if err != nil {
			return err
		}
		if capture.policy.FixedMTU != 0 {
			return errors.New("fixed device MTU lost its original connection preference")
		}
	}
	if capture.app != a {
		return errors.New("fixed MTU admission lost its original application")
	}
	if err := capture.current(); err != nil {
		return err
	}
	if capture.policy.FixedMTU != 0 && !owned {
		return errors.New("this older connection adapter cannot verify the fixed device MTU; use this node from Add / select node in the current Router VPN app")
	}
	return ctx.Err()
}

func (a *app) deviceMTULaunchEnvironment(ctx context.Context, original []string, jumbo, socks bool) ([]string, error) {
	capture := deviceMTUForContext(ctx)
	if capture == nil {
		var err error
		capture, err = captureDeviceMTUPolicy(a)
		if err != nil || capture.policy.FixedMTU != 0 {
			return nil, errors.Join(err, errors.New("legacy connection lost its captured device MTU preference"))
		}
	}
	if err := capture.current(); err != nil {
		return nil, err
	}
	if capture.policy.FixedMTU != 0 && (socks || jumbo && capture.policy.FixedMTU != 9000) {
		return nil, errors.New("device-wide fixed MTU conflicts with this connection's SOCKS-only or Jumbo choice")
	}
	env := make([]string, 0, len(original)+3)
	for _, item := range original {
		key, _, _ := strings.Cut(item, "=")
		if key == "HOMEVPN_DEVICE_MTU" || strings.HasPrefix(key, "HOMEVPN_DEVICE_MTU_") || capture.policy.FixedMTU != 0 && key == "HOMEVPN_MTU" {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "HOMEVPN_DEVICE_MTU="+strconv.Itoa(capture.policy.FixedMTU), "HOMEVPN_DEVICE_MTU_REVISION="+capture.policy.Revision)
	if capture.policy.FixedMTU != 0 {
		env = append(env, "HOMEVPN_MTU="+strconv.Itoa(capture.policy.FixedMTU))
	}
	return env, nil
}

func (a *app) deviceMTUSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		release, err := a.beginMutationOperation(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer release()
	}
	capture, err := captureDeviceMTUPolicy(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if r.Method == http.MethodPost {
		var request struct {
			Token    string `json:"token"`
			FixedMTU *int   `json:"fixed_mtu"`
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil || decodeDeviceMTUObject(raw, &request) != nil || request.FixedMTU == nil ||
			!deviceMTUValueValid(*request.FixedMTU) || request.Token == "" {
			http.Error(w, "use the captured token and a fixed_mtu of 0 or 1280 through 9000", http.StatusBadRequest)
			return
		}
		if request.Token != capture.token || capture.path == "" {
			http.Error(w, "device MTU settings changed; reopen Settings", http.StatusConflict)
			return
		}
		var revision [16]byte
		if _, err := rand.Read(revision[:]); err != nil {
			http.Error(w, "could not capture the new device preference", http.StatusInternalServerError)
			return
		}
		policy := deviceMTUPolicy{Schema: 1, Revision: hex.EncodeToString(revision[:]), FixedMTU: *request.FixedMTU}
		body, _ := json.Marshal(policy)
		if err := desktopnetwork.LockContext(r.Context(), &a.mu); err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		if a.controllerClosingLocked() || profileSettingsBusy(a.state.Connected, a.state.Phase) || a.profileCatalogEpoch == ^uint64(0) {
			a.mu.Unlock()
			http.Error(w, "wait for Router VPN to be idle before changing device MTU", http.StatusConflict)
			return
		}
		_, err = atomicWritePrivateChecked(capture.path, body, func() error {
			return errors.Join(r.Context().Err(), capture.current())
		})
		if err == nil {
			// Even A -> B -> A settings changes retire old draft captures.
			a.profileCatalogEpoch++
			a.deviceMTU = nil
		}
		a.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		cancelPendingStartupPolicy(a)
		capture = &deviceMTUCapture{app: a, path: capture.path, policy: policy, token: policy.token()}
	}
	if err := desktopnetwork.LockContext(r.Context(), &a.mu); err != nil {
		http.Error(w, err.Error(), http.StatusRequestTimeout)
		return
	}
	editable := !a.controllerClosingLocked() && !profileSettingsBusy(a.state.Connected, a.state.Phase)
	a.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": capture.token, "revision": capture.policy.Revision, "fixed_mtu": capture.policy.FixedMTU,
		"editable": editable,
		"note":     "Fixed for all applies to the client interface on this device at the next connection. Each path must support the exact value. Saved node settings stay intact. Choose 0 to use each configuration's MTU and Retest.",
	})
}

// Automatic work and explicit Retest may not displace the fixed device choice.
// A failed source read is not permission to run an optimizer on that session.
func (a *app) deviceMTUAllowsOptimization() bool {
	capture, err := a.captureTemporaryDeviceMTU()
	return err == nil && capture.policy.FixedMTU == 0
}
