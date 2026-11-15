//go:build darwin && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

const macOSCandidatePrefixMarker = "fixture-node-candidate-prefix-host"
const macOSCandidatePrefixCandidate = "installed-prefix-candidate"

var macOSCandidatePrefixHostCases = []string{
	"wg-save", "wg-cancel", "awg-fast-save", "awg-fast-cancel", "awg-strong-save", "awg-strong-cancel", "wg-off-save", "wg-off-cancel",
}

func macOSCandidatePrefixModes(scenario string) ([]string, string, error) {
	found := false
	for _, value := range macOSCandidatePrefixHostCases {
		found = found || value == scenario
	}
	if !found {
		return nil, "", errors.New("uncaptured native selected-prefix scenario")
	}
	action := scenario[strings.LastIndexByte(scenario, '-')+1:]
	switch strings.TrimSuffix(scenario, "-"+action) {
	case "wg", "wg-off":
		return []string{"wg", "wg"}, action, nil
	case "awg-fast":
		return []string{"awg2-fast", "wg"}, action, nil
	case "awg-strong":
		return []string{"awg2-strong", "awg2-fast"}, action, nil
	}
	return nil, "", errors.New("native selected-prefix mode unavailable")
}

// Retain the full original Save provenance, but its old final port is unopened.
// Only the separately saved candidate can receive the fifty TCP handshakes.
func macOSCandidatePrefixSources(t *testing.T, peer *macOSNodeChainPeer) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	store, assets := macOSNodeChainInstalledSources(t, peer, "")
	final := store.Profiles[len(store.Profiles)-1]
	candidate := cloneRouterProfile(final)
	candidate.ID, candidate.Name = macOSCandidatePrefixCandidate, "Independent saved prefix candidate"
	candidate.MultihopEnabled = false
	candidate.MultihopNodes = nil
	candidate.MultihopEntryID, candidate.MultihopExitID, candidate.MultihopEntryMode = "", "", ""
	if err := common.NormalizeRouterProfile(&candidate); err != nil {
		t.Fatal(err)
	}
	assets[candidate.ID] = map[string]map[string][]byte{}
	for mode, files := range assets[final.ID] {
		assets[candidate.ID][mode] = map[string][]byte{}
		for name, data := range files {
			assets[candidate.ID][mode][name] = append([]byte(nil), data...)
		}
	}
	var original map[string]any
	if json.Unmarshal(assets[final.ID]["shadowsocks"]["sing-box.json"], &original) != nil {
		t.Fatal("missing captured final source")
	}
	original["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	assets[final.ID]["shadowsocks"]["sing-box.json"] = raw
	store.Profiles = append(store.Profiles, candidate)
	return store, assets
}

func macOSCandidatePrefixInstall(t *testing.T, peer *macOSNodeChainPeer, scenario string) common.RouterProfileStore {
	t.Helper()
	// Existing installer supplies the unchanged optimizer/native bundle closure.
	installMacOSNodeChainProfiles(t, peer, "")
	if err := os.Remove(filepath.Join(macOSOwnedControllerRoot, macOSNodeChainNativeMarker)); err != nil {
		t.Fatal(err)
	}
	store, assets := macOSCandidatePrefixSources(t, peer)
	if strings.Contains(scenario, "-off-") {
		for i := range store.Profiles {
			store.Profiles[i].KillSwitch = false
			store.Profiles[i].KillSwitchPolicy = "off"
		}
	}
	raw, err := json.Marshal(store)
	if err != nil || os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"), raw, 0600) != nil {
		t.Fatal("prefix saved source unavailable", err)
	}
	for id, modes := range assets {
		for mode, files := range modes {
			directory := filepath.Join(macOSOwnedControllerRoot, "generated", id, mode)
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, macOSCandidatePrefixMarker), []byte(scenario+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return store
}

// The installed fixture registers the shipping public routes. Only read-only
// ownership observation is added; admission and worker handoff are unchanged.
func macOSCandidatePrefixNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSCandidatePrefixMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	modes, _, caseErr := macOSCandidatePrefixModes(strings.TrimSpace(string(raw)))
	if err != nil || caseErr != nil {
		return true, errors.Join(err, caseErr)
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{
		AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress, ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"),
		ModesFile: filepath.Join(macOSOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(macOSOwnedControllerRoot, "modes"), StateFile: filepath.Join(macOSOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || a.profiles.SelectedID != "installed-ordered-final" || len(a.profiles.Profiles) != len(modes)+2 {
		return true, errors.New("prefix fixture lost full saved original catalog")
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return true, errors.New("prefix fixture lost actual mode catalog")
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	registerOrderedCandidatePreparedRoutes(mux, a)
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller unavailable", 409)
			return
		}
		a.mu.Lock()
		value := a.state
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.HandleFunc("/api/native-prefix-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := macOSCandidatePrefixObservation(r.Context(), a, captured)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		viaEntryJSON(w, value)
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSCandidatePrefixNativeResult struct {
	Session, Source, Config, Transfer, Profile, Policy string
	ProcessID                                          int
	NativeJoined, Closed, WorkspaceRetired, Observer   bool
	Baseline                                           *desktopMacOSCandidatePrefixReceipt
	Proof                                              *mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
}

func macOSCandidatePrefixObservation(ctx context.Context, a *app, captured *desktopMacOSSessionCapture) (macOSCandidatePrefixNativeResult, error) {
	var result macOSCandidatePrefixNativeResult
	control := viaEntryControlFor(a)
	control.mu.Lock()
	owner := control.owner
	if owner == nil || owner.prepared == nil || owner.running || !owner.prepared.nativeDown {
		control.mu.Unlock()
		return result, errors.New("prefix observation requires original joined DOWN")
	}
	p := owner.preparation
	control.mu.Unlock()
	owner.closeMu.Lock()
	defer owner.closeMu.Unlock()
	if p == nil || p.launch == nil || p.launch.candidatePrefix == nil || p.launch.chain != nil || p.runtime == nil {
		return result, errors.New("prefix observation borrowed ordinary graph")
	}
	platform, ok := p.launch.candidatePrefix.platform.(*desktopNodeCandidatePrefixPlatformRuntime)
	if !ok || platform == nil || platform.host == nil {
		return result, errors.New("prefix observation lost native adapter")
	}
	h := platform.host
	if err := h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.parent.parent != captured.parent || h.parent.session != captured.session || h.policy == nil || h.policy.Validate() != nil || h.process == nil || h.process.command == nil || h.process.command.Process == nil {
		return result, errors.New("prefix observation changed original native identity")
	}
	meta := h.policy.Metadata()
	result.Policy = meta.KillSwitchPolicy
	if h.selection.Policy != meta.KillSwitchPolicy {
		return result, errors.New("prefix native baseline changed captured protection")
	}
	result.Session, result.Source, result.Config, result.Profile = meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256, meta.PolicyProfileID
	result.Transfer, _ = macosprocess.CandidatePrefixTransferSHA256(h.process.capture.Selection())
	result.ProcessID = h.process.command.Process.Pid
	result.NativeJoined = h.nativeRetired && h.process.NativeCleanup(ctx) == nil
	result.Closed, result.WorkspaceRetired = h.closed, h.workspaceRetired
	if h.baseline != nil {
		copy := *h.baseline
		result.Baseline = &copy
	}
	p.launch.candidatePrefix.mu.Lock()
	if p.launch.candidatePrefix.ready != nil {
		copy := *p.launch.candidatePrefix.ready
		result.Proof = &copy
	}
	p.launch.candidatePrefix.mu.Unlock()
	result.Observer = !p.down && p.runtime.cohort != nil
	if result.Observer {
		if err := p.reviewCurrent(ctx); err != nil {
			return result, err
		}
	}
	if !result.NativeJoined || !result.Closed || !result.WorkspaceRetired || result.Transfer == "" || result.Transfer != h.transfer || result.Proof == nil || meta.ApplicationOpen || meta.DNSOpen {
		return result, errors.New("prefix DOWN omitted actual original native join or closed proof")
	}
	if _, err := os.Lstat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
		return result, errors.New("prefix workspace did not retire")
	}
	return result, nil
}

func TestMacOSRetainedCandidatePrefixNativeHost(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("prefix native acceptance requires actual disposable authority")
	}
	for _, scenario := range macOSCandidatePrefixHostCases {
		t.Run(scenario, func(t *testing.T) { macOSCandidatePrefixNativeCase(t, scenario) })
	}
}

func macOSCandidatePrefixNativeCase(t *testing.T, scenario string) {
	t.Helper()
	modes, action, err := macOSCandidatePrefixModes(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	peer := startMacOSNodeChainPeer(t, modes)
	macOSExternalNativeTrust(t, &macOSExternalNativePeer{ca: peer.reply.PublicCA})
	store := macOSCandidatePrefixInstall(t, peer, scenario)
	profilesBefore, err := os.ReadFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(macOSOwnedControllerRoot, "state.json")
	stateBefore, stateBeforeErr := os.ReadFile(statePath)
	if stateBeforeErr != nil && !errors.Is(stateBeforeErr, os.ErrNotExist) {
		t.Fatal(stateBeforeErr)
	}
	profileProbe := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json")}}
	connectionBefore, connectionBeforeErr := os.ReadFile(connectionProfileStorePath(profileProbe))
	if connectionBeforeErr != nil && !errors.Is(connectionBeforeErr, os.ErrNotExist) {
		t.Fatal(connectionBeforeErr)
	}
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 150 * time.Second
	ctx, stop := context.WithTimeout(context.Background(), 240*time.Second)
	defer stop()
	joined := false
	id, token := "", ""
	t.Cleanup(func() {
		if joined {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if id != "" {
			body, _ := json.Marshal(map[string]string{"request_id": id, "view_token": token, "scope": orderedCandidateSavedPrefixScope})
			_, _, _ = macOSExternalNativeHTTP(cleanup, client, http.MethodPost, "/api/multihop/saved-candidates/cancel", string(body))
		}
		if err := connection.CloseWrite(); err != nil {
			t.Error(err)
			return
		}
		receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
		joined = true
		if receipt.ExitCode != 0 {
			t.Error("original prefix controller cleanup failed", receipt.ExitCode)
		}
	})
	macOSControllerNativeAwait(t, func() bool {
		call, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		code, _, err := macOSExternalNativeHTTP(call, client, http.MethodGet, "/api/status", "")
		return err == nil && code == 200
	}, "original prefix controller did not start")
	beforeTunnels := macOSExternalNativeTunnels(t)
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/multihop/saved-candidates/catalog?prefix_position=1&scope=saved-prefix-local", "")
	var view struct {
		Token      string                   `json:"view_token"`
		Position   int                      `json:"prefix_position"`
		Candidates []orderedCandidateChoice `json:"candidates"`
	}
	if err != nil || status != 200 || json.Unmarshal(raw, &view) != nil || len(view.Token) != 64 || view.Position != len(modes)-1 {
		t.Fatal("native prefix source view unavailable", status, err, string(raw))
	}
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil || envelope["scope"] != orderedCandidateSavedPrefixScope || envelope["proof_scope"] != "selected-prefix" || envelope["application_open"] != false || envelope["dns_open"] != false || envelope["samples"] != float64(50) {
		t.Fatal("public prefix catalog lost its closed exact purpose", string(raw))
	}
	staleToken := view.Token
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/multihop/saved-candidates/catalog?prefix_position=1&scope=saved-prefix-local", "")
	if err != nil || status != 200 || json.Unmarshal(raw, &view) != nil || len(view.Token) != 64 || view.Token == staleToken || view.Position != len(modes)-1 {
		t.Fatal("public prefix catalog failed to replace its original view", status, err, string(raw))
	}
	token = view.Token
	var choice *orderedCandidateChoice
	for i := range view.Candidates {
		if view.Candidates[i].ID == macOSCandidatePrefixCandidate {
			choice = &view.Candidates[i]
		}
	}
	if choice == nil || choice.SaveReason != "" || len(choice.Proposal) != len(modes)+1 {
		t.Fatal("native prefix candidate lost complete Save provenance", view)
	}
	id, err = randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	request := orderedCandidatePreparedRequestEnvelope{orderedCandidateRequest: orderedCandidateRequest{id, token, view.Position, []string{choice.ID}, 50}, Scope: orderedCandidateSavedPrefixScope}
	body, _ := json.Marshal(request)
	// Malformed and foreign requests cannot consume the original exact view.
	for _, bad := range []orderedCandidatePreparedRequestEnvelope{
		{orderedCandidateRequest: orderedCandidateRequest{id, staleToken, view.Position, []string{choice.ID}, 50}, Scope: orderedCandidateSavedPrefixScope},
		{orderedCandidateRequest: orderedCandidateRequest{id, strings.Repeat("0", 64), view.Position, []string{choice.ID}, 50}, Scope: orderedCandidateSavedPrefixScope},
		{orderedCandidateRequest: orderedCandidateRequest{id, token, view.Position, []string{choice.ID}, 49}, Scope: orderedCandidateSavedPrefixScope},
		{orderedCandidateRequest: orderedCandidateRequest{id, token, view.Position, []string{choice.ID}, 50}, Scope: orderedCandidateSavedCompleteScope},
	} {
		invalid, _ := json.Marshal(bad)
		code, _, requestErr := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/saved-candidates", string(invalid))
		if requestErr != nil || code < 400 {
			t.Fatal("public prefix accepted a foreign or malformed view", code, requestErr)
		}
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/saved-candidates", string(body))
	if err != nil || status != 202 {
		t.Fatal("native prefix original job was not admitted", status, err, string(raw))
	}
	replayStatus, _, replayErr := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/multihop/saved-candidates", string(body))
	if replayErr != nil || replayStatus != http.StatusConflict {
		t.Fatal("public prefix replay acquired another native worker", replayStatus, replayErr)
	}
	const base = "/api/multihop/saved-candidates"
	var result struct {
		RequestID                             string `json:"request_id"`
		ViewToken                             string `json:"view_token"`
		Scope                                 string `json:"scope"`
		Running, Accepted, Reviewing, Drained bool
		Down                                  bool                         `json:"native_down"`
		Cleanup                               bool                         `json:"cleanup_pending"`
		Changed                               bool                         `json:"active_path_changed"`
		ApplicationOpen                       bool                         `json:"application_open"`
		DNSOpen                               bool                         `json:"dns_open"`
		ProofScope                            string                       `json:"proof_scope"`
		Failure                               string                       `json:"failure"`
		Rows                                  []hopmeasure.CandidateStatus `json:"results"`
	}
	for {
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, base+"?request_id="+id, "")
		if err != nil || status != 200 || json.Unmarshal(raw, &result) != nil || result.RequestID != id || result.ViewToken != token || result.Scope != orderedCandidateSavedPrefixScope || result.ProofScope != "selected-prefix" || result.ApplicationOpen || result.DNSOpen || result.Changed {
			t.Fatal("native prefix status changed its closed original purpose", status, err, string(raw))
		}
		var closedEnvelope map[string]any
		if json.Unmarshal(raw, &closedEnvelope) != nil || closedEnvelope["application_open"] != false || closedEnvelope["dns_open"] != false {
			t.Fatal("prefix status omitted explicit closed application/DNS readback", string(raw))
		}
		homeStatus, homeRaw, homeErr := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var home state
		if homeErr != nil || homeStatus != 200 || json.Unmarshal(homeRaw, &home) != nil || home.Connected {
			t.Fatal("native prefix manufactured ordinary Connected", homeErr, string(homeRaw))
		}
		if !result.Running {
			break
		}
		if result.Accepted || result.Reviewing || len(result.Rows) != 0 {
			t.Fatal("native prefix exposed choices before original join", result)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !result.Accepted || !result.Reviewing || !result.Down || result.Drained || result.Cleanup || result.Failure != "" || len(result.Rows) != 1 {
		t.Fatal("native prefix failed actual DOWN review", string(raw))
	}
	row := result.Rows[0]
	if !row.Complete || !row.Drained || row.CandidateID != choice.ID || row.PrefixPosition != view.Position || len(row.Results) != 1 || row.Results[0].Benchmark == nil || row.Results[0].Benchmark.Attempts != 50 || row.Results[0].Benchmark.Distribution == nil || row.Results[0].Benchmark.Distribution.Samples != 50 {
		t.Fatal("native prefix omitted actual fifty-sample receipt", row)
	}
	read := func() macOSCandidatePrefixNativeResult {
		status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-prefix-observation", "")
		var value macOSCandidatePrefixNativeResult
		if err != nil || status != 200 || decodeRelayControlJSON(raw, &value) != nil {
			t.Fatal("prefix native DOWN observation failed", status, err, string(raw))
		}
		return value
	}
	observed := read()
	proof := observed.Proof
	wantPolicy := "on-connect"
	if strings.Contains(scenario, "-off-") {
		wantPolicy = "off"
	}
	if observed.Policy != wantPolicy {
		t.Fatal("native prefix changed selected protection", observed.Policy)
	}
	if !observed.NativeJoined || !observed.Closed || !observed.WorkspaceRetired || !observed.Observer || observed.ProcessID == started.ProcessID || observed.Profile != store.SelectedID || observed.Baseline == nil || observed.Baseline.Phase != "retired" || observed.Baseline.Baseline.Present || proof == nil || !proof.Prepared || proof.ApplicationOpen || proof.DNSOpen || len(proof.Prefixes) != len(modes) || proof.Identity.SessionID != observed.Session || proof.InterfaceIndex == 0 || proof.InterfaceName == "" {
		t.Fatal("prefix original PF/process/utun receipt incomplete", observed)
	}
	macOSExternalNativeRetiredKernel(t, ctx, observed.Baseline.Token, beforeTunnels)
	counters := peer.observe(t, "stats")
	deadline := time.Now().Add(time.Second)
	for counters.Final.FinalRawTCP != 50 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		counters = peer.observe(t, "stats")
	}
	if counters.Final.FinalRawTCP != 50 || counters.Final.FinalTCP != 0 || counters.Final.FinalUDP != 0 || counters.Final.RouterQueries != 0 || counters.Final.DNSQueries != 0 || counters.Final.FinalPublicQueries != 0 || counters.Final.DirectQueries != 0 {
		t.Fatal("prefix test contacted old final, authenticated a candidate or opened application/DNS ingress", counters)
	}
	for i, prefix := range counters.Prefixes {
		if prefix.Mode != modes[i] || prefix.RawUDP == 0 || prefix.TCP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 || !proof.Prefixes[i].Proven {
			t.Fatal("prefix test bypassed original encrypted private proof", i, prefix)
		}
	}
	wrong, _ := json.Marshal(map[string]string{"request_id": id, "view_token": strings.Repeat("0", 64), "scope": orderedCandidateSavedPrefixScope})
	status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, base+"/cancel", string(wrong))
	if err != nil || status != 409 {
		t.Fatal("prefix Cancel accepted foreign original view", status, err)
	}
	savedID := ""
	if action == "save" {
		save := map[string]any{"request_id": id, "view_token": token, "candidate_id": choice.ID, "name": "Explicit Darwin prefix profile", "proposed_path": choice.Proposal, "scope": orderedCandidateSavedPrefixScope}
		save["candidate_id"] = "uncaptured-candidate"
		bad, _ := json.Marshal(save)
		status, _, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, base+"/save-profile", string(bad))
		if err != nil || status != 409 {
			t.Fatal("prefix Save accepted unmeasured candidate", status, err)
		}
		save["candidate_id"] = choice.ID
		body, _ = json.Marshal(save)
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, base+"/save-profile", string(body))
		var reply struct {
			Saved   bool   `json:"saved"`
			ID      string `json:"saved_profile_id"`
			Down    bool   `json:"native_down"`
			Drained bool   `json:"drained"`
			Changed bool   `json:"active_path_changed"`
		}
		if err != nil || status != 200 || json.Unmarshal(raw, &reply) != nil || !reply.Saved || !validProfileID(reply.ID) || !reply.Down || !reply.Drained || reply.Changed {
			t.Fatal("prefix explicit Save lost committed separate profile", status, err, string(raw))
		}
		savedID = reply.ID
		// Resolve the same configured store path used by shipping profile adoption.
		probe := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json")}}
		path := connectionProfileStorePath(probe)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, base+"/save-profile", string(body))
		var repeated struct {
			ID string `json:"saved_profile_id"`
		}
		after, readErr := os.ReadFile(path)
		if err != nil || readErr != nil || status != 200 || json.Unmarshal(raw, &repeated) != nil || repeated.ID != savedID || !bytes.Equal(before, after) {
			t.Fatal("prefix retry duplicated or replaced committed profile", status, err)
		}
		profiles, err := loadConnectionProfileStore(probe)
		if err != nil || len(profiles.Profiles) != 1 {
			t.Fatal("prefix Save did not create one separate profile", err)
		}
		record := profiles.Profiles[0]
		if record.ID != savedID || record.NodeID != choice.ID || record.Prefs == nil || !record.Prefs.MultihopEnabled || record.Prefs.MultihopExecution != "local" || !reflect.DeepEqual(record.Prefs.MultihopNodes, choice.Proposal) {
			t.Fatal("prefix Save omitted full next-connection graph", record)
		}
	}
	body, _ = json.Marshal(map[string]string{"request_id": id, "view_token": token, "scope": orderedCandidateSavedPrefixScope})
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, base+"/cancel", string(body))
	var closed struct {
		Down    bool   `json:"native_down"`
		Drained bool   `json:"drained"`
		ID      string `json:"saved_profile_id"`
	}
	if err != nil || status != 200 || json.Unmarshal(raw, &closed) != nil || !closed.Down || !closed.Drained || closed.ID != savedID {
		t.Fatal("prefix explicit decision failed original observer join", status, err, string(raw))
	}
	retired := read()
	if retired.Observer || retired.Session != observed.Session || retired.Transfer != observed.Transfer || retired.ProcessID != observed.ProcessID || !reflect.DeepEqual(retired.Proof, observed.Proof) {
		t.Fatal("prefix decision changed original DOWN authority", retired)
	}
	profilesAfter, err := os.ReadFile(filepath.Join(macOSOwnedControllerRoot, "routers.json"))
	if err != nil || !bytes.Equal(profilesBefore, profilesAfter) {
		t.Fatal("prefix test or Save changed original selection/profile usage", err)
	}
	stateAfter, stateAfterErr := os.ReadFile(statePath)
	if !bytes.Equal(stateBefore, stateAfter) || errors.Is(stateBeforeErr, os.ErrNotExist) != errors.Is(stateAfterErr, os.ErrNotExist) || stateAfterErr != nil && !errors.Is(stateAfterErr, os.ErrNotExist) {
		t.Fatal("prefix test or Save changed persisted Last/startup state", stateAfterErr)
	}
	if action == "cancel" {
		connectionAfter, connectionAfterErr := os.ReadFile(connectionProfileStorePath(profileProbe))
		if !bytes.Equal(connectionBefore, connectionAfter) || errors.Is(connectionBeforeErr, os.ErrNotExist) != errors.Is(connectionAfterErr, os.ErrNotExist) || connectionAfterErr != nil && !errors.Is(connectionAfterErr, os.ErrNotExist) {
			t.Fatal("prefix Cancel appended or rewrote connection profiles", connectionAfterErr)
		}
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	joined = true
	if receipt.ExitCode != 0 {
		t.Fatal("original prefix controller did not join", receipt.ExitCode)
	}
	t.Logf("actual sealed Darwin selected-prefix host verified %s: shipping public catalog and admission, original encrypted private prefix, exactly fifty TCP handshakes, unopened saved final, closed application and DNS, native Stop and process join, PF and utun retirement, explicit detached decision", scenario)
}

func TestDesktopDarwinInstalledPrefixCandidateFixtureKeepsClosedAuthority(t *testing.T) {
	for _, scenario := range []string{"wg-save", "awg-fast-save", "awg-strong-save", "wg-off-save"} {
		t.Run(strings.TrimSuffix(scenario, "-save"), func(t *testing.T) {
			modes, _, err := macOSCandidatePrefixModes(scenario)
			if err != nil {
				t.Fatal(err)
			}
			peer := macOSNodeChainPeerKeys(t, 3)
			macOSNodeChainSetModes(t, peer, modes)
			peer.reply.Address = "192.168.210.2:51820"
			store, assets := macOSCandidatePrefixSources(t, peer)
			if strings.Contains(scenario, "-off-") {
				for i := range store.Profiles {
					store.Profiles[i].KillSwitch = false
					store.Profiles[i].KillSwitchPolicy = "off"
				}
			}
			root := t.TempDir()
			for id, modes := range assets {
				for mode, files := range modes {
					directory := filepath.Join(root, "generated", id, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					for name, data := range files {
						if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			raw, _ := json.Marshal(store)
			if err := os.WriteFile(filepath.Join(root, "routers.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			a := &app{profiles: store, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ModesFile: filepath.Join(root, "modes.json"), ScriptsDir: filepath.Join(root, "modes"), StateFile: filepath.Join(root, "state.json")}}
			observe := func(ctx context.Context) (string, error) { return "explicit-source-only-boundary", ctx.Err() }
			view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, 1, orderedCandidateSavedPrefixScope, observe)
			if err != nil {
				t.Fatal(err)
			}
			q := orderedCandidatePreparationRequest{Scope: orderedCandidateSavedPrefixScope, RequestID: strings.Repeat("a", 32), Position: 1, CandidateIDs: []string{macOSCandidatePrefixCandidate}, Samples: 50}
			p, err := beginOrderedCandidatePreparationWithLifetime(context.Background(), context.Background(), a, q, observe)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := p.finish(); err != nil {
					t.Error("source-only prefix owner did not retire", err)
				}
			}()
			if !view.matchesPreparation(p, time.Now()) || p.prefixPreparation == nil || p.inventory.current(context.Background()) == nil {
				t.Fatal("private source fixture manufactured live authority")
			}
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "darwin", p)
			if err != nil {
				t.Fatal(err)
			}
			meta := launch.candidatePrefix.policy.Metadata()
			if strings.Contains(scenario, "-off-") && meta.KillSwitchPolicy != "off" {
				t.Fatal("source changed explicit Off")
			}
			if meta.ApplicationOpen || meta.DNSOpen || len(meta.Prefixes) != 2 || meta.PolicyProfileID != store.SelectedID || meta.ProfileID == store.SelectedID || launch.chain != nil || launch.command != nil {
				t.Fatal("prefix source fixture adopted old final as tested authority")
			}
			if !strings.Contains(string(assets[store.SelectedID]["shadowsocks"]["sing-box.json"]), `"server_port":1`) || !strings.Contains(string(assets[macOSCandidatePrefixCandidate]["shadowsocks"]["sing-box.json"]), `"server_port":8388`) {
				t.Fatal("prefix source fixture lost independently unopened final")
			}
			for i, mode := range modes {
				if meta.Prefixes[i].ProfileID != store.Profiles[i].ID || p.selection.Nodes[i].Mode != mode {
					t.Fatal("prefix source changed independent mode or profile")
				}
			}
		})
	}
}
