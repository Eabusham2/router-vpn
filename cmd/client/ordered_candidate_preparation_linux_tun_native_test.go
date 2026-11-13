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
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

type linuxOrderedPreparedHostReceipt struct {
	RequestID   string                     `json:"request_id"`
	ViewToken   string                     `json:"view_token"`
	Action      string                     `json:"action"`
	SavedID     string                     `json:"saved_profile_id"`
	NativeDown  bool                       `json:"native_down"`
	Observer    bool                       `json:"observer_retained"`
	Drained     bool                       `json:"drained"`
	ProfileSame bool                       `json:"original_profile_unchanged"`
	Row         hopmeasure.CandidateStatus `json:"row"`
}

func linuxHostTUNPreparedCandidateParent(t *testing.T, installed, scenario, action string, modes []string, peer *linuxNodeChainPeer) {
	t.Helper()
	process := linuxHostTUNStartController(t, installed, scenario)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	result := process.readNodeChain(t, scenario)
	r := result.Prepared
	if result.Stage != "review" || !result.Retired || result.Session == "" || result.Ready == nil || result.Proof == nil ||
		result.Proof.Generation != 1 || result.Proof.Identity.SessionID != result.Session ||
		r == nil || r.Action != action || !validViaEntryRequestID(r.RequestID) || len(r.ViewToken) != 64 ||
		!r.NativeDown || !r.Observer || r.Drained || r.SavedID != "" || !r.ProfileSame || len(result.Nodes) != len(modes)+1 ||
		r.Row.PrefixPosition != len(modes)-1 || r.Row.CandidateID != "installed-ordered-final" || !r.Row.Complete || !r.Row.Drained ||
		len(r.Row.Results) != 1 || r.Row.Results[0].Benchmark == nil || r.Row.Results[0].Benchmark.Attempts != 50 ||
		r.Row.Results[0].Benchmark.Distribution == nil || r.Row.Results[0].Benchmark.Distribution.Samples != 50 {
		t.Fatal("installed saved candidate API omitted its actual fifty-sample DOWN/review boundary", result)
	}
	// Authenticated proof streams increment both native counters. Candidate
	// TCP handshakes deliberately send no SS credentials, so precisely fifty
	// additional raw streams must reach the original final endpoint.
	deadline := time.Now().Add(time.Second)
	var counters linuxNodeChainPeerReply
	for {
		counters = peer.observe(t, "stats")
		extra := counters.Final.FinalRawTCP - counters.Final.FinalTCP
		if extra == 50 {
			break
		}
		if extra > 50 || time.Now().After(deadline) {
			t.Fatal("installed saved candidate omitted exact independent fifty-handshake target count", extra, counters)
		}
		time.Sleep(time.Millisecond)
	}
	if counters.Final.RouterQueries == 0 || counters.Final.DNSQueries == 0 || counters.Final.FinalPublicQueries == 0 ||
		counters.Final.FinalTCP == 0 || counters.Final.FinalUDP == 0 || counters.Final.DirectQueries != 0 {
		t.Fatal("temporary candidate test omitted real final authentication/DNS or used a direct proof", counters)
	}
	for i, prefix := range counters.Prefixes {
		if result.Nodes[i].Mode != modes[i] || prefix.Mode != modes[i] || prefix.RawUDP == 0 || prefix.TCP == 0 ||
			prefix.UDP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 {
			t.Fatal("temporary candidate test bypassed an original encrypted prefix", i, prefix)
		}
	}
	if _, err := process.gate.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	final := process.readNodeChain(t, scenario)
	if final.Stage != "retired" || !final.Retired || final.Session != result.Session || final.Prepared == nil ||
		final.Prepared.RequestID != r.RequestID || final.Prepared.ViewToken != r.ViewToken || !final.Prepared.NativeDown ||
		final.Prepared.Observer || !final.Prepared.Drained || !final.Prepared.ProfileSame ||
		!reflect.DeepEqual(final.Prepared.Row, r.Row) || (final.Prepared.SavedID != "") != (action == "candidates-save") {
		t.Fatal("installed saved candidate explicit decision lost original join or separate profile receipt", final)
	}
	select {
	case <-process.done:
		if process.waitErr != nil {
			t.Fatal("installed saved candidate controller did not finish", process.waitErr, process.diagnostic.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("installed saved candidate controller did not join")
	}
	t.Log("verified installed host native lifecycle:", scenario)
	t.Log("verified installed host ordered independent prefixes and final:", scenario)
	t.Log("verified installed host saved candidate API fifty samples native DOWN and explicit decision:", scenario)
}

// The installed, protected original controller uses the shipping HTTP handlers
// and native constructor. No test driver supplies readiness, measurements,
// physical observations, DOWN or a writable profile receipt.
func linuxHostTUNPreparedCandidateFixture(ctx context.Context, a *app, controller *ownedDesktopController,
	gate *os.File, scenario, action string) (failure error) {
	if !nativeNodeChainPlatformSupported() {
		return errors.New("installed saved candidate API lost actual Linux native admission")
	}
	originalProfiles := cloneRouterProfileStore(a.profiles)
	originalState := a.state
	routerBytes, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		return err
	}
	defer clear(routerBytes)
	stateBytes, stateErr := os.ReadFile(a.cfg.StateFile)
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	storeBefore, err := loadConnectionProfileStore(a)
	if err != nil {
		return err
	}
	storeBytes, storeErr := os.ReadFile(connectionProfileStorePath(a))
	if storeErr != nil && !errors.Is(storeErr, os.ErrNotExist) {
		return storeErr
	}
	defer clear(storeBytes)
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, a)
	call := func(callContext context.Context, method, path string, value any) (*httptest.ResponseRecorder, error) {
		var body []byte
		var err error
		if value != nil {
			body, err = json.Marshal(value)
			if err != nil {
				return nil, err
			}
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(callContext))
		return response, nil
	}
	const base = "/api/multihop/saved-candidates"
	position := len(originalProfiles.Profiles) - 2
	response, err := call(ctx, http.MethodGet, fmt.Sprintf("%s/catalog?prefix_position=%d", base, position), nil)
	var catalog struct {
		Schema      int                      `json:"schema"`
		Scope       string                   `json:"scope"`
		Token       string                   `json:"view_token"`
		Position    int                      `json:"prefix_position"`
		Samples     int                      `json:"samples"`
		Measurement string                   `json:"measurement"`
		Candidates  []orderedCandidateChoice `json:"candidates"`
	}
	if err != nil {
		return err
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &catalog) != nil || catalog.Schema != 1 ||
		catalog.Scope != "saved-complete-local" || len(catalog.Token) != 64 || catalog.Position != position ||
		catalog.Samples != 50 || catalog.Measurement != "routed-tcp-connect" {
		return fmt.Errorf("installed saved candidate catalog: %d %s", response.Code, response.Body.String())
	}
	var choice *orderedCandidateChoice
	for i := range catalog.Candidates {
		if catalog.Candidates[i].ID == originalProfiles.SelectedID {
			choice = &catalog.Candidates[i]
		}
	}
	if choice == nil || choice.SaveReason != "" || len(choice.Proposal) != len(originalProfiles.Profiles) {
		return errors.New("installed saved graph omitted its original final candidate proposal")
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	q := orderedCandidateRequest{id, catalog.Token, position, []string{choice.ID}, 50}
	requestContext, endResponse := context.WithCancel(ctx)
	response, err = call(requestContext, http.MethodPost, base, q)
	endResponse() // Actual 202 return must not own the worker lifetime.
	if err != nil {
		return err
	}
	if response.Code != http.StatusAccepted {
		return fmt.Errorf("installed saved candidate Test did not return202: %d %s", response.Code, response.Body.String())
	}
	control := viaEntryControlFor(a)
	control.mu.Lock()
	owner := control.owner
	var p *orderedCandidatePreparation
	if owner != nil && owner.id == id {
		p = owner.preparation
	}
	control.mu.Unlock()
	if p == nil || p.owner != owner || p.app != a {
		return errors.New("installed202 did not retain its original typed preparation")
	}
	defer func() {
		if failure != nil {
			p.cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			select {
			case <-owner.done:
				failure = errors.Join(failure, cleanupViaEntryOwnerContext(cleanup, control, owner))
			case <-cleanup.Done():
				failure = errors.Join(failure, cleanup.Err())
			}
		}
	}()
	var status struct {
		RequestID string                       `json:"request_id"`
		ViewToken string                       `json:"view_token"`
		Running   bool                         `json:"running"`
		Accepted  bool                         `json:"accepted"`
		Reviewing bool                         `json:"reviewing"`
		Down      bool                         `json:"native_down"`
		Drained   bool                         `json:"drained"`
		Cleanup   bool                         `json:"cleanup_pending"`
		Changed   bool                         `json:"active_path_changed"`
		Failure   string                       `json:"failure"`
		Rows      []hopmeasure.CandidateStatus `json:"results"`
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		response, err = call(ctx, http.MethodGet, base+"?request_id="+id, nil)
		if err != nil {
			return err
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.RequestID != id || status.ViewToken != catalog.Token {
			return fmt.Errorf("installed original saved status changed: %d %s", response.Code, response.Body.String())
		}
		a.mu.Lock()
		ordinary := a.state.Connected
		a.mu.Unlock()
		if ordinary || status.Changed || status.Running && (status.Accepted || status.Reviewing || len(status.Rows) != 0) {
			return errors.New("temporary candidate preparation published ordinary Connected or choices before native DOWN")
		}
		if !status.Running {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	if !status.Accepted || !status.Reviewing || !status.Down || status.Drained || status.Cleanup || status.Failure != "" || len(status.Rows) != 1 {
		return fmt.Errorf("installed saved candidate did not reach actual native DOWN review: %s", response.Body.String())
	}
	select {
	case <-owner.done:
	default:
		return errors.New("saved review preceded its original worker join")
	}
	if p.runtime == nil || p.runtime.catalog == nil || p.launch == nil || p.launch.chain == nil || p.launch.chain.platform == nil {
		return errors.New("saved native result lost its actual original Linux launch")
	}
	if err := validateDesktopNodeChainCandidateStatus(p.runtime.catalog.plan, choice.ID, status.Rows[0], time.Now()); err != nil {
		return err
	}
	h, session := p.launch.chain.platform.host, p.launch.chain.platform.session
	if h == nil || h.process == nil || h.ready == nil || !h.closed || !h.released || h.chain != nil || len(h.source) != 0 ||
		h.process.command.ProcessState == nil || session == nil || session.active != nil || session.journal == nil {
		return errors.New("saved review omitted real original process/source/protection retirement")
	}
	select {
	case <-h.process.joined:
	default:
		return errors.New("saved review preceded original native Wait")
	}
	head, err := session.journal.Snapshot(ctx)
	if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
		return errors.Join(err, errors.New("saved native DOWN retained original on-connect protection"))
	}
	if err := linuxHostTUNTUNAbsent(h.ready); err != nil {
		return err
	}
	owner.closeMu.Lock()
	err = p.reviewCurrent(ctx)
	owner.closeMu.Unlock()
	if err != nil {
		return err
	}
	unchanged := func() error {
		a.mu.Lock()
		same := reflect.DeepEqual(a.profiles, originalProfiles) && !a.state.Connected &&
			[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == [3]bool{originalState.DAITA, originalState.Jumbo, originalState.Socks} && orderedCandidatePreparationDownLocked(a)
		a.mu.Unlock()
		raw, err := os.ReadFile(a.cfg.StateFile)
		if !same || !bytes.Equal(raw, stateBytes) || errors.Is(err, os.ErrNotExist) != errors.Is(stateErr, os.ErrNotExist) || err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("temporary candidate Test changed original selection, usage, Home settings or persisted startup state")
		}
		raw, err = os.ReadFile(a.cfg.ProfilesFile)
		if err != nil || !bytes.Equal(raw, routerBytes) {
			clear(raw)
			return errors.New("temporary candidate Test rewrote original saved Router profiles or usage")
		}
		clear(raw)
		return nil
	}
	if err := unchanged(); err != nil {
		return err
	}
	p.launch.chain.mu.Lock()
	proof := p.launch.chain.ready
	p.launch.chain.mu.Unlock()
	if proof == nil {
		return errors.New("saved candidate result lost its original complete native proof")
	}
	result := linuxNodeChainHostResult{linuxImportedHostResult: linuxImportedHostResult{Scenario: scenario, Stage: "review", Session: h.selection.SessionID, Ready: h.ready, Retired: true},
		Proof: proof, Nodes: append([]common.MultihopNodeSelection(nil), choice.Proposal...),
		Prepared: &linuxOrderedPreparedHostReceipt{RequestID: id, ViewToken: catalog.Token, Action: action, NativeDown: true, Observer: true, ProfileSame: true, Row: status.Rows[0]}}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 2); err != nil {
		return err
	}
	wrong := map[string]string{"request_id": id, "view_token": strings.Repeat("0", 64)}
	response, err = call(ctx, http.MethodPost, base+"/cancel", wrong)
	if err != nil || response.Code != 409 {
		return errors.Join(err, errors.New("installed saved Cancel accepted another view"))
	}
	if action == "candidates-save" {
		save := orderedCandidateSaveRequest{RequestID: id, ViewToken: catalog.Token, CandidateID: choice.ID, Name: "Explicit installed candidate draft", ProposedPath: choice.Proposal}
		foreign := save
		foreign.CandidateID = "uncaptured-candidate"
		response, err = call(ctx, http.MethodPost, base+"/save-profile", foreign)
		if err != nil || response.Code != 409 {
			return errors.Join(err, errors.New("installed saved profile adopted an unmeasured candidate"))
		}
		response, err = call(ctx, http.MethodPost, base+"/save-profile", save)
		if err != nil {
			return err
		}
		var reply struct {
			Saved   bool   `json:"saved"`
			ID      string `json:"saved_profile_id"`
			Name    string `json:"profile_name"`
			Drained bool   `json:"drained"`
			Down    bool   `json:"native_down"`
			Changed bool   `json:"active_path_changed"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &reply) != nil || !reply.Saved || !validProfileID(reply.ID) ||
			reply.Name != save.Name || !reply.Drained || !reply.Down || reply.Changed {
			return fmt.Errorf("installed explicit saved profile did not commit and join: %d %s", response.Code, response.Body.String())
		}
		result.Prepared.SavedID = reply.ID
		saved, err := loadConnectionProfileStore(a)
		if err != nil || len(saved.Profiles) != len(storeBefore.Profiles)+1 || !reflect.DeepEqual(saved.Profiles[:len(storeBefore.Profiles)], storeBefore.Profiles) {
			return errors.Join(err, errors.New("explicit candidate Save replaced another saved profile"))
		}
		record := saved.Profiles[len(saved.Profiles)-1]
		if record.ID != reply.ID || record.Name != save.Name || record.NodeID != choice.ID || record.Prefs == nil ||
			!record.Prefs.MultihopEnabled || record.Prefs.MultihopExecution != "local" || !reflect.DeepEqual(record.Prefs.MultihopNodes, choice.Proposal) {
			return errors.New("explicit candidate Save omitted its complete next-connection graph")
		}
		committed, err := os.ReadFile(connectionProfileStorePath(a))
		if err != nil {
			return err
		}
		defer clear(committed)
		response, err = call(ctx, http.MethodPost, base+"/save-profile", save)
		var repeated struct {
			ID string `json:"saved_profile_id"`
		}
		if err != nil || response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &repeated) != nil || repeated.ID != reply.ID {
			return errors.Join(err, errors.New("identical saved candidate retry lost its original committed identity"))
		}
		after, err := os.ReadFile(connectionProfileStorePath(a))
		if err != nil || !bytes.Equal(committed, after) {
			return errors.Join(err, errors.New("saved candidate retry duplicated or rewrote the named profile"))
		}
		clear(after)
	}
	response, err = call(ctx, http.MethodPost, base+"/cancel", map[string]string{"request_id": id, "view_token": catalog.Token})
	var cancelled struct {
		Request string `json:"request_id"`
		View    string `json:"view_token"`
		Saved   string `json:"saved_profile_id"`
		Drained bool   `json:"drained"`
		Down    bool   `json:"native_down"`
	}
	if err != nil || response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &cancelled) != nil || cancelled.Request != id ||
		cancelled.View != catalog.Token || cancelled.Saved != result.Prepared.SavedID || !cancelled.Drained || !cancelled.Down {
		return errors.Join(err, errors.New("installed exact candidate Cancel lost original DOWN, saved identity or observer join"))
	}
	if action == "candidates-cancel" {
		after, err := os.ReadFile(connectionProfileStorePath(a))
		if !bytes.Equal(after, storeBytes) || errors.Is(err, os.ErrNotExist) != errors.Is(storeErr, os.ErrNotExist) || err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("review Cancel wrote or changed a connection profile")
		}
		clear(after)
	}
	if err := unchanged(); err != nil {
		return err
	}
	a.mu.Lock()
	retired := a.candidatePreparation == nil && a.connectionContext == nil
	a.mu.Unlock()
	if !retired || !p.down || p.runtime.cohort.CurrentContext(ctx) == nil {
		return errors.New("explicit saved decision did not retire its exact retained physical observer")
	}
	if !a.operationMu.TryLock() {
		return errors.New("explicit saved decision retained the original operation lock")
	}
	a.operationMu.Unlock()
	result.Stage, result.Prepared.Observer, result.Prepared.Drained = "retired", false, true
	controller.close()
	return json.NewEncoder(os.Stdout).Encode(result)
}
