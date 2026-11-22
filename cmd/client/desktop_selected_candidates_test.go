package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// The parent owns the actual HTTP catalog, admission, MTU hold, private inode
// exchange and receipt adoption. The separate native child fixture executes
// the fifty actual connections; this component models only its publications.
func desktopSelectedCandidateParentFixture(t *testing.T, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainCandidateCatalog, string) {
	t.Helper()
	f, _ := desktopMultipleImportedSelectedLatencyFixture(t, desktopIndependentImportedLayouts[2], requested, winner)
	id := desktopCandidateAddCustomSource(t, f.a, "2022-blake3-aes-256-gcm")
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
	if err != nil {
		t.Fatal(err)
	}
	// Keep an unrelated resolver probe at its original pending boundary.
	// Releasing the real MTU hold may resume Auto; neither fabricating its DNS
	// receipt nor replacing the candidate publication owner is permitted.
	identity.Tracker.mu.Lock()
	if identity.Tracker.dnsProofRunning || identity.Tracker.dnsProofWork != nil {
		identity.Tracker.mu.Unlock()
		t.Fatal("selected candidate fixture lost its idle DNS boundary")
	}
	identity.Tracker.dnsProofRunning = true
	identity.Tracker.mu.Unlock()
	catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, 2, []string{id})
	if err != nil || catalog.selectedPlan == nil || catalog.plan != nil || catalog.typedPlan != nil {
		t.Fatal("selected packet candidate lost its original typed descriptor", err)
	}
	return f, catalog, id
}

func desktopSelectedCandidateMetadataFixture(t *testing.T, catalog *desktopNodeChainCandidateCatalog, request desktopSelectedCandidateRequest) []byte {
	t.Helper()
	var metadata map[string]any
	if err := json.Unmarshal([]byte(catalog.selectedPlan.plan.Metadata()), &metadata); err != nil {
		t.Fatal(err)
	}
	metadata["capture_sha256"] = strings.Repeat("b", 64)
	metadata["source_sha256"] = request.Capture.Identity.SourceSHA256
	metadata["config_sha256"] = request.Capture.Identity.ConfigSHA256
	metadata["preparation_source_sha256"] = request.Capture.PreparationSourceSHA256
	metadata["preparation_config_sha256"] = request.Capture.PreparationConfigSHA256
	metadata["requested_execution"] = catalog.selectedPlan.preparation.Execution()
	metadata["execution"] = request.Capture.Progress.Execution
	metadata["selection_epoch"] = request.Capture.SelectionEpoch
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	envelope := desktopSelectedCandidateEnvelope{request.Request, request.Generation, request.InventorySHA, strings.Repeat("b", 64), catalog.revision, raw}
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func desktopSelectedCandidateStatusFixture(t *testing.T, catalog *desktopNodeChainCandidateCatalog, request desktopSelectedCandidateRequest) hopmeasure.CandidateStatus {
	t.Helper()
	status := desktopCandidateDescriptionStatusFixture(t, catalog.selectedPlan.plan, request.Candidate)
	status.CaptureSHA256 = strings.Repeat("b", 64)
	status.Request = request.Request
	return status
}

func waitDesktopSelectedCandidateParentFile(t *testing.T, ctx context.Context, f *desktopNodeChainOwnedFixture, name string, done <-chan *httptest.ResponseRecorder) []byte {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, _, err := readDesktopSelectedCandidateFile(ctx, f.launch, name, 128<<10)
		if err == nil {
			return raw
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("selected candidate mailbox", name, err)
		}
		select {
		case response := <-done:
			t.Fatal("selected candidate HTTP completed before expected native publication", name, response.Code, response.Body.String())
		case <-ctx.Done():
			t.Fatal("selected candidate mailbox wait", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func publishDesktopSelectedCandidateParentResult(t *testing.T, f *desktopNodeChainOwnedFixture, request desktopSelectedCandidateRequest, metadata []byte, status hopmeasure.CandidateStatus) {
	t.Helper()
	result := desktopSelectedCandidateResult{desktopSelectedCandidateRequest: request, CompletedAt: time.Now().UnixMilli(), Status: status}
	if len(metadata) != 0 {
		var envelope desktopSelectedCandidateEnvelope
		if json.Unmarshal(metadata, &envelope) != nil {
			t.Fatal("fixture metadata envelope")
		}
		digest := sha256.Sum256(metadata)
		result.CaptureSHA, result.MetadataSHA = envelope.CaptureSHA, hex.EncodeToString(digest[:])
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	f.launch.workspaceMu.Lock()
	err = f.launch.directoryRoot.WriteFile(".selected-candidate-result.pending", raw, 0600)
	if err == nil {
		err = f.launch.directoryRoot.Link(".selected-candidate-result.pending", desktopSelectedCandidateResultFile)
	}
	if err == nil {
		err = f.launch.directoryRoot.Remove(".selected-candidate-result.pending")
	}
	if err == nil {
		err = f.launch.directoryRoot.Remove(desktopSelectedCandidateRequestFile)
	}
	f.launch.workspaceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

type desktopSelectedCandidateHTTPTestView struct {
	Token      string                   `json:"view_token"`
	Prefixes   []orderedCandidatePrefix `json:"prefixes"`
	Candidates []orderedCandidateChoice `json:"candidates"`
}

func exerciseDesktopSelectedCandidateHTTP(t *testing.T, f *desktopNodeChainOwnedFixture, catalog *desktopNodeChainCandidateCatalog, id, winner string, position int, prefixes []int) (desktopSelectedCandidateHTTPTestView, orderedCandidateRequest) {
	t.Helper()
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, f.a)
	catalogResponse := httptest.NewRecorder()
	mux.ServeHTTP(catalogResponse, httptest.NewRequest("GET", fmt.Sprintf("/api/multihop/prefix-candidates/catalog?prefix_position=%d", position), nil))
	var view desktopSelectedCandidateHTTPTestView

	if catalogResponse.Code != 200 || json.Unmarshal(catalogResponse.Body.Bytes(), &view) != nil {
		t.Fatal("selected HTTP catalog", catalogResponse.Code, catalogResponse.Body.String())
	}
	positions := []int{}
	found := false
	for _, row := range view.Prefixes {
		positions = append(positions, row.Position)
	}
	for _, row := range view.Candidates {
		if row.ID == id {
			found = true
		}
	}
	if !reflect.DeepEqual(positions, prefixes) || !found || view.Token == "" {
		t.Fatal("catalog compacted sparse packet positions or lost exact target", positions, found)
	}
	before := cloneRouterProfileStore(f.a.profiles)
	q := orderedCandidateRequest{RequestID: strings.Repeat("c", 32), ViewToken: view.Token, PrefixPosition: position, CandidateIDs: []string{id}, Samples: 50}
	body, _ := json.Marshal(q)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("POST", "/api/multihop/prefix-candidates", bytes.NewReader(body)).WithContext(ctx))
		done <- response
	}()
	raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateRequestFile, done)
	var request desktopSelectedCandidateRequest
	if json.Unmarshal(raw, &request) != nil || request.Position != position || request.Candidate != id || request.Capture.Progress.Execution != winner || !mtuSuspended(f.a) {
		t.Fatal("selected prepare lost exact prefix, winner, or MTU hold")
	}
	for _, name := range []string{desktopSelectedCandidateStartFile, desktopSelectedCandidateLiveFile} {
		if _, err := f.launch.directoryRoot.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("parent authorized native work before metadata", name, err)
		}
	}
	metadata := desktopSelectedCandidateMetadataFixture(t, catalog, request)
	if err := writeDesktopRuntimeFile(f.launch, desktopSelectedCandidateMetadataFile, metadata, false); err != nil {
		t.Fatal(err)
	}
	startRaw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateStartFile, done)
	var start desktopSelectedCandidateStart
	digest := sha256.Sum256(metadata)
	if json.Unmarshal(startRaw, &start) != nil || start.Request != request.Request || start.Generation != request.Generation || start.MetadataSHA != hex.EncodeToString(digest[:]) || start.CaptureSHA != strings.Repeat("b", 64) {
		t.Fatal("Start borrowed a different native plan")
	}
	pulseRaw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateLiveFile, done)
	var pulse desktopSelectedCandidatePulse
	if json.Unmarshal(pulseRaw, &pulse) != nil || pulse.Request != request.Request || pulse.CaptureSHA != start.CaptureSHA || pulse.Revision != catalog.revision || pulse.Sequence == 0 {
		t.Fatal("Start has no original catalog pulse")
	}
	// A published but uncommitted file cannot be decoded or adopted. A
	// subsequent catalog pulse proves the consumer actually polled it.
	if err := writeDesktopRuntimeFile(f.launch, desktopSelectedCandidateResultFile, []byte("{"), false); err != nil {
		t.Fatal(err)
	}
	wait := time.NewTicker(10 * time.Millisecond)
	defer wait.Stop()
	for {
		raw, _, err := readDesktopSelectedCandidateFile(ctx, f.launch, desktopSelectedCandidateLiveFile, 4096)
		var after desktopSelectedCandidatePulse
		if err == nil && json.Unmarshal(raw, &after) == nil && after.Sequence >= pulse.Sequence+2 {
			break
		}
		select {
		case response := <-done:
			t.Fatal("parent adopted an uncommitted result", response.Code)
		case <-ctx.Done():
			t.Fatal("parent stopped observing a request with an uncommitted result")
		case <-wait.C:
		}
	}
	if err := f.launch.directoryRoot.Remove(desktopSelectedCandidateResultFile); err != nil {
		t.Fatal(err)
	}
	status := desktopSelectedCandidateStatusFixture(t, catalog, request)
	publishDesktopSelectedCandidateParentResult(t, f, request, metadata, status)
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-ctx.Done():
		t.Fatal("selected parent did not join", ctx.Err())
	}
	var result struct {
		Accepted, Drained, Running bool
		Results                    []hopmeasure.CandidateStatus
		Failure                    string
		Errors                     []viaEntryCandidateError
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.Accepted || !result.Drained || result.Running || len(result.Results) != 1 || result.Results[0].CaptureSHA256 != status.CaptureSHA256 || result.Failure != "" || len(result.Errors) != 0 {
		t.Fatal("selected HTTP receipt was not adopted", response.Code, response.Body.String())
	}
	for _, name := range []string{desktopSelectedCandidateSourceFile, desktopSelectedCandidateRequestFile, desktopSelectedCandidateMetadataFile, desktopSelectedCandidateStartFile, desktopSelectedCandidateLiveFile, desktopSelectedCandidateCancelFile} {
		if _, err := f.launch.directoryRoot.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("joined parent retained original private file", name, err)
		}
	}
	if f.starts != 1 || f.executionModel.winner != winner || mtuSuspended(f.a) || !reflect.DeepEqual(before, f.a.profiles) {
		t.Fatal("measurement changed source profiles, repeated selection, or retained its MTU hold")
	}
	poll := httptest.NewRecorder()
	mux.ServeHTTP(poll, httptest.NewRequest("GET", fmt.Sprintf("/api/multihop/prefix-candidates?request_id=%s", q.RequestID), nil))
	if poll.Code != 200 || json.Unmarshal(poll.Body.Bytes(), &result) != nil || !result.Accepted || len(result.Results) != 1 {
		t.Fatal("fresh selected status lost its original receipt", poll.Code, poll.Body.String())
	}
	return view, q
}

func TestDesktopSelectedCandidateHTTPRetainsSparsePrefixAndSelectedWinner(t *testing.T) {
	for _, choice := range [][2]string{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
		t.Run(choice[0]+"/"+choice[1], func(t *testing.T) {
			f, catalog, id := desktopSelectedCandidateParentFixture(t, choice[0], choice[1])
			view, q := exerciseDesktopSelectedCandidateHTTP(t, f, catalog, id, choice[1], 2, []int{0, 2})
			before := cloneRouterProfileStore(f.a.profiles)
			var proposed []common.MultihopNodeSelection
			for _, row := range view.Candidates {
				if row.ID == id {
					proposed = row.Proposal
				}
			}
			save := orderedCandidateSaveRequest{RequestID: q.RequestID, ViewToken: q.ViewToken, CandidateID: id, Name: "Measured complete next path", ProposedPath: proposed}
			saved := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save)
			store, err := loadConnectionProfileStore(f.a)
			if saved.Code != 200 || err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].NodeChain) != 5 || store.Profiles[0].Prefs.MultihopExecution != choice[0] || !reflect.DeepEqual(store.Profiles[0].Prefs.MultihopNodes, proposed) {
				t.Fatal("explicit Save lost complete selected next path", saved.Code, saved.Body.String(), err)
			}
			if !reflect.DeepEqual(before, f.a.profiles) || f.starts != 1 || f.executionModel.winner != choice[1] || mtuSuspended(f.a) {
				t.Fatal("explicit future profile Save changed the connected path")
			}
			if repeated := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save); repeated.Code != 409 {
				t.Fatal("same selected receipt saved twice", repeated.Code)
			}
			// A cold profile consumer must restore the exact saved policy using
			// the original linked private records, without starting a connection.
			cold := &app{cfg: f.a.cfg, profiles: cloneRouterProfileStore(f.a.profiles)}
			loaded := postSetup(t, cold, "/api/connection-profile/setup/load", map[string]any{"id": store.Profiles[0].ID})
			selected, found := profileByID(cold.profiles.Profiles, cold.profiles.SelectedID)
			if loaded.Code != 200 || !found || selected.MultihopExecution != choice[0] || !reflect.DeepEqual(selected.MultihopNodes, proposed) || cold.cmd != nil || cold.state.Connected {
				t.Fatal("cold public Load lost the exact selected future profile", loaded.Code, loaded.Body.String())
			}
			for _, fault := range []string{"custom-entry", "imported-final", "unknown-paired-layer", "mixed-import"} {
				raw, _ := json.Marshal(store.Profiles[0])
				var changed connectionProfileRecord
				if json.Unmarshal(raw, &changed) != nil {
					t.Fatal("saved record copy")
				}
				switch fault {
				case "custom-entry":
					changed.NodeChain[0], changed.NodeChain[1] = changed.NodeChain[1], changed.NodeChain[0]
					changed.Prefs.MultihopNodes[0], changed.Prefs.MultihopNodes[1] = changed.Prefs.MultihopNodes[1], changed.Prefs.MultihopNodes[0]
				case "imported-final":
					changed.NodeChain[4], changed.NodeChain[3] = changed.NodeChain[3], changed.NodeChain[4]
					changed.Prefs.MultihopNodes[4], changed.Prefs.MultihopNodes[3] = changed.Prefs.MultihopNodes[3], changed.Prefs.MultihopNodes[4]
				case "unknown-paired-layer":
					changed.NodeChain[2].Preferences.StartLayer = "foreign-layer"
				case "mixed-import":
					changed.NodeChain[1].Mode = "socks5"
					changed.Prefs.MultihopNodes[1].Mode = "socks5"
					changed.NodeChain[1].External.Protocol = "socks5"
				}
				if validateSavedNodeChain(changed) == nil {
					t.Fatal("selected saved record admitted unsupported source", fault)
				}
			}
		})
	}
}

func TestDesktopSelectedCandidateMetadataRejectsForeignOriginals(t *testing.T) {
	f, catalog, id := desktopSelectedCandidateParentFixture(t, "auto", "server")
	publication, ready, _, _, err := readDesktopSelectedLatencyCapture(context.Background(), f.launch)
	if err != nil {
		t.Fatal(err)
	}
	request := desktopSelectedCandidateRequest{Schema: 1, Operation: "selected-packet-candidate-50", Request: strings.Repeat("d", 32), Generation: 1, Deadline: time.Now().Add(time.Minute).UnixMilli(), Position: 2, Candidate: id, InventorySHA: catalog.inventorySHA, Capture: ready, Selected: publication.Selected}
	valid := desktopSelectedCandidateMetadataFixture(t, catalog, request)
	faults := []string{"source", "config", "preparation-source", "preparation-config", "epoch", "requested", "execution", "position", "prefix", "target-id", "target-source", "extra-target-field", "missing", "extra", "duplicate", "whitespace", "request", "generation", "inventory", "capture", "revision"}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			var envelope desktopSelectedCandidateEnvelope
			if json.Unmarshal(valid, &envelope) != nil {
				t.Fatal("fixture metadata")
			}
			var inner map[string]any
			if json.Unmarshal(envelope.Metadata, &inner) != nil {
				t.Fatal("fixture inner metadata")
			}
			switch fault {
			case "source":
				inner["source_sha256"] = strings.Repeat("f", 64)
			case "config":
				inner["config_sha256"] = strings.Repeat("f", 64)
			case "preparation-source":
				inner["preparation_source_sha256"] = strings.Repeat("f", 64)
			case "preparation-config":
				inner["preparation_config_sha256"] = strings.Repeat("f", 64)
			case "epoch":
				inner["selection_epoch"] = ready.SelectionEpoch + 1
			case "requested":
				inner["requested_execution"] = "server"
			case "execution":
				inner["execution"] = "local"
			case "position":
				inner["prefix_position"] = 0
			case "prefix":
				inner["prefix_id"] = "another-packet"
			case "target-id":
				inner["targets"].([]any)[0].(map[string]any)["id"] = "another-target"
			case "target-source":
				inner["targets"].([]any)[0].(map[string]any)["source_sha256"] = strings.Repeat("f", 64)
			case "extra-target-field":
				inner["targets"].([]any)[0].(map[string]any)["extra"] = true
			case "missing":
				delete(inner, "targets")
			case "extra":
				inner["borrowed"] = true
			case "request":
				envelope.Request = strings.Repeat("e", 32)
			case "generation":
				envelope.Generation++
			case "inventory":
				envelope.InventorySHA = strings.Repeat("f", 64)
			case "capture":
				envelope.CaptureSHA = strings.Repeat("f", 64)
			case "revision":
				envelope.Revision += "-changed"
			}
			envelope.Metadata, _ = json.Marshal(inner)
			raw, _ := json.Marshal(envelope)
			if fault == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"revision":`), []byte(`"revision":"duplicate","revision":`), 1)
			}
			if fault == "whitespace" {
				raw = append([]byte(" "), raw...)
			}
			if _, _, err := catalog.selectedPlan.validateMetadata(request, catalog.revision, raw); err == nil {
				t.Fatal("foreign native metadata authorized Start", fault)
			}
			if catalog.selectedPlan.ready != nil {
				t.Fatal("rejected metadata retained authority")
			}
		})
	}
	if _, _, err := catalog.selectedPlan.validateMetadata(request, catalog.revision, valid); err != nil {
		t.Fatal("original exact metadata rejected", err)
	}
	status := desktopSelectedCandidateStatusFixture(t, catalog, request)
	if err := validateDesktopSelectedCandidateStatus(catalog.selectedPlan, id, status, time.Now()); err != nil {
		t.Fatal(err)
	}
	status.CaptureSHA256 = catalog.selectedPlan.plan.CaptureSHA256()
	if validateDesktopSelectedCandidateStatus(catalog.selectedPlan, id, status, time.Now()) == nil {
		t.Fatal("source-only plan substituted for original selected receipt")
	}
}

func TestDesktopSelectedCandidateCancellationJoinsWithoutStart(t *testing.T) {
	for _, fault := range []string{"factory-failure", "metadata-refusal", "cancel-before-metadata"} {
		t.Run(fault, func(t *testing.T) {
			f, catalog, id := desktopSelectedCandidateParentFixture(t, "auto", "server")
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := exchangeDesktopSelectedCandidateObserved(ctx, catalog, id, catalog.current, catalog.pulseCurrent)
				done <- err
			}()
			raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateRequestFile, nil)
			var request desktopSelectedCandidateRequest
			if json.Unmarshal(raw, &request) != nil {
				t.Fatal("prepare")
			}
			var metadata []byte
			if fault == "metadata-refusal" {
				metadata = desktopSelectedCandidateMetadataFixture(t, catalog, request)
				var envelope desktopSelectedCandidateEnvelope
				_ = json.Unmarshal(metadata, &envelope)
				envelope.Revision += "-foreign"
				metadata, _ = json.Marshal(envelope)
				if err := writeDesktopRuntimeFile(f.launch, desktopSelectedCandidateMetadataFile, metadata, false); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "cancel-before-metadata" {
				cancel()
			}
			if fault != "factory-failure" {
				joined, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				cancelled := waitDesktopSelectedCandidateParentFile(t, joined, f, desktopSelectedCandidateCancelFile, nil)
				if !bytes.Equal(raw, cancelled) {
					t.Fatal("Cancel did not retain its original Prepare")
				}
			}
			if _, err := f.launch.directoryRoot.Lstat(desktopSelectedCandidateStartFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed or cancelled preparation authorized Start")
			}
			status := hopmeasure.CandidateStatus{Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "failed", Failure: "modeled original preparation failure"}}
			publishDesktopSelectedCandidateParentResult(t, f, request, metadata, status)
			select {
			case err := <-done:
				if err == nil || errors.Is(err, errDesktopNodeChainMeasurementPending) {
					t.Fatal("joined failed candidate borrowed success or retained cleanup", err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("original cancellation did not join")
			}
			f.launch.chain.mu.Lock()
			pending := f.launch.chain.candidatePending
			f.launch.chain.mu.Unlock()
			if pending != nil {
				t.Fatal("joined candidate retained original pending retirement")
			}
			for _, name := range []string{desktopSelectedCandidateSourceFile, desktopSelectedCandidateRequestFile, desktopSelectedCandidateMetadataFile, desktopSelectedCandidateStartFile, desktopSelectedCandidateLiveFile, desktopSelectedCandidateCancelFile} {
				if _, err := f.launch.directoryRoot.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("cancelled original file survived join", name, err)
				}
			}
		})
	}
}

func TestDesktopSelectedCandidatePendingRetirementPreservesForeignMetadata(t *testing.T) {
	f, catalog, id := desktopSelectedCandidateParentFixture(t, "auto", "server")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := exchangeDesktopSelectedCandidateObserved(ctx, catalog, id, catalog.current, catalog.pulseCurrent)
		done <- err
	}()
	raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateRequestFile, nil)
	var request desktopSelectedCandidateRequest
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("prepare")
	}
	metadata := desktopSelectedCandidateMetadataFixture(t, catalog, request)
	if err := writeDesktopRuntimeFile(f.launch, desktopSelectedCandidateMetadataFile, metadata, false); err != nil {
		t.Fatal(err)
	}
	_ = waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateStartFile, nil)
	f.launch.workspaceMu.Lock()
	original, err := f.launch.directoryRoot.Lstat(desktopSelectedCandidateMetadataFile)
	if err == nil {
		err = f.launch.directoryRoot.Rename(desktopSelectedCandidateMetadataFile, ".original-selected-metadata-held")
	}
	if err == nil {
		err = f.launch.directoryRoot.WriteFile(desktopSelectedCandidateMetadataFile, metadata, 0600)
	}
	foreign, statErr := f.launch.directoryRoot.Lstat(desktopSelectedCandidateMetadataFile)
	f.launch.workspaceMu.Unlock()
	if err != nil || statErr != nil || os.SameFile(original, foreign) {
		t.Fatal("distinct metadata replacement", err, statErr)
	}
	_ = waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateCancelFile, nil)
	status := hopmeasure.CandidateStatus{Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "invalidated", Failure: "modeled changed original metadata"}}
	publishDesktopSelectedCandidateParentResult(t, f, request, metadata, status)
	var pending error
	select {
	case pending = <-done:
	case <-ctx.Done():
		t.Fatal("parent failed to return bounded pending cleanup", ctx.Err())
	}
	if !errors.Is(pending, errDesktopNodeChainMeasurementPending) {
		t.Fatal("foreign file cleanup was reported joined", pending)
	}
	current, err := f.launch.directoryRoot.Lstat(desktopSelectedCandidateMetadataFile)
	if err != nil || !os.SameFile(foreign, current) {
		t.Fatal("retirement deleted or replaced a foreign metadata inode", err)
	}
	if desktopSelectedCandidateMeasurementIdle(ctx, f.launch) == nil {
		t.Fatal("next measurement borrowed unjoined original cleanup")
	}
	// A later cleanup retry may remove the original inode after its owner has
	// restored it. The retained result and cancellation never acquire a new one.
	f.launch.workspaceMu.Lock()
	err = f.launch.directoryRoot.Remove(desktopSelectedCandidateMetadataFile)
	if err == nil {
		err = f.launch.directoryRoot.Rename(".original-selected-metadata-held", desktopSelectedCandidateMetadataFile)
	}
	f.launch.workspaceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// The original result is already acknowledged but remains pinned until
	// every other original file can retire. An equal replacement cannot join it.
	resultRaw, resultInfo, err := readDesktopSelectedCandidateFile(ctx, f.launch, desktopSelectedCandidateResultFile, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	const held = ".original-selected-result-held"
	if err := f.launch.directoryRoot.Rename(desktopSelectedCandidateResultFile, held); err != nil {
		t.Fatal(err)
	}
	if err := f.launch.directoryRoot.WriteFile(desktopSelectedCandidateResultFile, resultRaw, 0600); err != nil {
		t.Fatal(err)
	}
	short, finish := context.WithTimeout(ctx, 250*time.Millisecond)
	retryErr := retryDesktopNodeChainCandidateDrain(short, f.launch, pending)
	finish()
	observedRaw, observed, readErr := readDesktopSelectedCandidateFile(ctx, f.launch, desktopSelectedCandidateResultFile, 128<<10)
	if !errors.Is(retryErr, errDesktopNodeChainMeasurementPending) || readErr != nil || os.SameFile(resultInfo, observed) || !bytes.Equal(observedRaw, resultRaw) {
		t.Fatal("pending cleanup adopted or erased a replacement result", retryErr, readErr)
	}
	if err := f.launch.directoryRoot.Remove(desktopSelectedCandidateResultFile); err != nil {
		t.Fatal(err)
	}
	if err := f.launch.directoryRoot.Rename(held, desktopSelectedCandidateResultFile); err != nil {
		t.Fatal(err)
	}
	if err := retryDesktopNodeChainCandidateDrain(ctx, f.launch, pending); err != nil {
		t.Fatal("exact original cleanup retry did not join", err)
	}
	if err := desktopSelectedCandidateMeasurementIdle(ctx, f.launch); err != nil {
		t.Fatal("joined original cleanup blocked successor", err)
	}
}

func TestDesktopSelectedCandidateResultRetirement(t *testing.T) {
	for _, fault := range []string{"original", "same-bytes-foreign-inode", "modified-original-bytes", "missing-original"} {
		t.Run(fault, func(t *testing.T) {
			f, _, _ := desktopSelectedCandidateParentFixture(t, "server", "server")
			ctx := t.Context()
			const name = desktopSelectedCandidateResultFile
			raw := []byte(`{"result":"original"}`)
			if err := writeDesktopRuntimeFile(f.launch, name, raw, false); err != nil {
				t.Fatal(err)
			}
			_, original, err := readDesktopSelectedCandidateFile(ctx, f.launch, name, 128<<10)
			if err != nil || desktopSelectedCandidateMeasurementIdle(ctx, f.launch) == nil {
				t.Fatal("unretired result admitted a subsequent generation", err)
			}
			switch fault {
			case "same-bytes-foreign-inode":
				if err := f.launch.directoryRoot.Rename(name, name+".held"); err != nil {
					t.Fatal(err)
				}
				if err := f.launch.directoryRoot.WriteFile(name, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "modified-original-bytes":
				if err := f.launch.directoryRoot.WriteFile(name, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-original":
				if err := f.launch.directoryRoot.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
			err = retireDesktopSelectedCandidateCaptured(ctx, f.launch, name, raw, original)
			if fault == "original" {
				if err != nil || desktopSelectedCandidateMeasurementIdle(ctx, f.launch) != nil {
					t.Fatal("original result retirement did not release the next generation", err)
				}
			} else if err == nil {
				t.Fatal("result retirement accepted a changed original", fault)
			} else if fault != "missing-original" {
				if _, err := f.launch.directoryRoot.Lstat(name); err != nil {
					t.Fatal("result retirement erased a foreign result", err)
				}
			}
		})
	}
}

func TestDesktopSelectedCandidatePagedMetadataRetainsOneEpoch(t *testing.T) {
	f, first, id := desktopSelectedCandidateParentFixture(t, "auto", "server")
	source, _ := f.a.profileByIDLocked(id)
	ids := make([]string, 513)
	for i := range ids {
		member := cloneRouterProfile(source)
		member.ID = fmt.Sprintf("linked-candidate-%04d", i)
		ids[i] = member.ID
		f.a.profiles.Profiles = append(f.a.profiles.Profiles, member)
	}
	catalog, err := captureDesktopNodeChainCandidates(t.Context(), f.a, first.identity, 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	publication, ready, _, _, err := readDesktopSelectedLatencyCapture(t.Context(), f.launch)
	if err != nil {
		t.Fatal(err)
	}
	var commonCapture string
	for i, idx := range []int{0, 512, 0} {
		request := desktopSelectedCandidateRequest{Schema: 1, Operation: "selected-packet-candidate-50", Request: fmt.Sprintf("%032x", i+1), Generation: uint64(i + 1), Deadline: time.Now().Add(time.Minute).UnixMilli(), Position: 2, Candidate: ids[idx], InventorySHA: catalog.inventorySHA, Capture: ready, Selected: publication.Selected}
		original := desktopSelectedCandidateMetadataFixture(t, catalog, request)
		var envelope desktopSelectedCandidateEnvelope
		if json.Unmarshal(original, &envelope) != nil {
			t.Fatal("original metadata unavailable")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(envelope.Metadata, &fields) != nil {
			t.Fatal("original native metadata")
		}
		var targets []desktopSelectedCandidateTarget
		if json.Unmarshal(fields["targets"], &targets) != nil || len(targets) != len(ids) {
			t.Fatal("missing original targets")
		}
		full, _ := json.Marshal(targets)
		sum := sha256.Sum256(full)
		fields["schema"] = json.RawMessage("2")
		fields["target_offset"], _ = json.Marshal(idx)
		fields["target_total"], _ = json.Marshal(len(ids))
		fields["targets_sha256"], _ = json.Marshal(hex.EncodeToString(sum[:]))
		fields["targets"], _ = json.Marshal(targets[idx : idx+1])
		envelope.Metadata, _ = json.Marshal(fields)
		wire, _ := json.Marshal(envelope)
		if _, _, err := catalog.selectedPlan.validateMetadata(request, catalog.revision, wire); err != nil {
			t.Fatal("original selected membership", idx, err)
		}
		if i == 0 {
			commonCapture = catalog.selectedPlan.metadata
		} else if commonCapture != catalog.selectedPlan.metadata {
			t.Fatal("page changed original epoch")
		}
		for _, fault := range []string{"target_offset", "target_total", "targets_sha256", "targets"} {
			var wrong map[string]json.RawMessage
			_ = json.Unmarshal(envelope.Metadata, &wrong)
			switch fault {
			case "target_offset":
				wrong[fault], _ = json.Marshal((idx + 1) % len(ids))
			case "target_total":
				wrong[fault], _ = json.Marshal(len(ids) - 1)
			case "targets_sha256":
				wrong[fault], _ = json.Marshal(strings.Repeat("0", 64))
			case "targets":
				wrong[fault], _ = json.Marshal(targets[(idx+1)%len(ids) : (idx+1)%len(ids)+1])
			}
			altered := envelope
			altered.Metadata, _ = json.Marshal(wrong)
			other, _ := json.Marshal(altered)
			if _, _, err := catalog.selectedPlan.validateMetadata(request, catalog.revision, other); err == nil {
				t.Fatal("foreign page accepted", fault, idx)
			}
		}
	}
}
