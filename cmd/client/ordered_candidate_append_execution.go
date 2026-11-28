package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"router-vpn/internal/hopmeasure"
)

// This source purpose measures an unfinished Local editor prefix using an
// explicitly requested lane. It never changes the editor's saved execution.
type orderedCandidateAppendExecutionResult struct {
	status hopmeasure.CandidateStatus
	raw    json.RawMessage
}

func orderedCandidateOriginalInventoryIDs(q orderedCandidatePreparationRequest) []string {
	if q.Scope == orderedCandidateAppendExecutionScope {
		return q.inventoryCandidateIDs
	}
	return q.CandidateIDs
}
func (p *orderedCandidatePreparation) originalCandidateInventoryIDs() []string {
	if p == nil {
		return nil
	}
	return orderedCandidateOriginalInventoryIDs(p.request)
}
func validateOrderedCandidateAppendExecutionInventoryRequest(q orderedCandidatePreparationRequest) error {
	bad := errors.New("append execution requires the exact whole original candidate inventory")
	if q.Scope != orderedCandidateAppendExecutionScope {
		if len(q.inventoryCandidateIDs) != 0 || q.inventorySHA != "" || q.executionSourceSHA != "" {
			return bad
		}
		return nil
	}
	if q.append == nil || q.append.Purpose != q.Scope || q.append.validate() != nil || len(q.inventoryCandidateIDs) < 1 || len(q.inventoryCandidateIDs) > 50 || !validExternalProfileExpectationToken(q.inventorySHA) || !validExternalProfileExpectationToken(q.executionSourceSHA) {
		return bad
	}
	seen := map[string]bool{}
	for _, id := range q.inventoryCandidateIDs {
		if !validProfileID(id) || seen[id] {
			return bad
		}
		seen[id] = true
	}
	for _, id := range q.CandidateIDs {
		if !seen[id] {
			return bad
		}
	}
	return nil
}

func (view *orderedCandidatePreparedView) bindAppendExecutionCatalog() error {
	bad := errors.New("append execution catalog lost its original source or target inventory")
	if view == nil || view.append == nil || view.append.Purpose != orderedCandidateAppendExecutionScope || view.scopeValue() != view.append.Purpose || view.catalog == nil || view.appendSource == nil {
		return bad
	}
	execution := view.catalog.appendExecutionPreparation
	original := view.catalog.prefixPreparation
	if execution == nil || original == nil || execution.OriginalPreparation() != original || execution.Execution() != view.append.RequestedExecution || execution.OriginalSourceSHA256() != view.appendSource.SourceSHA || execution.SourceSHA256() == "" || !original.IsAppend() {
		return bad
	}
	var metadata struct {
		Targets []struct {
			ID     string `json:"id"`
			Source string `json:"source_sha256"`
		} `json:"targets"`
	}
	if json.Unmarshal([]byte(original.Metadata()), &metadata) != nil || len(metadata.Targets) != len(view.candidates) || len(metadata.Targets) < 1 || len(metadata.Targets) > 50 {
		return bad
	}
	seen := map[string]bool{}
	for i, target := range metadata.Targets {
		if target.ID != view.candidates[i].ID || seen[target.ID] || !validExternalProfileExpectationToken(target.Source) {
			return bad
		}
		seen[target.ID] = true
		view.candidates[i].SourceSHA256 = target.Source
	}
	view.appendSource.Purpose = view.append.Purpose
	view.appendSource.ExecutionSourceSHA = execution.SourceSHA256()
	view.appendSource.RequestedExecution = execution.Execution()
	return nil
}

func (view *orderedCandidatePreparedView) appendExecutionInventoryRequest() ([]string, string, string) {
	if view == nil || view.scopeValue() != orderedCandidateAppendExecutionScope || view.catalog == nil || view.catalog.appendExecutionPreparation == nil {
		return nil, "", ""
	}
	ids := make([]string, len(view.candidates))
	for i, candidate := range view.candidates {
		ids[i] = candidate.ID
	}
	return ids, view.catalog.inventorySHA, view.catalog.appendExecutionPreparation.SourceSHA256()
}

func (p *orderedCandidatePreparation) appendExecutionSourceCurrent() bool {
	if p == nil || p.inventory == nil {
		return false
	}
	if p.request.Scope != orderedCandidateAppendExecutionScope {
		return p.appendExecutionPreparation == nil && p.inventory.appendExecutionPreparation == nil
	}
	execution := p.appendExecutionPreparation
	captured := desktopCandidateAppendCapture(p.selection)
	return execution != nil && captured != nil && p.request.append != nil && p.request.append == captured.request &&
		p.request.append.Purpose == p.request.Scope && p.request.append.validate() == nil && validateOrderedCandidateAppendExecutionInventoryRequest(p.request) == nil &&
		execution == p.inventory.appendExecutionPreparation && execution.OriginalPreparation() == p.prefixPreparation && p.prefixPreparation == p.inventory.prefixPreparation &&
		execution.SourceSHA256() == p.request.executionSourceSHA && execution.OriginalSourceSHA256() == captured.source.SourceSHA256() &&
		execution.LocalSource() == captured.source.Source() && execution.Execution() == p.request.append.RequestedExecution &&
		execution.ConfigSHA256() == p.prefixPreparation.ConfigSHA256() && p.inventory.inventorySHA == p.request.inventorySHA
}

// The IPC consumer calls this only after validating its actual original native
// request, readiness sidecar, worker, receipt and complete fifty-sample result.
// A byte-preserving copy keeps execution fields out of the legacy status type.
func (p *orderedCandidatePreparation) retainAppendExecutionResult(id string, status hopmeasure.CandidateStatus, raw json.RawMessage) error {
	bad := errors.New("append execution result differs from its original candidate or request")
	if p == nil || !p.appendExecutionSourceCurrent() || !slices.Contains(p.request.CandidateIDs, id) || status.CandidateID != id || len(raw) == 0 {
		return bad
	}
	var decoded hopmeasure.CandidateStatus
	var execution struct {
		Purpose         string          `json:"purpose"`
		Source          string          `json:"source_sha256"`
		ExecutionSource string          `json:"execution_source_sha256"`
		Capture         string          `json:"execution_capture_sha256"`
		Requested       string          `json:"requested_execution"`
		Winning         string          `json:"winning_execution"`
		Selection       json.RawMessage `json:"selection"`
	}
	if _, err := externalConnectJSONObject(raw); err != nil {
		return bad
	}
	if json.Unmarshal(raw, &decoded) != nil || !reflect.DeepEqual(decoded, status) || json.Unmarshal(raw, &execution) != nil ||
		execution.Purpose != p.request.Scope || execution.Source != p.appendExecutionPreparation.OriginalSourceSHA256() || execution.ExecutionSource != p.request.executionSourceSHA ||
		execution.Requested != p.request.append.RequestedExecution || execution.Capture != status.CaptureSHA256 || !validExternalProfileExpectationToken(execution.Capture) ||
		execution.Winning != "local" && execution.Winning != "server" || execution.Requested == "server" && execution.Winning != "server" ||
		execution.Requested == "server" && len(execution.Selection) != 0 || execution.Requested == "auto" && (len(execution.Selection) == 0 || string(execution.Selection) == "null") {
		return bad
	}
	if !validViaEntryRequestID(status.Request) || !status.Complete || !status.Drained || status.Stage != "complete" || status.Failure != "" || len(status.Results) != 1 {
		return bad
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nativeDown || p.down || p.invalidated.Load() || p.operation == nil || p.operation.Err() != nil {
		return bad
	}
	p.appendExecutionResultsMu.Lock()
	defer p.appendExecutionResultsMu.Unlock()
	if p.appendExecutionResults == nil {
		p.appendExecutionResults = map[string]orderedCandidateAppendExecutionResult{}
	}
	if _, exists := p.appendExecutionResults[id]; exists {
		return bad
	}
	// Decode an independent copy: callers cannot mutate the retained benchmark
	// or a distribution pointer after this ownership transfer.
	p.appendExecutionResults[id] = orderedCandidateAppendExecutionResult{status: decoded, raw: append(json.RawMessage(nil), raw...)}
	return nil
}

func (p *orderedCandidatePreparation) retainedAppendExecutionResult(id string, status hopmeasure.CandidateStatus, now time.Time) (json.RawMessage, error) {
	bad := errors.New("append execution result is absent, changed or expired")
	if p == nil || !p.appendExecutionSourceCurrent() || !slices.Contains(p.request.CandidateIDs, id) || status.CandidateID != id ||
		status.MeasuredAt <= 0 || status.MeasuredAt > now.UnixMilli() || status.ExpiresAt != status.MeasuredAt+hopmeasure.CandidateReceiptLifetime.Milliseconds() || status.ExpiresAt <= now.UnixMilli() {
		return nil, bad
	}
	p.appendExecutionResultsMu.Lock()
	defer p.appendExecutionResultsMu.Unlock()
	retained, exists := p.appendExecutionResults[id]
	if !exists || p.invalidated.Load() || !reflect.DeepEqual(retained.status, status) {
		return nil, bad
	}
	return append(json.RawMessage(nil), retained.raw...), nil
}
