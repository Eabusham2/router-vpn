package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

const (
	desktopSelectedCandidateSourceFile   = "node-chain-execution-candidate-source.json"
	desktopSelectedCandidateRequestFile  = "node-chain-execution-candidate-request.json"
	desktopSelectedCandidateMetadataFile = "node-chain-execution-candidate-metadata.json"
	desktopSelectedCandidateStartFile    = "node-chain-execution-candidate-start.json"
	desktopSelectedCandidateLiveFile     = "node-chain-execution-candidate-live.json"
	desktopSelectedCandidateCancelFile   = "node-chain-execution-candidate-cancel.json"
	desktopSelectedCandidateResultFile   = "node-chain-execution-candidate-result.json"
)

type desktopSelectedCandidateRequest struct {
	Schema       int                                                 `json:"schema"`
	Operation    string                                              `json:"operation"`
	Request      string                                              `json:"request_id"`
	Generation   uint64                                              `json:"generation"`
	Deadline     int64                                               `json:"deadline_at"`
	Path         string                                              `json:"path_id"`
	Position     int                                                 `json:"prefix_position"`
	Candidate    string                                              `json:"candidate_id"`
	InventorySHA string                                              `json:"inventory_sha256"`
	Capture      mobilemultihop.DesktopNodeChainExecutionReadyRecord `json:"capture"`
	Selected     string                                              `json:"selected_capture"`
}

type desktopSelectedCandidateEnvelope struct {
	Request      string          `json:"request_id"`
	Generation   uint64          `json:"generation"`
	InventorySHA string          `json:"inventory_sha256"`
	CaptureSHA   string          `json:"capture_sha256"`
	Revision     string          `json:"revision"`
	Metadata     json.RawMessage `json:"metadata"`
}

type desktopSelectedCandidateStart struct {
	Request     string `json:"request_id"`
	Generation  uint64 `json:"generation"`
	CaptureSHA  string `json:"capture_sha256"`
	MetadataSHA string `json:"metadata_sha256"`
}

type desktopSelectedCandidatePulse struct {
	Schema     int    `json:"schema"`
	Request    string `json:"request_id"`
	CaptureSHA string `json:"capture_sha256"`
	Revision   string `json:"revision"`
	Sequence   uint64 `json:"sequence"`
	ObservedAt int64  `json:"observed_at"`
}

type desktopSelectedCandidateResult struct {
	desktopSelectedCandidateRequest
	CaptureSHA  string                     `json:"capture_sha256"`
	MetadataSHA string                     `json:"metadata_sha256"`
	CompletedAt int64                      `json:"completed_at"`
	Status      hopmeasure.CandidateStatus `json:"status"`
}

func readDesktopSelectedCandidateFile(ctx context.Context, launch *desktopNodeLaunch, name string, limit int) ([]byte, os.FileInfo, error) {
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return nil, nil, err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return nil, nil, err
	}
	before, err := launch.directoryRoot.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	raw, err := readDesktopRuntimeSnapshot(launch.directoryRoot, name, int64(limit))
	after, statErr := launch.directoryRoot.Lstat(name)
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		clear(raw)
		return nil, nil, errors.Join(err, statErr, errors.New("selected candidate private file changed while reading"))
	}
	return raw, after, ctx.Err()
}

// Capture the producer's original inode before the atomic public link. The
// child may consume a request or cancellation immediately after publication.
func publishDesktopSelectedCandidateOwned(ctx context.Context, launch *desktopNodeLaunch, name string, raw []byte) (os.FileInfo, error) {
	var info os.FileInfo
	err := publishDesktopNodeChainMeasurementWithWriter(ctx, launch, name, raw, func(file *os.File, body []byte) error {
		if _, err := file.Write(body); err != nil {
			return err
		}
		var err error
		info, err = file.Stat()
		return err
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Caller holds the shared measurement mutex. A previous failed operation must
// join its own cancellation before a different measurement can be admitted.
func desktopSelectedCandidateMeasurementIdle(ctx context.Context, launch *desktopNodeLaunch) error {
	launch.chain.mu.Lock()
	pending := launch.chain.candidatePending != nil
	launch.chain.mu.Unlock()
	if pending {
		return errDesktopNodeChainMeasurementPending
	}
	for _, name := range []string{desktopSelectedLatencyRequestFile, desktopSelectedLatencyCancelFile, desktopSelectedCandidateRequestFile, desktopSelectedCandidateCancelFile, desktopSelectedCandidateResultFile} {
		_, _, err := readDesktopSelectedCandidateFile(ctx, launch, name, 16384)
		if !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, errDesktopNodeChainMeasurementPending)
		}
	}
	return ctx.Err()
}

// The two-stage exchange obtains the child-owned capture before publishing a
// catalog pulse or Start. The same request owns cancellation even when native
// construction fails before metadata, and keeps its lease until joined drain.
func exchangeDesktopSelectedCandidateObserved(parent context.Context, catalog *desktopNodeChainCandidateCatalog, id string,
	current, pulseCurrent func(context.Context) error) (hopmeasure.CandidateStatus, error) {
	var empty hopmeasure.CandidateStatus
	if parent == nil || parent.Err() != nil || catalog == nil || catalog.selectedPlan == nil || !catalog.hasConnectedPlan() ||
		catalog.launch == nil || catalog.profiles[id] == "" || current == nil || pulseCurrent == nil {
		return empty, errors.New("selected candidate requires its original complete catalog")
	}
	ctx, cancel := context.WithTimeout(parent, hopmeasure.RequestTimeout)
	defer cancel()
	launch, chain, descriptor := catalog.launch, catalog.launch.chain, catalog.selectedPlan
	if err := mobilemtu.LockContext(ctx, &chain.measurementMu); err != nil {
		return empty, err
	}
	defer chain.measurementMu.Unlock()
	if err := desktopSelectedCandidateMeasurementIdle(ctx, launch); err != nil {
		return empty, err
	}
	if err := current(ctx); err != nil {
		return empty, err
	}
	publication, ready, _, _, err := readDesktopSelectedLatencyCapture(ctx, launch)
	if err != nil {
		return empty, err
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || live.Active || live.Failure != "" || live.Reader != ready.Reader || live.Session != ready.Identity.SessionID ||
		live.Config != ready.PreparationConfigSHA256 || live.Interface != ready.InterfaceName || live.Index != int(ready.InterfaceIndex) || live.MTU != ready.MTU {
		return empty, errors.Join(err, errors.New("selected candidate lost its original idle TUN reader"))
	}
	if chain.candidateGeneration == ^uint64(0) {
		return empty, errors.New("selected candidate generation exhausted")
	}
	var sourceMetadata struct {
		Position int `json:"prefix_position"`
	}
	if json.Unmarshal([]byte(descriptor.plan.Metadata()), &sourceMetadata) != nil {
		return empty, errors.New("selected candidate lost its original packet prefix")
	}
	nonce, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	deadline, _ := ctx.Deadline()
	request := desktopSelectedCandidateRequest{Schema: 1, Operation: "selected-packet-candidate-50", Request: nonce,
		Generation: chain.candidateGeneration + 1, Deadline: deadline.UnixMilli(), Path: live.Path, Position: sourceMetadata.Position,
		Candidate: id, InventorySHA: catalog.inventorySHA, Capture: ready, Selected: publication.Selected}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 16384 {
		return empty, errors.New("selected candidate request exceeds its original private bound")
	}
	type retainedFile struct {
		info os.FileInfo
		raw  []byte
	}
	files := map[string]retainedFile{}
	defer func() {
		for _, file := range files {
			clear(file.raw)
		}
	}()
	// Full native source and the exact selected publication are pinned before
	// prepare. These checks cannot rebuild the runtime or refresh a stale trial.
	for _, name := range []string{"sing-box.json", "node-chain-execution-source.json", "node-chain-execution-latency-capture.json"} {
		body, info, err := readDesktopSelectedCandidateFile(ctx, launch, name, mobilemultihop.NodeChainInputLimit)
		if err != nil {
			return empty, err
		}
		files[name] = retainedFile{info, body}
	}
	if string(files["sing-box.json"].raw) != descriptor.preparation.Config() || string(files["node-chain-execution-source.json"].raw) != descriptor.preparation.Source() {
		return empty, errors.New("selected candidate source differs from its original preparation")
	}
	check := func(call context.Context) error {
		if err := pulseCurrent(call); err != nil {
			return err
		}
		for name, file := range files {
			body, info, err := readDesktopSelectedCandidateFile(call, launch, name, mobilemultihop.NodeChainInputLimit)
			valid := err == nil && os.SameFile(file.info, info) && bytes.Equal(file.raw, body)
			clear(body)
			if !valid {
				return errors.Join(err, errors.New("selected candidate changed an original private inode or source"))
			}
		}
		after, err := readDesktopNodeMTUContext(call, launch)
		if err != nil || after.Session != live.Session || after.Config != live.Config || after.Path != live.Path || after.Reader != live.Reader ||
			after.Interface != live.Interface || after.Index != live.Index || after.MTU != live.MTU || after.Active || after.Failure != "" {
			return errors.Join(err, errors.New("selected candidate changed its original TUN reader"))
		}
		return call.Err()
	}
	var sourceInfo, requestInfo, metadataInfo, startInfo, pulseInfo, cancelInfo os.FileInfo
	var capturedMetadata []byte
	var resultOwner retainedFile
	var captureSHA, metadataSHA string
	var pulseSequence uint64
	cleanup := func(call context.Context, stopped bool) error {
		var requestErr error
		if stopped {
			requestErr = retireDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateRequestFile, requestInfo)
		}
		if err := errors.Join(requestErr,
			retireDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateSourceFile, sourceInfo),
			retireDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateMetadataFile, metadataInfo),
			retireDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateStartFile, startInfo),
			retireDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateLiveFile, pulseInfo),
			retireDesktopSelectedCandidateCaptured(call, launch, desktopSelectedCandidateCancelFile, raw, cancelInfo)); err != nil {
			return err
		}
		if resultOwner.info != nil {
			if err := retireDesktopSelectedCandidateCaptured(call, launch, desktopSelectedCandidateResultFile, resultOwner.raw, resultOwner.info); err != nil {
				return err
			}
			clear(resultOwner.raw)
			resultOwner = retainedFile{}
		}
		return nil
	}
	beforeRequestFailure := func(cause error) (hopmeasure.CandidateStatus, error) {
		joined, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		return empty, errors.Join(cause, cleanup(joined, false))
	}
	sourceInfo, err = publishDesktopSelectedCandidateOwned(ctx, launch, desktopSelectedCandidateSourceFile, []byte(catalog.inventory))
	if err != nil {
		return empty, err
	}
	files[desktopSelectedCandidateSourceFile] = retainedFile{sourceInfo, []byte(catalog.inventory)}
	if err := check(ctx); err != nil {
		return beforeRequestFailure(err)
	}
	started := time.Now().UnixMilli()
	requestInfo, err = publishDesktopSelectedCandidateOwned(ctx, launch, desktopSelectedCandidateRequestFile, raw)
	if err != nil {
		return beforeRequestFailure(err)
	}
	chain.candidateGeneration = request.Generation
	readMetadata := func(call context.Context, adopt bool) (bool, error) {
		body, info, err := readDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateMetadataFile, 64<<10)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer clear(body)
		if metadataInfo != nil && (!os.SameFile(metadataInfo, info) || !bytes.Equal(capturedMetadata, body)) {
			return false, errors.New("selected candidate metadata was replaced")
		}
		// Retain the exact original envelope for cancellation even if its
		// descriptive fields fail admission. That cannot authorize Start.
		var envelope desktopSelectedCandidateEnvelope
		if decodePrivateControlJSONBounded(body, &envelope, 64<<10) != nil || envelope.Request != request.Request || envelope.Generation != request.Generation ||
			envelope.InventorySHA != request.InventorySHA || !desktopOrderedDigest.MatchString(envelope.CaptureSHA) {
			return false, errors.New("selected candidate metadata belongs to a different preparation")
		}
		if metadataInfo == nil {
			metadataInfo, capturedMetadata = info, bytes.Clone(body)
			sum := sha256.Sum256(body)
			captureSHA, metadataSHA = envelope.CaptureSHA, hex.EncodeToString(sum[:])
		}
		if adopt {
			verified, digest, verifyErr := descriptor.validateMetadata(request, catalog.revision, body)
			if verifyErr != nil || verified.Revision != catalog.revision || digest != metadataSHA {
				return false, errors.Join(verifyErr, errors.New("selected candidate metadata lost its original catalog"))
			}
			files[desktopSelectedCandidateMetadataFile] = retainedFile{info, bytes.Clone(body)}
		}
		return true, nil
	}
	defer func() { clear(capturedMetadata) }()
	readResult := func(call context.Context) (*desktopSelectedCandidateResult, error) {
		// The child may still be withdrawing an uncommitted success. Only a
		// consumed original request transfers the immutable terminal result.
		if _, _, err := readDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateRequestFile, 16384); !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		body, info, err := readDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateResultFile, 128<<10)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var result desktopSelectedCandidateResult
		if decodePrivateControlJSONBounded(body, &result, 128<<10) != nil || !desktopSelectedCandidateExactFields(body,
			"schema", "operation", "request_id", "generation", "deadline_at", "path_id", "prefix_position", "candidate_id", "inventory_sha256", "capture", "selected_capture", "capture_sha256", "metadata_sha256", "completed_at", "status") {
			return nil, errors.New("selected candidate result is malformed")
		}
		if result.Request != request.Request {
			return nil, errors.New("selected candidate result belongs to a different request")
		}
		if metadataInfo == nil && (result.CaptureSHA != "" || result.MetadataSHA != "") {
			if _, err := readMetadata(call, false); err != nil {
				return nil, err
			}
		}
		if !reflect.DeepEqual(result.desktopSelectedCandidateRequest, request) || result.CaptureSHA != captureSHA || result.MetadataSHA != metadataSHA ||
			result.CompletedAt < started-1 || result.CompletedAt > time.Now().Add(time.Second).UnixMilli() ||
			result.Status.Request != request.Request || !result.Status.Complete || !result.Status.Drained {
			return nil, errors.New("selected candidate result changed its original capture or did not drain")
		}
		if _, _, err := readDesktopSelectedCandidateFile(call, launch, desktopSelectedCandidateRequestFile, 16384); !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if resultOwner.info == nil {
			resultOwner = retainedFile{info, bytes.Clone(body)}
		} else if !os.SameFile(resultOwner.info, info) || !bytes.Equal(resultOwner.raw, body) {
			return nil, errors.New("selected candidate result changed after its original acknowledgment")
		}
		return &result, nil
	}
	retirement := &desktopNodeChainCandidateRetirement{launch: launch, request: request.Request}
	retirement.run = func(call context.Context) error {
		if result, err := readResult(call); err == nil && result != nil {
			return cleanup(call, false)
		}
		if stopped, _ := readDesktopNodeStoppedContext(call, launch); stopped {
			return cleanup(call, true)
		}
		info, statErr := launch.directoryRoot.Lstat(desktopSelectedCandidateCancelFile)
		if errors.Is(statErr, os.ErrNotExist) {
			cancelInfo, statErr = publishDesktopSelectedCandidateOwned(call, launch, desktopSelectedCandidateCancelFile, raw)
			if statErr != nil {
				return statErr
			}
		} else if statErr != nil || cancelInfo == nil || !os.SameFile(cancelInfo, info) {
			return errors.New("selected candidate cannot replace another cancellation inode")
		}
		poll := time.NewTicker(100 * time.Millisecond)
		defer poll.Stop()
		for {
			if result, err := readResult(call); err == nil && result != nil {
				return cleanup(call, false)
			}
			if stopped, _ := readDesktopNodeStoppedContext(call, launch); stopped {
				return cleanup(call, true)
			}
			select {
			case <-call.Done():
				return call.Err()
			case <-poll.C:
			}
		}
	}
	chain.mu.Lock()
	chain.candidatePending = retirement
	chain.mu.Unlock()
	drain := func(cause error) (hopmeasure.CandidateStatus, error) {
		joined, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		if err := retirement.run(joined); err != nil && !retirement.joined.Load() {
			return empty, &desktopNodeChainCandidatePendingError{retirement, errors.Join(cause, err)}
		}
		finishDesktopNodeChainCandidateRetirement(retirement)
		return empty, cause
	}
	pulse := func(call context.Context) error {
		if err := check(call); err != nil {
			return err
		}
		pulseSequence++
		value := desktopSelectedCandidatePulse{Schema: 1, Request: request.Request, CaptureSHA: captureSHA, Revision: catalog.revision,
			Sequence: pulseSequence, ObservedAt: time.Now().UnixMilli()}
		var err error
		pulseInfo, err = publishDesktopSelectedCandidatePulse(call, launch, value, pulseInfo)
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	startPublished := false
	for {
		if err := check(ctx); err != nil {
			return drain(errors.Join(err, ctx.Err()))
		}
		if !startPublished {
			available, err := readMetadata(ctx, true)
			if err != nil {
				return drain(err)
			}
			if available {
				if err := pulse(ctx); err != nil {
					return drain(err)
				}
				start := desktopSelectedCandidateStart{request.Request, request.Generation, captureSHA, metadataSHA}
				body, _ := json.Marshal(start)
				startInfo, err = publishDesktopSelectedCandidateOwned(ctx, launch, desktopSelectedCandidateStartFile, body)
				if err != nil {
					return drain(err)
				}
				files[desktopSelectedCandidateStartFile] = retainedFile{startInfo, body}
				startPublished = true
			}
		} else if err := pulse(ctx); err != nil {
			return drain(err)
		}
		result, err := readResult(ctx)
		if err != nil {
			return drain(err)
		}
		if result != nil {
			if err := cleanup(ctx, false); err != nil {
				return drain(err)
			}
			finishDesktopNodeChainCandidateRetirement(retirement)
			if !startPublished || result.CompletedAt > request.Deadline || result.Status.Failure != "" {
				return empty, errors.New("selected candidate failed, changed or expired")
			}
			if err := current(ctx); err != nil {
				return empty, err
			}
			if err := validateDesktopSelectedCandidateStatus(descriptor, id, result.Status, time.Now()); err != nil {
				return empty, err
			}
			return result.Status, nil
		}
		select {
		case <-ctx.Done():
			return drain(ctx.Err())
		case <-ticker.C:
		}
	}
}

func publishDesktopSelectedCandidatePulse(ctx context.Context, launch *desktopNodeLaunch, value desktopSelectedCandidatePulse, previous os.FileInfo) (os.FileInfo, error) {
	const name = "node-chain-execution-candidate-live.json"
	raw, err := json.Marshal(value)
	if err != nil {
		return previous, err
	}
	if previous == nil {
		return publishDesktopSelectedCandidateOwned(ctx, launch, name, raw)
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return previous, err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return previous, err
	}
	actual, err := launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(previous, actual) {
		return previous, errors.New("candidate catalog pulse was replaced")
	}
	temporary := "." + name + ".pending"
	file, err := launch.directoryRoot.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return previous, err
	}
	info, statErr := file.Stat()
	defer func() {
		_ = file.Close()
		if actual, err := launch.directoryRoot.Lstat(temporary); err == nil && info != nil && os.SameFile(info, actual) {
			_ = launch.directoryRoot.Remove(temporary)
		}
	}()
	if statErr != nil {
		return previous, statErr
	}
	if _, err := file.Write(raw); err != nil {
		return previous, err
	}
	if err := file.Sync(); err != nil {
		return previous, err
	}
	if err := file.Close(); err != nil {
		return previous, err
	}
	actual, err = launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(previous, actual) || ctx.Err() != nil {
		return previous, errors.New("candidate catalog pulse lost its original owner")
	}
	if err := launch.directoryRoot.Rename(temporary, name); err != nil {
		return previous, err
	}
	actual, err = launch.directoryRoot.Lstat(name)
	if err != nil || !os.SameFile(info, actual) {
		return previous, errors.New("candidate catalog pulse changed during publication")
	}
	return actual, nil
}

func retireDesktopSelectedCandidateFile(ctx context.Context, launch *desktopNodeLaunch, name string, info os.FileInfo) error {
	if info == nil {
		return nil
	}
	if name != desktopSelectedCandidateSourceFile && name != desktopSelectedCandidateLiveFile && name != desktopSelectedCandidateRequestFile && name != desktopSelectedCandidateMetadataFile && name != desktopSelectedCandidateStartFile {
		return errors.New("invalid candidate cleanup source")
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	actual, err := launch.directoryRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !os.SameFile(info, actual) {
		return errors.New("candidate cleanup source changed")
	}
	return launch.directoryRoot.Remove(name)
}

func retireDesktopSelectedCandidateCaptured(ctx context.Context, launch *desktopNodeLaunch, name string, expected []byte, captured os.FileInfo) error {
	limit := int64(16384)
	switch name {
	case desktopSelectedCandidateCancelFile:
	case desktopSelectedCandidateResultFile:
		limit = 128 << 10
	default:
		return errors.New("invalid selected candidate terminal cleanup")
	}
	if err := mobilemtu.LockContext(ctx, &launch.workspaceMu); err != nil {
		return err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return err
	}
	before, err := launch.directoryRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if name == desktopSelectedCandidateResultFile && captured != nil {
			return errors.New("selected candidate original result disappeared before retirement")
		}
		return nil
	}
	actual, readErr := readDesktopRuntimeSnapshot(launch.directoryRoot, name, limit)
	after, statErr := launch.directoryRoot.Lstat(name)
	if err != nil || readErr != nil || statErr != nil || captured == nil || !os.SameFile(captured, before) || !os.SameFile(before, after) || !bytes.Equal(actual, expected) {
		return errors.New("selected candidate terminal file changed before drain")
	}
	return launch.directoryRoot.Remove(name)
}
