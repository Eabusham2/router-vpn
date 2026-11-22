package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// The parent compiles an immutable description of eligible packet prefixes
// and candidate sources. Only the original selected child can supply the live
// plan capture, which includes its retained trial and selection epoch.
type desktopSelectedCandidateDescriptor struct {
	self        *desktopSelectedCandidateDescriptor
	launch      *desktopNodeLaunch
	execution   *desktopNodeChainExecutionLaunch
	preparation *mobilemultihop.NodeChainExecutionPreparation
	policy      *mobilemultihop.DesktopNodeChainPolicy
	original    *mobilemultihop.NodeChain
	plan        *mobilemultihop.NodeChainCandidatePlan
	mu          sync.Mutex
	metadata    string
	selected    string
	ready       *mobilemultihop.DesktopNodeChainExecutionReadyRecord
}

type desktopSelectedCandidateTarget struct {
	ID     string `json:"id"`
	Source string `json:"source_sha256"`
}

type desktopSelectedCandidateMetadata struct {
	Schema            int                              `json:"schema"`
	Capture           string                           `json:"capture_sha256"`
	Position          int                              `json:"prefix_position"`
	Prefix            string                           `json:"prefix_id"`
	Source            string                           `json:"source_sha256"`
	Config            string                           `json:"config_sha256"`
	Targets           []desktopSelectedCandidateTarget `json:"targets"`
	PreparationSource string                           `json:"preparation_source_sha256"`
	PreparationConfig string                           `json:"preparation_config_sha256"`
	Requested         string                           `json:"requested_execution"`
	Execution         string                           `json:"execution"`
	Epoch             uint64                           `json:"selection_epoch"`
}

func desktopSelectedCandidateSourceAllowed(launch *desktopNodeLaunch) bool {
	e := desktopNodeChainLaunchExecution(launch)
	return e != nil && launch.command != nil && launch.chain.preparation == nil &&
		launch.chain.policy != nil && launch.chain.socksPolicy == nil && launch.chain.connectPolicy == nil &&
		e.original == launch.chain && e.preparation != nil &&
		(e.physical != nil || e.openvpnPhysical != nil || e.multiplePhysical != nil)
}

func captureDesktopSelectedCandidateDescriptor(launch *desktopNodeLaunch, position int, inventory string) (*desktopSelectedCandidateDescriptor, error) {
	bad := errors.New("selected candidate timing requires its original complete packet source")
	if !desktopSelectedCandidateSourceAllowed(launch) || position < 0 || position >= len(launch.chain.selection.Nodes)-1 {
		return nil, bad
	}
	e := launch.chain.execution
	if e.bound(launch) != nil {
		return nil, bad
	}
	d := &desktopSelectedCandidateDescriptor{launch: launch, execution: e, preparation: e.preparation,
		policy: launch.chain.policy, original: launch.chain.policy.OriginalChain()}
	d.self = d
	var err error
	if e.multiplePhysical != nil {
		original, sourceErr := e.preparation.OriginalMultipleImportedSource()
		if sourceErr != nil || original != d.original {
			return nil, bad
		}
		d.plan, err = original.NewMultipleImportedCandidatePlan(position, inventory)
	} else {
		d.plan, err = d.original.NewCandidatePlan(position, inventory)
	}
	if err != nil {
		return nil, err
	}
	return d, d.sourceCurrent()
}

func (d *desktopSelectedCandidateDescriptor) ownsOriginalFamily() bool {
	return d != nil && d.self == d && desktopSelectedCandidateSourceAllowed(d.launch) &&
		d.launch.chain.execution == d.execution && d.execution.preparation == d.preparation &&
		d.original != nil && d.launch.chain.policy == d.policy && d.plan != nil
}

func (d *desktopSelectedCandidateDescriptor) sourceCurrent() error {
	if !d.ownsOriginalFamily() || d.execution.bound(d.launch) != nil || d.plan.Metadata() == "" ||
		!desktopOrderedDigest.MatchString(d.plan.CaptureSHA256()) {
		return errors.New("selected candidate descriptor changed its original source or preparation")
	}
	return nil
}

func (d *desktopSelectedCandidateDescriptor) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || d.sourceCurrent() != nil {
		return errors.New("selected candidate source is no longer current")
	}
	d.mu.Lock()
	selected, ready := d.selected, d.ready
	d.mu.Unlock()
	if ready != nil {
		publication, live, _, _, err := readDesktopSelectedLatencyCapture(ctx, d.launch)
		if err != nil || publication.Selected != selected || !sameDesktopSelectedLatencyReady(*ready, live) {
			return errors.Join(err, errors.New("selected candidate changed its original native epoch"))
		}
	}
	return ctx.Err()
}

// No live capture is synthesized from source-only metadata. The six-field
// envelope must be the exact canonical bytes published by the original child.
func (d *desktopSelectedCandidateDescriptor) validateMetadata(request desktopSelectedCandidateRequest, revision string, raw []byte) (desktopSelectedCandidateEnvelope, string, error) {
	var envelope desktopSelectedCandidateEnvelope
	var metadata desktopSelectedCandidateMetadata
	bad := errors.New("selected candidate metadata changed its original source, prefix or native epoch")
	if d.sourceCurrent() != nil || decodePrivateControlJSONBounded(raw, &envelope, 64<<10) != nil ||
		!desktopSelectedCandidateExactFields(raw, "request_id", "generation", "inventory_sha256", "capture_sha256", "revision", "metadata") {
		return envelope, "", bad
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonical) || envelope.Request != request.Request || envelope.Generation != request.Generation ||
		envelope.InventorySHA != request.InventorySHA || !desktopOrderedDigest.MatchString(envelope.CaptureSHA) || envelope.Revision == "" || envelope.Revision != revision ||
		decodePrivateControlJSONBounded(envelope.Metadata, &metadata, 32<<10) != nil ||
		!desktopSelectedCandidateExactFields(envelope.Metadata, "schema", "capture_sha256", "prefix_position", "prefix_id", "source_sha256", "config_sha256", "targets", "preparation_source_sha256", "preparation_config_sha256", "requested_execution", "execution", "selection_epoch") {
		return envelope, "", bad
	}
	var expected struct {
		Position int                              `json:"prefix_position"`
		Prefix   string                           `json:"prefix_id"`
		Targets  []desktopSelectedCandidateTarget `json:"targets"`
	}
	if json.Unmarshal([]byte(d.plan.Metadata()), &expected) != nil || metadata.Schema != 1 ||
		metadata.Capture != envelope.CaptureSHA || metadata.Position != expected.Position || metadata.Position != request.Position ||
		metadata.Prefix != expected.Prefix || !reflect.DeepEqual(metadata.Targets, expected.Targets) ||
		metadata.Source != request.Capture.Identity.SourceSHA256 || metadata.Config != request.Capture.Identity.ConfigSHA256 ||
		metadata.PreparationSource != request.Capture.PreparationSourceSHA256 || metadata.PreparationConfig != request.Capture.PreparationConfigSHA256 ||
		metadata.Requested != d.preparation.Execution() || metadata.Execution != request.Capture.Progress.Execution ||
		metadata.Epoch == 0 || metadata.Epoch != request.Capture.SelectionEpoch {
		return envelope, "", bad
	}
	// Shared metadata is a canonical JSON map. Check its exact spelling without
	// converting epoch integers through floating point or accepting extra keys.
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Metadata, &fields) != nil {
		return envelope, "", bad
	}
	canonical, err = json.Marshal(fields)
	if err != nil || !bytes.Equal(canonical, envelope.Metadata) {
		return envelope, "", bad
	}
	for _, target := range metadata.Targets {
		if !validProfileID(target.ID) || !desktopOrderedDigest.MatchString(target.Source) {
			return envelope, "", bad
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ready != nil && (d.selected != request.Selected || !sameDesktopSelectedLatencyReady(*d.ready, request.Capture) || d.metadata != string(envelope.Metadata)) {
		return envelope, "", bad
	}
	copy := request.Capture
	d.ready, d.selected, d.metadata = &copy, request.Selected, string(envelope.Metadata)
	digest := sha256.Sum256(raw)
	return envelope, hex.EncodeToString(digest[:]), nil
}

func desktopSelectedCandidateExactFields(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if value, exists := fields[name]; !exists || bytes.Equal(value, []byte("null")) {
			return false
		}
	}
	return true
}

func validateDesktopSelectedCandidateStatus(d *desktopSelectedCandidateDescriptor, id string, status hopmeasure.CandidateStatus, now time.Time) error {
	bad := errors.New("selected candidate result lost its original fifty-sample capture")
	if !d.ownsOriginalFamily() {
		return bad
	}
	d.mu.Lock()
	raw := d.metadata
	d.mu.Unlock()
	var metadata desktopSelectedCandidateMetadata
	if json.Unmarshal([]byte(raw), &metadata) != nil || !desktopOrderedDigest.MatchString(metadata.Capture) || status.CaptureSHA256 != metadata.Capture {
		return bad
	}
	// The source-only compiler verifies the exact target and every numeric
	// receipt invariant. Its static capture is used only in this descriptive
	// copy after the original selected capture has independently matched above.
	description := status
	description.CaptureSHA256 = d.plan.CaptureSHA256()
	return validateDesktopNodeChainCandidateStatus(d.plan, id, description, now)
}
