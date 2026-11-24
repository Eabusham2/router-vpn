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
type desktopCandidateDescription interface {
	Metadata() string
	CaptureSHA256() string
}

type desktopSelectedCandidateDescriptor struct {
	socksPolicy   *mobilemultihop.DesktopNodeChainSOCKSPolicy
	connectPolicy *mobilemultihop.DesktopNodeChainCONNECTPolicy
	purpose       *orderedCandidatePreparation
	self          *desktopSelectedCandidateDescriptor
	launch        *desktopNodeLaunch
	execution     *desktopNodeChainExecutionLaunch
	preparation   *mobilemultihop.NodeChainExecutionPreparation
	policy        *mobilemultihop.DesktopNodeChainPolicy
	original      *mobilemultihop.NodeChain
	plan          desktopCandidateDescription
	mu            sync.Mutex
	metadata      string
	expectedRaw   string
	expected      *desktopSelectedCandidateInventory
	selected      string
	ready         *mobilemultihop.DesktopNodeChainExecutionReadyRecord
}

type desktopSelectedCandidateTarget struct {
	ID     string `json:"id"`
	Source string `json:"source_sha256"`
}

type desktopSelectedCandidateInventory struct {
	Position    int                              `json:"prefix_position"`
	Prefix      string                           `json:"prefix_id"`
	Targets     []desktopSelectedCandidateTarget `json:"targets"`
	digest      string
	targetBytes int
}

// The descriptor owns the original full ordered membership. Revalidate its
// immutable source before reusing the precomputed canonical target digest.
func (d *desktopSelectedCandidateDescriptor) originalInventory() (*desktopSelectedCandidateInventory, error) {
	raw := d.plan.Metadata()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.expected != nil && raw == d.expectedRaw {
		return d.expected, nil
	}
	if raw == "" || d.expected != nil {
		return nil, errors.New("selected source inventory was replaced")
	}
	var expected desktopSelectedCandidateInventory
	if json.Unmarshal([]byte(raw), &expected) != nil || len(expected.Targets) == 0 {
		return nil, errors.New("invalid selected candidate inventory")
	}
	targets, err := json.Marshal(expected.Targets)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(targets)
	expected.digest = hex.EncodeToString(sum[:])
	expected.targetBytes = len(targets)
	d.expectedRaw, d.expected = raw, &expected
	return d.expected, nil
}

type desktopSelectedCandidateMetadata struct {
	TargetTotal       int                              `json:"target_total,omitempty"`
	TargetOffset      int                              `json:"target_offset,omitempty"`
	TargetsSHA256     string                           `json:"targets_sha256,omitempty"`
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
	return desktopSelectedCandidateSourceAllowedForPurpose(launch, nil)
}

func desktopSelectedCandidateSourceAllowedForPurpose(launch *desktopNodeLaunch, purpose *orderedCandidatePreparation) bool {
	e := desktopNodeChainLaunchExecution(launch)
	return e != nil && launch.command != nil && launch.chain.preparation == purpose &&
		(purpose == nil || purpose.ownsSelectedDraft(launch, e)) &&
		e.original == launch.chain && e.preparation != nil && desktopSelectedCandidateFamily(e)
}

func desktopSelectedCandidateFamily(e *desktopNodeChainExecutionLaunch) bool {
	if e == nil || e.original == nil || !e.original.hasPolicy() {
		return false
	}
	c := e.original
	if c.socksPolicy != nil || c.connectPolicy != nil {
		return c.socksPolicy != nil && e.socksPhysical != nil || c.connectPolicy != nil && e.connectPhysical != nil
	}
	return c.policy != nil && (e.physical != nil || e.openvpnPhysical != nil || e.multiplePhysical != nil)
}

func desktopSelectedCandidatePosition(launch *desktopNodeLaunch, position int) bool {
	e := desktopNodeChainLaunchExecution(launch)
	if e == nil {
		return true
	}
	if launch == nil || launch.chain == nil || position < 0 || position >= len(launch.chain.selection.Nodes) || !mobilemultihop.NodeChainPrefixMode(launch.chain.selection.Nodes[position].Mode) {
		return false
	}
	return e.socksPhysical == nil && e.connectPhysical == nil || position == 0
}

func captureDesktopSelectedCandidateDescriptor(launch *desktopNodeLaunch, position int, inventory string) (*desktopSelectedCandidateDescriptor, error) {
	return captureDesktopSelectedCandidateDescriptorForPurpose(launch, position, inventory, nil)
}

func captureDesktopSelectedCandidateDescriptorForPurpose(launch *desktopNodeLaunch, position int, inventory string, purpose *orderedCandidatePreparation) (*desktopSelectedCandidateDescriptor, error) {
	bad := errors.New("selected candidate timing requires its original complete packet source")
	if !desktopSelectedCandidateSourceAllowedForPurpose(launch, purpose) || position < 0 || position >= len(launch.chain.selection.Nodes)-1 || !desktopSelectedCandidatePosition(launch, position) {
		return nil, bad
	}
	e := launch.chain.execution
	if e.bound(launch) != nil {
		return nil, bad
	}
	d := &desktopSelectedCandidateDescriptor{purpose: purpose, launch: launch, execution: e, preparation: e.preparation,
		policy: launch.chain.policy, socksPolicy: launch.chain.socksPolicy, connectPolicy: launch.chain.connectPolicy}
	d.self = d
	var err error
	if d.socksPolicy != nil || d.connectPolicy != nil {
		d.plan, err = e.preparation.DescribeDesktopTypedEntryCandidate(d.socksPolicy, d.connectPolicy, position, inventory)
	} else {
		d.original = launch.chain.policy.OriginalChain()
		if e.multiplePhysical != nil {
			original, sourceErr := e.preparation.OriginalMultipleImportedSource()
			if sourceErr != nil || original != d.original {
				return nil, bad
			}
			d.plan, err = original.NewMultipleImportedCandidatePlan(position, inventory)
		} else {
			d.plan, err = d.original.NewCandidatePlan(position, inventory)
		}
	}
	if err != nil {
		return nil, err
	}
	return d, d.sourceCurrent()
}

func (d *desktopSelectedCandidateDescriptor) ownsOriginalFamily() bool {
	return d != nil && d.self == d && desktopSelectedCandidateSourceAllowedForPurpose(d.launch, d.purpose) &&
		d.launch.chain.execution == d.execution && d.execution.preparation == d.preparation &&
		d.launch.chain.policy == d.policy && d.launch.chain.socksPolicy == d.socksPolicy && d.launch.chain.connectPolicy == d.connectPolicy && d.plan != nil &&
		((d.original != nil && d.policy != nil && d.socksPolicy == nil && d.connectPolicy == nil) || (d.original == nil && d.policy == nil && (d.socksPolicy != nil) != (d.connectPolicy != nil)))
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
		publication, live, _, _, err := readDesktopSelectedLatencyCaptureForPurpose(ctx, d.launch, d.purpose)
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
		decodePrivateControlJSONBounded(envelope.Metadata, &metadata, 32<<10) != nil {
		return envelope, "", bad
	}
	names := []string{"schema", "capture_sha256", "prefix_position", "prefix_id", "source_sha256", "config_sha256", "targets", "preparation_source_sha256", "preparation_config_sha256", "requested_execution", "execution", "selection_epoch"}
	expected, err := d.originalInventory()
	if err != nil {
		return envelope, "", bad
	}
	switch metadata.Schema {
	case 1:
		if !reflect.DeepEqual(metadata.Targets, expected.Targets) {
			return envelope, "", bad
		}
	case 2:
		names = append(names, "target_total", "target_offset", "targets_sha256")
		if len(envelope.Metadata) > 12<<10 || metadata.TargetTotal != len(expected.Targets) || metadata.TargetOffset < 0 || metadata.TargetOffset >= metadata.TargetTotal ||
			metadata.TargetsSHA256 != expected.digest || len(metadata.Targets) != 1 || metadata.Targets[0].ID != request.Candidate ||
			metadata.Targets[0] != expected.Targets[metadata.TargetOffset] {
			return envelope, "", bad
		}
	default:
		return envelope, "", bad
	}
	if !desktopSelectedCandidateExactFields(envelope.Metadata, names...) ||
		metadata.Capture != envelope.CaptureSHA || metadata.Position != expected.Position || metadata.Position != request.Position || metadata.Prefix != expected.Prefix ||
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
	if metadata.Schema == 1 && len(canonical) > 24<<10 {
		return envelope, "", bad
	}
	if metadata.Schema == 2 {
		legacy := make(map[string]json.RawMessage, len(fields))
		for key, value := range fields {
			switch key {
			case "target_offset", "target_total", "targets_sha256":
				continue
			}
			legacy[key] = value
		}
		legacy["schema"] = json.RawMessage("1")
		legacy["targets"] = json.RawMessage("[]")
		header, err := json.Marshal(legacy)
		if err != nil || len(header)+expected.targetBytes-2 <= 24<<10 {
			return envelope, "", bad
		}
	}
	for _, target := range metadata.Targets {
		if !validProfileID(target.ID) || !desktopOrderedDigest.MatchString(target.Source) {
			return envelope, "", bad
		}
	}
	// Different candidate requests may publish different rows. Their immutable
	// full-inventory digest and every execution/epoch field must stay identical.
	if metadata.Schema == 2 {
		delete(fields, "targets")
		delete(fields, "target_offset")
		canonical, err = json.Marshal(fields)
		if err != nil {
			return envelope, "", bad
		}
	}
	stable := string(canonical)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ready != nil && (d.selected != request.Selected || !sameDesktopSelectedLatencyReady(*d.ready, request.Capture) || d.metadata != stable) {
		return envelope, "", bad
	}
	copy := request.Capture
	d.ready, d.selected, d.metadata = &copy, request.Selected, stable
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
