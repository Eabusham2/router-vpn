package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

const desktopSelectedLatencyCaptureLimit = 8192
const desktopSelectedExtendedCaptureLimit = 512 + 1536*mobilemultihop.NodeChainExtendedLocalMaximumNodes

// A larger envelope is available only for the qualified original inventory.
// This size calculation never grants a live source or a measurement owner.
func desktopSelectedCaptureBound(count, legacy int) int {
	if count > mobilemultihop.NodeChainMaximumNodes && count <= mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		return max(legacy, 16384, 512+1536*count)
	}
	return legacy
}

func desktopSelectedSourceBound(launch *desktopNodeLaunch, legacy int) int {
	e := desktopNodeChainLaunchExecution(launch)
	if e != nil && e.preparation != nil && e.preparation.ExtendedOriginalNodeCount() > mobilemultihop.NodeChainMaximumNodes {
		return max(legacy, e.preparation.ExtendedOriginalStatusLimit())
	}
	return legacy
}

// This is a descriptive copy of the actual retained native facade's capture.
// It cannot construct a runtime, choose an execution, or grant live authority.
type desktopSelectedLatencyCapture struct {
	Schema           int                                     `json:"schema"`
	SourceSHA256     string                                  `json:"source_sha256"`
	ConfigSHA256     string                                  `json:"config_sha256"`
	GenerationSHA256 string                                  `json:"generation_sha256"`
	Execution        string                                  `json:"selected_execution"`
	Nodes            []desktopSelectedLatencyNode            `json:"nodes"`
	MultipleImported *desktopSelectedLatencyMultipleImported `json:"multiple_imported,omitempty"`
}

type desktopSelectedLatencyMultipleImported struct {
	Schema               int                            `json:"schema"`
	OriginalSourceSHA256 string                         `json:"original_source_sha256"`
	Public               []desktopSelectedLatencyPublic `json:"public"`
}

type desktopSelectedLatencyPublic struct {
	Position     int    `json:"position"`
	Tag          string `json:"tag"`
	SourceSHA256 string `json:"source_sha256"`
}

type desktopSelectedLatencyNode struct {
	NodeID   string `json:"node_id"`
	Position int    `json:"position"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
}

type desktopSelectedLatencyPublication struct {
	Schema   int             `json:"schema"`
	Kind     string          `json:"kind"`
	Capture  json.RawMessage `json:"capture"`
	Selected string          `json:"selected_capture"`
}

func decodeDesktopSelectedLatencyCapture(raw string) (desktopSelectedLatencyCapture, []desktopOrderedLatencyNode, error) {
	var capture desktopSelectedLatencyCapture
	bad := errors.New("selected fifty requires its complete original native capture")
	if len(raw) == 0 || len(raw) > desktopSelectedExtendedCaptureLimit || decodePrivateControlJSONBounded([]byte(raw), &capture, desktopSelectedExtendedCaptureLimit) != nil ||
		capture.Schema != 1 || !desktopOrderedDigest.MatchString(capture.SourceSHA256) ||
		!desktopOrderedDigest.MatchString(capture.ConfigSHA256) || !desktopOrderedDigest.MatchString(capture.GenerationSHA256) ||
		capture.Execution != "local" && capture.Execution != "server" || len(capture.Nodes) < 2 || len(capture.Nodes) > mobilemultihop.NodeChainExtendedLocalMaximumNodes ||
		len(raw) > desktopSelectedCaptureBound(len(capture.Nodes), desktopSelectedLatencyCaptureLimit) {
		return capture, nil, bad
	}
	// The producer exports this canonical string. A second spelling is not a
	// second native capture, even when it would decode to equal field values.
	canonical, err := json.Marshal(capture)
	if err != nil || string(canonical) != raw {
		return capture, nil, bad
	}
	if err := capture.validateMultipleImportedShape(); err != nil {
		return capture, nil, err
	}
	nodes := make([]desktopOrderedLatencyNode, len(capture.Nodes))
	seen := map[string]bool{}
	for position, row := range capture.Nodes {
		role, kind, label, metric, _ := capture.meaning(position, row.Kind)
		if row.Position != position || !validProfileID(row.NodeID) || seen[row.NodeID] || kind == "" || row.Role != role {
			return capture, nil, bad
		}
		seen[row.NodeID] = true
		nodes[position] = desktopOrderedLatencyNode{NodeID: row.NodeID, Position: position, Role: role, Kind: kind, Label: label, Measurement: metric}
	}
	return capture, nodes, nil
}

func (capture desktopSelectedLatencyCapture) meaning(position int, kind string) (string, string, string, string, string) {
	return desktopSelectedLatencyMeaningSource(position, len(capture.Nodes), kind, capture.Execution, capture.MultipleImported != nil, capture.privateStreamShape())
}

func desktopSelectedLatencyMeaningSource(position, count int, capturedKind, execution string, multiple, privateStream bool) (role, kind, label, metric, endpoint string) {
	if execution != "local" && execution != "server" || count < 2 || count > mobilemultihop.NodeChainExtendedLocalMaximumNodes || count > mobilemultihop.NodeChainMaximumNodes && !multiple || position < 0 || position >= count ||
		capturedKind != "private-node" && capturedKind != "public-path" ||
		count > mobilemultihop.NodeChainMaximumNodes && !privateStream && (position == 0 || position == count-1) != (capturedKind == "private-node") ||
		capturedKind == "public-path" && (count < 3 || position == 0 || position == count-1 || !multiple && position != count-2) {
		return
	}
	role = "intermediate"
	if position == 0 {
		role = "entry"
	} else if position == count-1 {
		role = "exit"
	}
	kind = capturedKind
	label = fmt.Sprintf("Cumulative %s path through node %d of %d", execution, position+1, count)
	metric = "routed-private-response-including-connection"
	if kind == "public-path" {
		label = fmt.Sprintf("Cumulative %s path through custom node %d of %d → Cloudflare edge", execution, position+1, count)
		metric = "routed-https-response-after-tls"
		endpoint = "https://" + hopmeasure.PublicHost + "/__down?bytes=1"
	}
	return
}

func (capture desktopSelectedLatencyCapture) privateStreamShape() bool {
	count, multiple := len(capture.Nodes), capture.MultipleImported
	if count < 4 || count > mobilemultihop.NodeChainExtendedLocalMaximumNodes || multiple == nil || multiple.Schema != 6 ||
		capture.Nodes[0].Kind != "private-node" || capture.Nodes[count-1].Kind != "private-node" || capture.Nodes[1].Kind != "public-path" {
		return false
	}
	private := 0
	for _, row := range capture.Nodes[1 : count-1] {
		if row.Kind == "private-node" {
			private++
		} else if row.Kind != "public-path" {
			return false
		}
	}
	return private > 0 && len(multiple.Public) == count-private-2
}

// Historical shape has no native authority. Live publication additionally
// matches every tag and digest against the original typed projection below.
func (capture desktopSelectedLatencyCapture) validateMultipleImportedShape() error {
	multiple := capture.MultipleImported
	if multiple == nil {
		if len(capture.Nodes) > mobilemultihop.NodeChainMaximumNodes {
			return errors.New("extended selected capture requires every original imported interior")
		}
		return nil
	}
	bad := errors.New("selected fifty lost its complete multiple imported capture")
	if multiple.Schema != 6 || !desktopOrderedDigest.MatchString(capture.SourceSHA256) || !desktopOrderedDigest.MatchString(multiple.OriginalSourceSHA256) || len(multiple.Public) == 0 || len(multiple.Public) > len(capture.Nodes)-2 {
		return bad
	}
	if len(capture.Nodes) > mobilemultihop.NodeChainMaximumNodes && (len(multiple.Public) != len(capture.Nodes)-2 && !capture.privateStreamShape() ||
		capture.Nodes[0].Kind != "private-node" || capture.Nodes[len(capture.Nodes)-1].Kind != "private-node") {
		return bad
	}
	public := make(map[int]bool, len(multiple.Public))
	previous := 0
	for _, row := range multiple.Public {
		if row.Position <= previous || row.Position >= len(capture.Nodes)-1 || capture.Nodes[row.Position].Kind != "public-path" || !desktopOrderedDigest.MatchString(row.SourceSHA256) {
			return bad
		}
		if capture.Execution == "server" {
			if row.Tag != fmt.Sprintf("routervpn-chain-server-%d-%s", row.Position, capture.SourceSHA256[:16]) {
				return bad
			}
		} else {
			prefix := fmt.Sprintf("routervpn-chain-%d-%s-node-", row.Position, row.SourceSHA256[:12])
			suffix, ok := strings.CutPrefix(row.Tag, prefix)
			if !ok || len(suffix) != 12 || strings.ToLower(suffix) != suffix {
				return bad
			}
			if _, err := hex.DecodeString(suffix); err != nil {
				return bad
			}
		}
		public[row.Position], previous = true, row.Position
	}
	for position, row := range capture.Nodes {
		if (row.Kind == "public-path") != public[position] {
			return bad
		}
	}
	return nil
}

// Each concrete parser validates the exact original projection before a common
// descriptive view is returned. No Kind conversion grants generic authority.
func (e *desktopNodeChainExecutionLaunch) parseSelectedLatencyReady(raw []byte, projection *mobilemultihop.NodeChainExecutionProjection, identity mobilemultihop.NodeChainIdentity, transfer string) (mobilemultihop.DesktopNodeChainExecutionReadyRecord, error) {
	if e.multiplePhysical != nil {
		r, err := mobilemultihop.ParseDesktopNodeChainMultipleImportedExecutionAdoptedReadyRecord(raw, projection, identity, transfer)
		return mobilemultihop.DesktopNodeChainExecutionReadyRecord(r), err
	}
	if e.openvpnPhysical != nil {
		r, err := mobilemultihop.ParseDesktopNodeChainOpenVPNExecutionAdoptedReadyRecord(raw, projection, identity, transfer)
		return mobilemultihop.DesktopNodeChainExecutionReadyRecord(r), err
	}
	if e.socksPhysical != nil {
		r, err := mobilemultihop.ParseDesktopNodeChainSOCKSExecutionAdoptedReadyRecord(raw, projection, identity, transfer)
		return mobilemultihop.DesktopNodeChainExecutionReadyRecord(r), err
	}
	if e.connectPhysical != nil {
		r, err := mobilemultihop.ParseDesktopNodeChainCONNECTExecutionAdoptedReadyRecord(raw, projection, identity, transfer)
		return mobilemultihop.DesktopNodeChainExecutionReadyRecord(r), err
	}
	return mobilemultihop.ParseDesktopNodeChainExecutionAdoptedReadyRecord(raw, projection, identity, transfer)
}

func sameDesktopSelectedLatencyReady(original, live mobilemultihop.DesktopNodeChainExecutionReadyRecord) bool {
	if original.ObservedAt <= 0 || live.ObservedAt < original.ObservedAt {
		return false
	}
	// A fresh validated heartbeat may refresh its prefix response timings.
	// The captured publication remains immutable; no node, proof flag, reader,
	// generation, epoch, MTU, comparison or identity is normalized away.
	if len(original.Progress.Prefixes) != len(live.Progress.Prefixes) {
		return false
	}
	live.Progress.Prefixes = append([]mobilemultihop.NodeChainPrefixProgress(nil), live.Progress.Prefixes...)
	for position := range original.Progress.Prefixes {
		oldMS, newMS := original.Progress.Prefixes[position].ResponseMS, live.Progress.Prefixes[position].ResponseMS
		if oldMS <= 0 || newMS <= 0 || math.IsNaN(oldMS) || math.IsNaN(newMS) || math.IsInf(oldMS, 0) || math.IsInf(newMS, 0) {
			return false
		}
		live.Progress.Prefixes[position].ResponseMS = oldMS
	}
	live.ObservedAt = original.ObservedAt
	return reflect.DeepEqual(original, live)
}

func readDesktopSelectedLatencyCapture(ctx context.Context, launch *desktopNodeLaunch) (desktopSelectedLatencyPublication, mobilemultihop.DesktopNodeChainExecutionReadyRecord, desktopSelectedLatencyCapture, []desktopOrderedLatencyNode, error) {
	return readDesktopSelectedLatencyCaptureForPurpose(ctx, launch, nil)
}

func readDesktopSelectedLatencyCaptureForPurpose(ctx context.Context, launch *desktopNodeLaunch, purpose *orderedCandidatePreparation) (desktopSelectedLatencyPublication, mobilemultihop.DesktopNodeChainExecutionReadyRecord, desktopSelectedLatencyCapture, []desktopOrderedLatencyNode, error) {
	var publication desktopSelectedLatencyPublication
	var ready mobilemultihop.DesktopNodeChainExecutionReadyRecord
	var capture desktopSelectedLatencyCapture
	bad := errors.New("selected fifty lost its retained native execution association")
	e := desktopNodeChainLaunchExecution(launch)
	if ctx == nil || ctx.Err() != nil || e == nil || e.bound(launch) != nil || launch.chain.preparation != purpose || purpose != nil && !purpose.ownsSelectedDraft(launch, e) {
		return publication, ready, capture, nil, bad
	}
	if err := mobilemtu.LockContext(ctx, &e.mu); err != nil {
		return publication, ready, capture, nil, err
	}
	projection, identity := e.projection, e.identity
	if projection == nil || e.ready == nil || e.ready.Identity != identity || e.started.IsZero() {
		e.mu.Unlock()
		return publication, ready, capture, nil, bad
	}
	transfer, started := e.ready.TransferSHA256, e.started
	e.mu.Unlock()
	limit := desktopSelectedSourceBound(launch, 32<<10)
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-execution-latency-capture.json", int64(limit))
	if err != nil || decodePrivateControlJSONBounded(raw, &publication, limit) != nil || publication.Schema != 1 ||
		publication.Kind != "routervpn-node-chain-execution-latency-capture-v1" {
		return publication, ready, capture, nil, errors.Join(err, bad)
	}
	ready, err = e.parseSelectedLatencyReady(publication.Capture, projection, identity, transfer)
	if err != nil || ready.ObservedAt < started.UnixMilli() {
		return publication, ready, capture, nil, errors.Join(err, bad)
	}
	var nodes []desktopOrderedLatencyNode
	capture, nodes, err = decodeDesktopSelectedLatencyCapture(publication.Selected)
	if err != nil || capture.SourceSHA256 != projection.SourceSHA256() || capture.ConfigSHA256 != projection.ConfigSHA256() ||
		capture.Execution != ready.Progress.Execution || len(nodes) != len(launch.chain.selection.Nodes) || (e.multiplePhysical != nil) != (capture.MultipleImported != nil) {
		return publication, ready, capture, nil, errors.Join(err, bad)
	}
	if capture.MultipleImported != nil {
		original, originalErr := e.preparation.OriginalMultipleImportedSource()
		public, _, publicErr := projection.ImportedPublicMeasurementCaptures(capture.Execution)
		if originalErr != nil || publicErr != nil || original.SourceSHA256() != capture.MultipleImported.OriginalSourceSHA256 || len(public) != len(capture.MultipleImported.Public) ||
			len(nodes) > mobilemultihop.NodeChainMaximumNodes && e.preparation.ExtendedOriginalNodeCount() != len(nodes) {
			return publication, ready, capture, nil, errors.Join(originalErr, publicErr, bad)
		}
		for index, selected := range public {
			row := capture.MultipleImported.Public[index]
			if row.Position != selected.Position || row.Tag != selected.Tag || row.SourceSHA256 != selected.SourceSHA256 {
				return publication, ready, capture, nil, bad
			}
		}
	}
	proofs, err := projection.ProofInventory(capture.Execution)
	if err != nil || len(proofs) != len(nodes) {
		return publication, ready, capture, nil, errors.Join(err, bad)
	}
	for position, row := range nodes {
		member, proof := launch.chain.selection.Nodes[position], proofs[position]
		kind := "private-node"
		if member.Profile.NodeKind == "external" {
			kind = "public-path"
		}
		proofKind := proof.Kind
		if proofKind == "" {
			proofKind = "private-node"
		}
		if row.NodeID != member.Profile.ID || proof.ProfileID != row.NodeID || proof.Position != position || proofKind != row.Kind || kind != row.Kind {
			return publication, ready, capture, nil, bad
		}
	}
	if err := mobilemtu.LockContext(ctx, &e.mu); err != nil {
		return publication, ready, capture, nil, err
	}
	defer e.mu.Unlock()
	if e.projection != projection || e.identity != identity || e.ready == nil || !sameDesktopSelectedLatencyReady(ready, *e.ready) || ctx.Err() != nil {
		return publication, ready, capture, nil, bad
	}
	return publication, ready, capture, nodes, nil
}

func captureDesktopSelectedLatency(ctx context.Context, identity speedLabPathIdentity) (desktopOrderedLatencyView, error) {
	var view desktopOrderedLatencyView
	if identity.Ordered == nil || identity.Ordered.launch == nil || !identity.GraphOK ||
		identity.Graph.Execution != "local" && identity.Graph.Execution != "server" {
		return view, errors.New("selected fifty requires its captured execution graph")
	}
	publication, _, capture, nodes, err := readDesktopSelectedLatencyCapture(ctx, identity.Ordered.launch)
	if err != nil || capture.Execution != identity.Graph.Execution {
		return view, errors.Join(err, errors.New("selected fifty changed its proved execution"))
	}
	view = desktopOrderedLatencyView{Schema: 1, desktopOrderedLatencyRequest: desktopOrderedLatencyRequest{Capture: desktopOrderedLatencyCapture{
		SessionID: identity.SessionID, ProfileID: identity.RouterID, ProfileToken: identity.ProfileToken,
		SourceSHA256: capture.SourceSHA256, ConfigSHA256: capture.ConfigSHA256, GenerationSHA256: capture.GenerationSHA256,
		SelectedCaptureJSON: publication.Selected}}, Nodes: nodes,
		Status: hopmeasure.Status{Stage: "idle", Complete: true, Drained: true, Results: []hopmeasure.Result{}}}
	if len(nodes) > mobilemultihop.NodeChainMaximumNodes {
		view.Capture.ExtendedOriginalNodes = desktopNodeChainLaunchExecution(identity.Ordered.launch).preparation.ExtendedOriginalNodeCount()
	}
	return view, nil
}

func validateDesktopSelectedLatencyCaptureBinding(c desktopOrderedLatencyCapture) error {
	if c.SelectedCaptureJSON == "" {
		if c.ExtendedOriginalNodes != 0 {
			return errors.New("extended selected capture requires its original native projection")
		}
		return nil
	}
	selected, _, err := decodeDesktopSelectedLatencyCapture(c.SelectedCaptureJSON)
	extended := 0
	if len(selected.Nodes) > mobilemultihop.NodeChainMaximumNodes {
		extended = len(selected.Nodes)
	}
	if err != nil || c.ExternalFinalNodeID != "" || c.ExtendedLocalNodes != 0 || c.ExtendedOriginalNodes != extended || selected.SourceSHA256 != c.SourceSHA256 || selected.ConfigSHA256 != c.ConfigSHA256 || selected.GenerationSHA256 != c.GenerationSHA256 {
		return errors.Join(err, errors.New("selected fifty changed its original public capture"))
	}
	return nil
}

// Used by both native publication and durable history validation. Historical
// data has no heartbeat authority; the live caller separately checks the owner.
func validateDesktopSelectedLatencyReceipt(raw string, receipt hopmeasure.OrderedLatencyReceipt, now time.Time) error {
	capture, nodes, err := decodeDesktopSelectedLatencyCapture(raw)
	if err != nil || receipt.Position < 0 || receipt.Position >= len(nodes) ||
		receipt.SourceSHA256 != capture.SourceSHA256 || receipt.ConfigSHA256 != capture.ConfigSHA256 ||
		receipt.GenerationSHA256 != capture.GenerationSHA256 || !desktopOrderedReceiptMatchesNode(receipt, nodes[receipt.Position]) {
		return errors.Join(err, errors.New("selected fifty receipt changed its complete original capture"))
	}
	role, kind, label, metric, endpoint := capture.meaning(receipt.Position, receipt.Result.Kind)
	return validateDesktopOrderedReceiptMeaning(receipt, now, role, kind, label, metric, endpoint)
}
