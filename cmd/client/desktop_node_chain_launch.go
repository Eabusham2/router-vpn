package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// This adjunct seals source and proof observations inside the existing launch.
// It owns no native process, protection, TUN, journal or independent registry.
type desktopNodeChainLaunch struct {
	policy    *mobilemultihop.DesktopNodeChainPolicy
	selection multihopSelection
	input     string
	platform  *desktopNodeChainPlatformRuntime
	capture   *desktopNodeChainHostCapture
	mu        sync.Mutex
	ready     *mobilemultihop.DesktopNodeChainReadyRecord
	mtuPath   string
}

func newDesktopNodeChainLaunch(selection multihopSelection, session, target string) (*desktopNodeLaunch, error) {
	if selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil ||
		selection.Control.ID != selection.Exit.ID || target != "windows" && target != "linux" && target != "darwin" {
		return nil, errors.New("ordered native launch requires its complete captured Local source")
	}
	policy, err := mobilemultihop.NewDesktopNodeChainPolicy(selection.Native.chain.chain, session, target, selection.restoreMTU)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	if meta.ProfileID != selection.Control.ID || meta.NodeID != selection.Exit.NodeProofID || meta.Mode != selection.ExitMode ||
		meta.OriginalSourceSHA256 != selection.Native.source {
		return nil, errors.New("ordered native projection changed its captured final control or complete source")
	}
	input, err := policy.NodeChain().LaunchInput()
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
	return &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint,
		profileID: selection.Exit.ID, policyProfileID: selection.Control.ID, mode: selection.ExitMode,
		config: []byte(policy.Config()), metadata: metadata, configSHA256: meta.ConfigSHA256, mtuSession: session,
		nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), selection.Native.entryPhysical...),
		chain:              &desktopNodeChainLaunch{policy: policy, selection: selection, input: input}}, nil
}

func validateDesktopNodeChainLaunch(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.chain == nil || launch.chain.policy == nil ||
		launch.importedEntry || launch.importedPlatform != nil || launch.external != nil || launch.tor != nil {
		return errors.New("ordered native launch lost its concrete policy family or original caller")
	}
	owner := launch.chain
	selection := owner.selection
	if selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil {
		return errors.New("ordered native launch changed a captured member")
	}
	if owner.capture != nil && selection.Native.chain.host != owner.capture {
		return errors.New("ordered native launch replaced its original host capture")
	}
	config, meta, _, err := owner.policy.ReadValidated()
	actual := string(launch.config)
	if len(launch.config) == 0 && launch.ownedNode != nil && launch.ownedNode.chain == owner && launch.command != nil && launch.directory != "" {
		raw, readErr := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", mobilemultihop.NodeChainInputLimit)
		if readErr != nil {
			return readErr
		}
		actual = string(raw)
		clear(raw)
	}
	if err != nil || config != actual || meta.ConfigSHA256 != launch.configSHA256 || meta.SessionID != launch.mtuSession ||
		meta.ProfileID != launch.profileID || launch.policyProfileID != selection.Control.ID || meta.NodeID != selection.Exit.NodeProofID ||
		meta.Mode != launch.mode || meta.OriginalSourceSHA256 != selection.Native.source || launch.root != selection.Native.root ||
		launch.endpoint != selection.Native.endpoint || owner.policy.OriginalChain() != selection.Native.chain.chain {
		return errors.Join(err, errors.New("ordered native launch changed its sealed derived graph or original authority"))
	}
	input, err := owner.policy.NodeChain().LaunchInput()
	if err != nil || input != owner.input {
		return errors.Join(err, errors.New("ordered native launch changed its exact projected private input"))
	}
	return ctx.Err()
}

// Initial chain proofs use the core's bounded complete-inventory budget. The
// original setup/readback allowance remains separate. This never changes MTU
// operation, heartbeat, socket, journal or lease deadlines.
func desktopNodeReadyBudget(launch *desktopNodeLaunch) (time.Duration, error) {
	if launch == nil || launch.chain == nil {
		return 25 * time.Second, nil
	}
	chain := launch.chain
	if chain.policy == nil || chain.policy.Validate() != nil || chain.selection.Native == nil ||
		chain.selection.Native.chain == nil || len(chain.selection.Nodes) < 2 || len(chain.selection.Nodes) > 8 ||
		len(chain.policy.NodeChain().ProofInventory()) != len(chain.selection.Nodes) {
		return 0, errors.New("ordered readiness lost its bounded complete proof inventory")
	}
	return time.Duration(35+10*len(chain.selection.Nodes)) * time.Second, nil
}

// Callers bracket this read with their original process/native policy guard.
// Reading files is not authority to adopt a new process or native owner. The
// mutex only serializes the evidence pin; it cannot grant native ownership.
func readDesktopNodeChainReadyContext(ctx context.Context, launch *desktopNodeLaunch, transfer string,
	started time.Time, fresh bool, live desktopNodeMTURecord) (mobilemultihop.DesktopNodeChainReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeChainReadyRecord
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.chain == nil || launch.chain.policy == nil {
		return empty, errors.New("ordered readiness has no original typed launch and caller")
	}
	owner := launch.chain
	if err := desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
		return empty, err
	}
	defer owner.mu.Unlock()
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-chain-ready.json", mobilemultihop.DesktopNodeChainReadyRecordLimit)
	if err != nil {
		return empty, err
	}
	record, err := mobilemultihop.ParseDesktopNodeChainReadyRecord(raw, owner.policy, transfer)
	if err != nil {
		return empty, err
	}
	if err := validateDesktopNodeChainReadyForTarget(owner.policy.Metadata().TargetOS, record, live, started, time.Now(), owner.ready, fresh); err != nil {
		return empty, err
	}
	if owner.mtuPath != "" && owner.mtuPath != live.Path || !desktopMTUPathPattern.MatchString(live.Path) {
		return empty, errors.New("ordered readiness changed its original native MTU path")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	copy := record
	owner.ready = &copy
	owner.mtuPath = live.Path
	return record, nil
}

func validateDesktopNodeChainReady(record mobilemultihop.DesktopNodeChainReadyRecord, live desktopNodeMTURecord,
	started, now time.Time, captured *mobilemultihop.DesktopNodeChainReadyRecord, fresh bool) error {
	return validateDesktopNodeChainReadyForTarget("", record, live, started, now, captured, fresh)
}

func desktopNodeChainDarwinInterfaceName(name string) bool {
	if !strings.HasPrefix(name, "utun") || len(name) == len("utun") {
		return false
	}
	for _, digit := range strings.TrimPrefix(name, "utun") {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func validateDesktopNodeChainReadyForTarget(target string, record mobilemultihop.DesktopNodeChainReadyRecord, live desktopNodeMTURecord,
	started, now time.Time, captured *mobilemultihop.DesktopNodeChainReadyRecord, fresh bool) error {
	bad := errors.New("ordered readiness lost its fresh proof generation or exact native MTU reader")
	if target == "darwin" && (!desktopNodeChainDarwinInterfaceName(record.InterfaceName) ||
		captured != nil && !desktopNodeChainDarwinInterfaceName(captured.InterfaceName)) {
		return bad
	}
	if started.IsZero() || record.ObservedAt < started.UnixMilli() || record.ObservedAt > now.UnixMilli() || now.UnixMilli()-record.ObservedAt > 2000 ||
		live.Session != record.Identity.SessionID || live.Config != record.Identity.ConfigSHA256 || live.Reader != record.Reader ||
		live.Interface != record.InterfaceName || live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU ||
		live.Failure != "" && !(live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored") {
		return bad
	}
	if captured == nil {
		if !fresh || record.Generation != 1 || record.Reader != 1 || live.Active || live.Generation != 0 || live.Request != "" || live.Lease != "" ||
			live.Restored || live.Expired || live.Failure != "" {
			return bad
		}
		return nil
	}
	if record.Identity != captured.Identity || record.SourceSHA256 != captured.SourceSHA256 || record.TransferSHA256 != captured.TransferSHA256 ||
		record.DNSConfigSHA256 != captured.DNSConfigSHA256 || record.ObservedAt < captured.ObservedAt || record.Generation < captured.Generation ||
		record.Reader < captured.Reader || target != "darwin" && record.InterfaceName != captured.InterfaceName {
		return bad
	}
	if record.Reader == captured.Reader {
		if record.Generation != captured.Generation || record.InterfaceName != captured.InterfaceName || record.InterfaceIndex != captured.InterfaceIndex || record.MTU != captured.MTU {
			return bad
		}
	} else if fresh || record.Generation <= captured.Generation || record.Generation-captured.Generation != record.Reader-captured.Reader {
		return bad
	}
	return nil
}
