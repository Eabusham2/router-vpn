package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

// A typed binding retains the validated original Local source and its sealed
// projection. Only its independent canonical provider pair can match discovery.
// It confers no connected endpoint or native socket authority.
type nodeChainOpenVPNExecutionBinding struct {
	desktop                        *nodeChainOpenVPNExecutionDesktop
	self                           *nodeChainOpenVPNExecutionBinding
	preparation                    *NodeChainExecutionPreparation
	source, local                  *NodeChain
	middle                         *nodeChainOpenVPNMember
	pair, server                   nativeopenvpn.PublicDescriptor
	pairSHA                        string
	sourceSeal, launch, valuesSeal string
	capture                        NodeChainOpenVPNCapture
	mu                             sync.Mutex
	connected                      *nativeopenvpn.PacketObservation
	connectedEngine                any
}

func NewNodeChainOpenVPNExecutionPreparation(original *NodeChain, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || original.validateCapture() != nil || original.openVPNMiddle == nil || original.openVPNOwners == nil || original.connectSource != nil || original.socksSource != nil || original.importedMiddle != nil || execution != "server" && execution != "auto" || len(original.nodes) < 3 || len(original.nodes) > NodeChainMaximumNodes || original.nodes[len(original.nodes)-1].mode != "shadowsocks" || original.projection.Kind != "" || original.projection.TargetOS != "" && original.projection.TargetOS != "ios" && original.projection.TargetOS != "android" {
		return nil, nodeChainExecutionError
	}
	if _, _, _, err := nodeChainOpenVPNLocalPair(original.openVPNMiddle); err != nil {
		return nil, err
	}
	return newNodeChainExecutionPreparationOwnedOpenVPN(original.sourceJSON, execution, nil, nil, original, nil, nil, nil, nil, original)
}

func ParseNodeChainOpenVPNExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 5 || source.OpenVPNLocalLaunch == "" || source.DesktopOpenVPN != nil || source.Desktop != nil || source.DesktopCONNECT != nil || source.DesktopSOCKS != nil || source.DesktopLast != "" {
		return nil, nodeChainExecutionError
	}
	original, err := ParseNodeChainLaunchInput(source.OpenVPNLocalLaunch)
	if err != nil || original.sourceJSON != source.LocalSource {
		return nil, nodeChainExecutionError
	}
	p, err := NewNodeChainOpenVPNExecutionPreparation(original, source.Execution)
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (b *nodeChainOpenVPNExecutionBinding) validate(p *NodeChainExecutionPreparation, local *NodeChain) error {
	if b == nil || b.self != b || p == nil || p.openvpn != b || b.preparation != p || local == nil || b.source != local || b.local != local || p.local != local || b.middle == nil || local.openVPNMiddle != b.middle || local.openVPNOwners == nil || p.connect != nil || p.socks != nil || local.connectSource != nil || local.socksSource != nil || local.importedMiddle != nil || p.source.Schema != 5 || p.source.LocalSource != local.sourceJSON || p.source.OpenVPNLocalLaunch == "" || p.desktop != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil {
		return nodeChainExecutionError
	}
	if b.desktop != nil {
		// This exact original desktop constructor freshly validates both the
		// same plain Local source and its native physical projection. Do not
		// repeat that Local validation in the same synchronous observation.
		if b.desktop.validate(p, b) != nil {
			return nodeChainExecutionError
		}
	} else if local.validateCapture() != nil || p.source.DesktopOpenVPN != nil || p.source.DesktopLast != "" {
		return nodeChainExecutionError
	}
	if p.mobile != nil && (p.mobile.openvpn == nil || p.mobile.openvpn.validate(p) != nil) {
		return nodeChainExecutionError
	}
	if b.sourceSeal == "" || local.seal != b.sourceSeal || b.launch != p.source.OpenVPNLocalLaunch || b.valuesSeal == "" || b.valuesSeal != b.immutableValuesSeal() {
		return nodeChainExecutionError
	}
	return nil
}

// The constructor records immutable original input, not a validity result.
// Every observation still reads the original source seal, owner pointers and
// graph/proof bytes freshly; live endpoint state is never authorized by this seal.
func (b *nodeChainOpenVPNExecutionBinding) immutableValuesSeal() string {
	raw, err := json.Marshal([]any{"routervpn-openvpn-execution-original-input-v1", b.sourceSeal, b.launch, b.pair, b.server, b.pairSHA, b.capture})
	if err != nil {
		return ""
	}
	return externalDigest(raw)
}

func (p *NodeChainExecutionPreparation) OriginalOpenVPNSource() (*NodeChain, error) {
	if p == nil || p.openvpn == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.openvpn.source, nil
}
func (p *NodeChainExecutionPreparation) RequiresOpenVPNExecutionObserver() bool {
	return p != nil && (p.openvpn != nil || p.source.Schema == 5)
}

// Native implementations retain the same source, Box, endpoint manager and
// *openvpn.ClientEndpoint even before the Local provider connects. This method
// proves construction ownership, not Local candidate authentication. A selected
// Local trial separately retains its actual connected packet observation.
type NodeChainOpenVPNExecutionObserver interface {
	ObserveOpenVPNExecutionContext(context.Context, *NodeChain) error
}

func (p *NodeChainExecutionPreparation) observeOpenVPNExecutionContext(ctx context.Context, engine any) error {
	return p.observeOpenVPNExecutionCurrentContext(ctx, engine, true)
}

// Entry discovery and an independently authenticated Server trial do not use
// the Local provider connection. They still require the original native owner.
func (p *NodeChainExecutionPreparation) observeOpenVPNExecutionOwnerContext(ctx context.Context, engine any) error {
	return p.observeOpenVPNExecutionCurrentContext(ctx, engine, false)
}

func (p *NodeChainExecutionPreparation) observeOpenVPNExecutionCurrentContext(ctx context.Context, engine any, connected bool) error {
	return p.observeOpenVPNExecutionReceiptContext(ctx, engine, connected, nil)
}

func (p *NodeChainExecutionPreparation) observeOpenVPNExecutionReceiptContext(ctx context.Context, engine any, connected bool, receipt *nodeChainOpenVPNExecutionConnectedReceipt) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if p.openvpn == nil {
		if p.source.Schema == 5 {
			return nodeChainExecutionError
		}
		return nil
	}
	if p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	owner, ok := engine.(NodeChainOpenVPNExecutionObserver)
	if !ok {
		return nodeChainExecutionError
	}
	native, ok := engine.(NodeChainOpenVPNEngine)
	if !ok {
		return nodeChainExecutionError
	}
	original := p.openvpn
	if receipt != nil && receipt.validate(p, engine) != nil {
		return nodeChainExecutionError
	}
	if !connected {
		if err := owner.ObserveOpenVPNExecutionContext(ctx, original.source); err != nil {
			return err
		}
		if ctx.Err() != nil || p.openvpn != original || p.validateCapture() != nil || receipt != nil && receipt.validate(p, engine) != nil {
			return nodeChainExecutionError
		}
		return nil
	}
	capture := original.capture
	mu, retained := &original.mu, &original.connected
	if receipt != nil {
		mu, retained = &receipt.mu, &receipt.connected
	}
	var err error
	for {
		err = owner.ObserveOpenVPNExecutionContext(ctx, original.source)
		var state nativeopenvpn.PacketObservation
		if err == nil {
			state, err = native.OpenVPNMiddleStateContext(ctx, capture.Tag)
		}
		if err := externalObservationLock(ctx, mu); err != nil {
			return err
		}
		initial := *retained == nil
		mu.Unlock()
		if initial && errors.Is(err, nativeopenvpn.ErrRemotePending) {
			if _, bounded := ctx.Deadline(); !bounded {
				return nodeChainExecutionError
			}
			timer := time.NewTimer(40 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				continue
			}
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil || p.openvpn != original || p.validateCapture() != nil || receipt != nil && receipt.validate(p, engine) != nil || state.Validate() != nil || state.Remote.Remote != capture.Remote || state.MTU < uint32(capture.ConfiguredMTU) {
			return nodeChainExecutionError
		}
		if err := externalObservationLock(ctx, mu); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			mu.Unlock()
			return err
		}
		if *retained == nil {
			if !nodeChainOpenVPNExecutionEnginePointer(engine) {
				mu.Unlock()
				return nodeChainExecutionError
			}
			copy := state
			*retained = &copy
			if receipt == nil {
				original.connectedEngine = engine
			}
		}
		valid := **retained == state
		if receipt == nil {
			valid = valid && nodeChainOpenVPNExecutionEnginePointer(engine) && nodeChainOpenVPNExecutionEnginePointer(original.connectedEngine) && original.connectedEngine == engine
		}
		mu.Unlock()
		if !valid {
			return nodeChainExecutionError
		}
		return nil
	}
}
func NewNodeChainOpenVPNExecutionPolicy(preparation *NodeChainExecutionPreparation, input string) (*NodeChainExecutionPolicy, error) {
	if preparation == nil || preparation.openvpn == nil || preparation.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPolicyFamilyOpenVPN(input, nil, nil, preparation.openvpn)
}
