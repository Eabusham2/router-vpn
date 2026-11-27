package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

// SelectedPacketCandidateMode describes an exact complete source replacement.
// It grants no selected owner, remote registry entry or native UDP socket.
func (p *NodeChainExecutionPreparation) SelectedPacketCandidateMode(position int) string {
	if p == nil || p.validateCapture() != nil || p.local == nil ||
		(p.Execution() != "auto" && p.Execution() != "server") {
		return ""
	}
	return p.local.ConnectedPacketSuccessorCandidateMode(position)
}
func (p *NodeChainExecutionPreparation) SupportsCompareLocalPacketResponseCandidate(position int) bool {
	return p != nil && p.Execution() == "auto" && NodeChainPrefixMode(p.SelectedPacketCandidateMode(position))
}
func (p *NodeChainExecutionPreparation) SupportsServerPacketResponseCandidate(position int) bool {
	// Position zero has a distinct first-suffix native carrier constructor.
	// This description alone grants neither that carrier nor a suffix outbound.
	return p != nil && position >= 0 && NodeChainPrefixMode(p.SelectedPacketCandidateMode(position))
}
func (p *NodeChainExecutionPreparation) SelectedPacketCandidateInputFitsSource(position int, input string) bool {
	mode := p.SelectedPacketCandidateMode(position)
	if !NodeChainPrefixMode(mode) {
		return false
	}
	raw, err := json.Marshal(NodeChainCandidateInventory{Schema: 1, Revision: "selected-packet-source-preflight", Inputs: []string{input}, ResponseMode: mode})
	if err != nil {
		return false
	}
	defer clear(raw)
	_, err = p.local.NewCandidatePlan(position, string(raw))
	return err == nil
}

func (p *NodeChainExecutionProjection) selectedPacketCandidatePlan(position int, inventory string) (*NodeChainCandidatePlan, error) {
	if p == nil || p.validateCapture() != nil || p.preparation == nil || p.policy == nil ||
		p.policy.local == nil || p.preparation.local == nil ||
		p.policy.source.LocalSource != p.preparation.source.LocalSource || p.policy.source.Execution != p.preparation.source.Execution ||
		p.policy.local.sourceJSON != p.preparation.local.sourceJSON || p.policy.local.Config() != p.preparation.local.Config() ||
		!reflect.DeepEqual(p.policy.local.proofs, p.preparation.local.proofs) ||
		!NodeChainPrefixMode(p.preparation.SelectedPacketCandidateMode(position)) {
		return nil, nodeChainExecutionError
	}
	// Ordinary discovery compiles its own Local graph. BindExecution seals the
	// complete source/config/proof correspondence; the selected plan still owns
	// the policy's original graph, while imported registries retain identity.
	if p.policy.multiple != nil && (p.policy.multiple != p.preparation.multiple || p.policy.multiple.local != p.policy.local ||
		p.policy.multiple.owners != p.policy.local.importedNodes) {
		return nil, nodeChainExecutionError
	}
	return p.policy.local.NewCandidatePlan(position, inventory)
}

// This constructor accepts only the already selected Local winner. The older
// entry, TCP and stream-response constructors continue to reject response_mode.
func (r *NodeChainExecutionRuntime) NewLocalPacketResponseCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionCandidatePlan, error) {
	return r.newExecutionCandidatePlanContext(ctx, position, inventory, true, true)
}

type NodeChainSelectedPacketEngine interface {
	DialSelectedCandidatePacketContext(context.Context, *NodeChainCandidatePacketRequest) (net.Conn, error)
	OpenSelectedCandidateEndpointContext(context.Context, *NodeChainCandidatePacketRequest) (NodeChainCandidateEndpoint, error)
}

// ReadSelected cannot read an ordinary or prepared request. The complete
// projection, exact native reader, current winner and epoch are original owners.
func (r *NodeChainCandidatePacketRequest) ReadSelected(ctx context.Context, reader NodeChainExecutionEngine, original *NodeChainExecutionProjection) (NodeChainIdentity, string, string, error) {
	if r == nil || r.self != r || r.selected == nil || r.engine != nil || r.prepared != nil || r.preparedReader != nil ||
		r.plan == nil || r.plan.preparedNativeResponse || !NodeChainPrefixMode(r.plan.responseMode) ||
		reader == nil || !reflect.TypeOf(reader).Comparable() {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	e := r.selected
	if e.plan == nil || e.plan.plan != r.plan || e.plan.projection != original || original == nil ||
		e.plan.native != reader || e.plan.trial == nil || e.plan.trial.execution != "local" ||
		!e.plan.preparation.SupportsCompareLocalPacketResponseCandidate(r.plan.prefix.Position) {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if _, ok := reader.(NodeChainSelectedPacketEngine); !ok {
		return NodeChainIdentity{}, "", "", hopmeasure.ErrStale
	}
	if err := e.current(ctx); err != nil {
		return NodeChainIdentity{}, "", "", err
	}
	return r.source(e.plan.identity)
}

func (e *nodeChainExecutionEntryCandidateEngine) dialPacket(ctx context.Context, r *NodeChainCandidatePacketRequest) (net.Conn, error) {
	if r == nil || r.selected != e {
		return nil, hopmeasure.ErrStale
	}
	if _, _, _, err := r.ReadSelected(ctx, e.plan.native, e.plan.projection); err != nil {
		return nil, err
	}
	reader, ok := e.plan.native.(NodeChainSelectedPacketEngine)
	if !ok {
		return nil, hopmeasure.ErrStale
	}
	e.base.mu.Lock()
	scope := e.base.scope
	e.base.mu.Unlock()
	if scope == nil {
		return nil, hopmeasure.ErrStale
	}
	call, finish, err := scope.io.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	connection, dialErr := reader.DialSelectedCandidatePacketContext(call, r)
	var keepErr error
	if connection != nil {
		connection, keepErr = scope.io.keep(connection)
	}
	currentErr := e.current(call)
	if connection == nil || dialErr != nil || keepErr != nil || currentErr != nil || call.Err() != nil {
		if owned, ok := connection.(*leaseStopConn); ok {
			owned.startClose()
		}
		return connection, errors.Join(dialErr, keepErr, currentErr, call.Err(), nodeChainExecutionError)
	}
	return connection, nil
}
