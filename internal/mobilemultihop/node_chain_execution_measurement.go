package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"router-vpn/internal/hopmeasure"
)

// The bridge retains its original native activity until the exact measurement
// worker and every original socket have joined. A replacement runtime after an
// authorized MTU operation needs a newly captured measurement service.
type NodeChainExecutionMeasurementOwner interface {
	MeasurementExecutionContext(context.Context) (*NodeChainExecutionRuntime, error)
	BeginMeasurementContext(context.Context) (func(), error)
}

func (r *NodeChainExecutionRuntime) NewHopMeasurementContext(ctx context.Context, owner NodeChainExecutionMeasurementOwner) (*NodeChainExecutionMeasurement, error) {
	if ctx == nil {
		return nil, nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || owner == nil || r.projection.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	active, err := owner.MeasurementExecutionContext(ctx)
	if err != nil || active != r {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	identity, trial := r.identity, r.active
	r.mu.Unlock()
	if trial == nil {
		return nil, hopmeasure.ErrStale
	}
	e := &nodeChainExecutionMeasurementEngine{runtime: r, owner: owner, identity: identity, trial: trial}
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	proofs, err := r.projection.ProofInventory(trial.execution)
	if err != nil {
		return nil, err
	}
	hops := make([]hopmeasure.Hop, len(proofs))
	for position, proof := range proofs {
		role := "intermediate"
		if position == 0 {
			role = "entry"
		} else if position == len(proofs)-1 {
			role = "exit"
		}
		node := r.projection.policy.local.nodes[position]
		hops[position] = hopmeasure.Hop{ID: proof.ProfileID, Role: role, Tag: proof.Tag,
			API: predecessorText(node.profile, "router_api"), Token: predecessorText(node.profile, "api_token"), Proof: proof.NodeID,
			Kind: "private-node", Label: fmt.Sprintf("Cumulative %s path through node %d of %d", trial.execution, position+1, len(proofs))}
	}
	var service *hopmeasure.Service
	if trial.execution == "server" {
		service, err = hopmeasure.NewOrderedServerContext(ctx, e, hops)
	} else if trial.execution == "local" {
		service, err = hopmeasure.NewOrderedContext(ctx, e, hops)
	} else {
		err = nodeChainExecutionError
	}
	if err != nil {
		return nil, err
	}
	return &NodeChainExecutionMeasurement{service: service, engine: e}, nil
}

type nodeChainExecutionMeasurementEngine struct {
	runtime  *NodeChainExecutionRuntime
	owner    NodeChainExecutionMeasurementOwner
	identity NodeChainIdentity
	trial    *nodeChainExecutionTrial
	closed   atomic.Bool
	mu       sync.Mutex
	starting bool
	nextID   string
	scope    *nodeChainExecutionMeasurementScope
}

func (e *nodeChainExecutionMeasurementEngine) current(ctx context.Context) error {
	if e == nil || ctx == nil || ctx.Err() != nil || e.closed.Load() {
		return hopmeasure.ErrStale
	}
	active, err := e.owner.MeasurementExecutionContext(ctx)
	if err != nil || active != e.runtime {
		return errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return err
	}
	active.mu.Lock()
	current := active.identity == e.identity && active.active == e.trial
	active.mu.Unlock()
	if !current {
		return hopmeasure.ErrStale
	}
	return active.current(ctx, e.trial, true)
}

func (e *nodeChainExecutionMeasurementEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}

func (e *nodeChainExecutionMeasurementEngine) IdentityContext(ctx context.Context) (string, error) {
	if err := e.current(ctx); err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{e.identity, e.trial.id, e.trial.execution, e.trial.tag, e.trial.selectionEpoch})
	return string(raw), err
}

func (e *nodeChainExecutionMeasurementEngine) VerifyMeasurement(ctx context.Context) error {
	if err := e.current(ctx); err != nil {
		return err
	}
	// Server measurement observes a fresh nonce-bound receipt before work and
	// before result publication; cached client health alone is not admission.
	return e.trial.Verify(ctx)
}

func (e *nodeChainExecutionMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if err := e.current(ctx); err != nil {
		return nil, err
	}
	proofs, err := e.runtime.projection.ProofInventory(e.trial.execution)
	if err != nil {
		return nil, err
	}
	allowed := false
	for position, proof := range proofs {
		api, parseErr := privateAPI(predecessorText(e.runtime.projection.policy.local.nodes[position].profile, "router_api"))
		allowed = allowed || parseErr == nil && proof.Tag == tag && api.Host == address
	}
	if !allowed {
		return nil, nodeChainExecutionError
	}
	e.mu.Lock()
	scope := e.scope
	e.mu.Unlock()
	if scope == nil {
		return nil, nodeChainExecutionError
	}
	call, finish, err := scope.io.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	connection, dialErr := e.runtime.engine.Dial(call, tag, address)
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
