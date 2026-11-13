package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"router-vpn/internal/hopmeasure"
)

// The native owner must observe its exact Box, TUN, never-open application/DNS
// ingress, physical Network and prefix objects. No complete connected-chain
// proof or final-node availability is substituted for this separate purpose.
type NodeChainCandidatePreparationOwner interface {
	ObservePreparationContext(context.Context) (NodeChainIdentity, error)
	Dial(context.Context, string, string) (net.Conn, error)
	BeginMeasurementContext(context.Context) (func(), error)
	CandidateInventoryCurrentContext(context.Context, string) error
}

type NodeChainCandidatePreparationProgress struct {
	Stage           string                    `json:"stage"`
	Prepared        bool                      `json:"prepared"`
	Prefixes        []NodeChainPrefixProgress `json:"prefixes"`
	ApplicationOpen bool                      `json:"application_open"`
	DNSOpen         bool                      `json:"dns_open"`
}

// This controller joins only its private prefix proof workers. The native
// enclosing owner separately joins candidate work before closing these proof
// workers and retiring that same Box/TUN; no join failure drops either handle.
type NodeChainCandidatePreparationRuntime struct {
	preparation            *NodeChainCandidatePreparation
	owner                  NodeChainCandidatePreparationOwner
	mu                     sync.Mutex
	identity               NodeChainIdentity
	started, retired       bool
	lifetime               context.Context
	cancel                 context.CancelFunc
	startDone, observeDone chan struct{}
	checkedAt              time.Time
	progress               NodeChainCandidatePreparationProgress
}

func NewNodeChainCandidatePreparationRuntime(preparation *NodeChainCandidatePreparation, owner NodeChainCandidatePreparationOwner) (*NodeChainCandidatePreparationRuntime, error) {
	if preparation.validate() != nil || owner == nil {
		return nil, nodeChainCandidatePreparationError
	}
	return &NodeChainCandidatePreparationRuntime{preparation: preparation, owner: owner, progress: NodeChainCandidatePreparationProgress{Stage: "pending-prefix-proof"}}, nil
}

func (r *NodeChainCandidatePreparationRuntime) nativeCurrent(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainCandidatePreparationError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	identity, alive := r.identity, r.started && !r.retired && r.lifetime != nil && r.lifetime.Err() == nil
	r.mu.Unlock()
	p := r.preparation
	if !alive || p.validate() != nil || !nodeChainIdentityText(identity.EngineID) || !nodeChainIdentityText(identity.SessionID) || !nodeChainIdentityText(identity.NetworkID) || identity.SourceSHA256 != p.sourceSHA || identity.ConfigSHA256 != p.configSHA {
		return nodeChainCandidatePreparationError
	}
	observed, err := r.owner.ObservePreparationContext(ctx)
	if err != nil || observed != identity {
		return errors.Join(err, nodeChainCandidatePreparationError)
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	alive = !r.retired && r.identity == identity && r.lifetime.Err() == nil
	r.mu.Unlock()
	if !alive {
		return nodeChainCandidatePreparationError
	}
	return ctx.Err()
}

// AllowsDial is a private native-adapter allowlist: only exact captured private
// prefix proof addresses, or captured candidates through the selected prefix.
func (p *NodeChainCandidatePreparation) AllowsDial(tag, address string) bool {
	if p.validate() != nil {
		return false
	}
	for position, proof := range p.proofs {
		api, err := privateAPI(predecessorText(p.original.nodes[position].profile, "router_api"))
		if err == nil && proof.Tag == tag && api.Host == address {
			return true
		}
	}
	if tag != p.proofs[p.position].Tag {
		return false
	}
	for _, target := range p.candidates.targets {
		if target.Address == address {
			return true
		}
	}
	return false
}

func (r *NodeChainCandidatePreparationRuntime) dialProof(ctx context.Context, tag, address string) (net.Conn, error) {
	if !r.preparation.AllowsDial(tag, address) {
		return nil, nodeChainCandidatePreparationError
	}
	if err := r.nativeCurrent(ctx); err != nil {
		return nil, err
	}
	connection, err := r.owner.Dial(ctx, tag, address)
	after := r.nativeCurrent(ctx)
	if err != nil || after != nil || ctx.Err() != nil {
		// Keep late sockets with the shared I/O worker that owns their join.
		return connection, errors.Join(err, after, ctx.Err())
	}
	return connection, nil
}

func (r *NodeChainCandidatePreparationRuntime) provePrefixes(parent context.Context, publish bool) error {
	for position, proof := range r.preparation.proofs {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		node := r.preparation.original.nodes[position]
		started := time.Now()
		data, err := externalProofHTTP(ctx, r.dialProof, proof.Tag, healthURL(predecessorText(node.profile, "router_api")), predecessorText(node.profile, "api_token"), nil)
		if err == nil {
			var value struct {
				OK     bool   `json:"ok"`
				NodeID string `json:"node_id"`
				Proof  string `json:"proof"`
			}
			if exactJSON(data, &value, 8192) != nil || !value.OK || value.NodeID != proof.NodeID || value.Proof != "router-vpn-private-agent-v1" {
				err = errors.New("candidate preparation returned another private prefix identity")
			}
		}
		if err == nil {
			err = r.nativeCurrent(ctx)
		}
		cancel()
		if err != nil {
			return err
		}
		if publish {
			if err := externalObservationLock(parent, &r.mu); err != nil {
				return err
			}
			if r.retired {
				r.mu.Unlock()
				return nodeChainCandidatePreparationError
			}
			r.progress.Prefixes = append(r.progress.Prefixes, NodeChainPrefixProgress{Position: position, ProfileID: proof.ProfileID, ResponseMS: float64(time.Since(started)) / float64(time.Millisecond), Proven: true})
			r.mu.Unlock()
		}
	}
	return nil
}

// StartContext proves exactly the selected packet prefix. The context belongs
// to the enclosing native lifetime, not a disposable Activity callback.
func (r *NodeChainCandidatePreparationRuntime) StartContext(parent context.Context) (failure error) {
	if r == nil || parent == nil {
		return nodeChainCandidatePreparationError
	}
	if err := externalObservationLock(parent, &r.mu); err != nil {
		return err
	}
	if r.started || r.retired {
		r.mu.Unlock()
		return nodeChainCandidatePreparationError
	}
	lifetime, cancel := context.WithCancel(parent)
	r.lifetime = lifetime
	r.cancel = cancel
	r.started = true
	r.startDone = make(chan struct{})
	done := r.startDone
	r.mu.Unlock()
	defer close(done)
	defer func() {
		if failure != nil {
			r.Cancel()
		}
	}()
	ctx, end := context.WithTimeout(lifetime, time.Duration(15+5*len(r.preparation.proofs))*time.Second)
	defer end()
	identity, err := r.owner.ObservePreparationContext(ctx)
	if err != nil {
		return err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	r.identity = identity
	r.mu.Unlock()
	if err := r.nativeCurrent(ctx); err != nil {
		return err
	}
	if err := r.provePrefixes(ctx, true); err != nil {
		return err
	}
	if err := r.nativeCurrent(ctx); err != nil {
		return err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	if r.retired {
		r.mu.Unlock()
		return nodeChainCandidatePreparationError
	}
	r.progress.Prepared = true
	r.progress.Stage = "prefix-prepared"
	r.checkedAt = time.Now()
	r.observeDone = make(chan struct{})
	observed := r.observeDone
	r.mu.Unlock()
	go r.observe(lifetime, observed)
	return r.nativeCurrent(ctx)
}
func (r *NodeChainCandidatePreparationRuntime) observe(lifetime context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			r.Cancel()
			return
		case <-ticker.C:
			if r.provePrefixes(lifetime, false) != nil {
				r.Cancel()
				return
			}
			r.mu.Lock()
			if !r.retired {
				r.checkedAt = time.Now()
			}
			r.mu.Unlock()
		}
	}
}
func (r *NodeChainCandidatePreparationRuntime) HealthyContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainCandidatePreparationError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	expired := r.progress.Prepared && time.Since(r.checkedAt) > time.Duration(15+5*len(r.preparation.proofs))*time.Second
	ready := !r.retired && r.progress.Prepared && !expired
	r.mu.Unlock()
	if !ready {
		if expired {
			r.Cancel()
		}
		return nodeChainCandidatePreparationError
	}
	err := r.nativeCurrent(ctx)
	if err != nil && ctx.Err() == nil {
		r.Cancel()
	}
	return err
}
func (r *NodeChainCandidatePreparationRuntime) Progress() NodeChainCandidatePreparationProgress {
	if r == nil {
		return NodeChainCandidatePreparationProgress{Stage: "unavailable"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value := r.progress
	value.Prefixes = append([]NodeChainPrefixProgress(nil), value.Prefixes...)
	if r.retired || time.Since(r.checkedAt) > time.Duration(15+5*len(r.preparation.proofs))*time.Second {
		value.Prepared = false
	}
	return value
}
func (r *NodeChainCandidatePreparationRuntime) Cancel() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.retired = true
	r.progress.Prepared = false
	r.progress.Stage = "retired"
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (r *NodeChainCandidatePreparationRuntime) CloseContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainCandidatePreparationError
	}
	r.Cancel()
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	started, observed := r.startDone, r.observeDone
	r.mu.Unlock()
	for _, done := range []chan struct{}{started, observed} {
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return ctx.Err()
}
func (r *NodeChainCandidatePreparationRuntime) NewMeasurementContext(ctx context.Context) (*hopmeasure.CandidateService, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	p := r.preparation
	return hopmeasure.NewPrefixCandidatesContext(ctx, r, hopmeasure.CandidatePrefix{Position: p.position, ID: p.proofs[p.position].ProfileID, Tag: p.proofs[p.position].Tag, CaptureSHA256: p.capture}, p.candidates.targets)
}
func (r *NodeChainCandidatePreparationRuntime) VerifyMeasurement(ctx context.Context) error {
	if err := r.HealthyContext(ctx); err != nil {
		return err
	}
	err := r.owner.CandidateInventoryCurrentContext(ctx, r.preparation.capture)
	if err != nil {
		if ctx.Err() == nil {
			r.Cancel()
		}
		return err
	}
	return r.HealthyContext(ctx)
}
func (r *NodeChainCandidatePreparationRuntime) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	value, _ := r.IdentityContext(ctx)
	return value
}
func (r *NodeChainCandidatePreparationRuntime) IdentityContext(ctx context.Context) (string, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return "", err
	}
	r.mu.Lock()
	identity := r.identity
	r.mu.Unlock()
	raw, err := json.Marshal([]any{identity, r.preparation.capture})
	return string(raw), err
}
func (r *NodeChainCandidatePreparationRuntime) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	release, err := r.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		if release != nil {
			release()
		}
		return nil, errors.Join(err, errors.New("prefix preparation measurement lease is unavailable"))
	}
	if err := r.VerifyMeasurement(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (r *NodeChainCandidatePreparationRuntime) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if err := r.VerifyMeasurement(ctx); err != nil {
		return nil, err
	}
	p := r.preparation
	allowed := false
	for _, target := range p.candidates.targets {
		if target.Address == address {
			allowed = true
		}
	}
	if tag != p.proofs[p.position].Tag || !allowed {
		return nil, nodeChainCandidatePreparationError
	}
	connection, err := r.owner.Dial(ctx, tag, address)
	after := r.VerifyMeasurement(ctx)
	if err != nil || after != nil || ctx.Err() != nil {
		return connection, errors.Join(err, after, ctx.Err())
	}
	return connection, nil
}
