package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"

	"router-vpn/internal/hopmeasure"
)

// NodeChainMeasurementOwner retains the original native connection and its MTU
// exclusion through worker/socket drain. An authorized MTU replacement may
// return a new proved controller, but never another engine/session/source/path.
type NodeChainMeasurementOwner interface {
	MeasurementChainContext(context.Context) (*NodeChain, error)
	BeginMeasurementContext(context.Context) (func(), error)
}

func (c *NodeChain) NewHopMeasurementContext(ctx context.Context, owner NodeChainMeasurementOwner) (*hopmeasure.Service, error) {
	if ctx == nil {
		return nil, errors.New("ordered measurement requires a caller context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil || owner == nil || c.validateCapture() != nil {
		return nil, errors.New("ordered measurement lost its sealed source")
	}
	engine := &nodeChainMeasurementEngine{source: c, owner: owner}
	active, err := owner.MeasurementChainContext(ctx)
	if err != nil || active == nil || active.SourceSHA256() != c.SourceSHA256() || active.ConfigSHA256() != c.ConfigSHA256() {
		return nil, errors.Join(err, errors.New("ordered measurement changed its native source"))
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	engine.identity = active.runtime.identity
	active.runtime.mu.Unlock()
	hops := make([]hopmeasure.Hop, len(c.proofs))
	for position, proof := range c.proofs {
		role := "intermediate"
		if position == 0 {
			role = "entry"
		} else if position == len(c.proofs)-1 {
			role = "exit"
		}
		node := c.nodes[position]
		hops[position] = hopmeasure.Hop{ID: proof.ProfileID, Role: role, Tag: proof.Tag,
			API: predecessorText(node.profile, "router_api"), Token: predecessorText(node.profile, "api_token"), Proof: proof.NodeID,
			Kind: "private-node", Label: fmt.Sprintf("Cumulative path through node %d of %d", position+1, len(c.proofs))}
	}
	return hopmeasure.NewOrderedContext(ctx, engine, hops)
}

type nodeChainMeasurementEngine struct {
	source   *NodeChain
	owner    NodeChainMeasurementOwner
	identity NodeChainIdentity
}

func (e *nodeChainMeasurementEngine) current(ctx context.Context) (*NodeChain, error) {
	active, err := e.owner.MeasurementChainContext(ctx)
	if err != nil || active == nil || active.SourceSHA256() != e.source.SourceSHA256() || active.ConfigSHA256() != e.source.ConfigSHA256() {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	if err := active.HealthyContext(ctx); err != nil {
		return nil, err
	}
	if err := externalObservationLock(ctx, &active.runtime.mu); err != nil {
		return nil, err
	}
	identity := active.runtime.identity
	active.runtime.mu.Unlock()
	if identity != e.identity {
		return nil, hopmeasure.ErrStale
	}
	return active, ctx.Err()
}

func (e *nodeChainMeasurementEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.ObservationTimeout)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}
func (e *nodeChainMeasurementEngine) IdentityContext(ctx context.Context) (string, error) {
	if _, err := e.current(ctx); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(e.identity)
	return string(encoded), err
}
func (e *nodeChainMeasurementEngine) VerifyMeasurement(ctx context.Context) error {
	_, err := e.current(ctx)
	return err
}
func (e *nodeChainMeasurementEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := e.current(ctx); err != nil {
		return nil, err
	}
	release, err := e.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, errors.New("ordered measurement activity unavailable"))
	}
	if _, err := e.current(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (e *nodeChainMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	active, err := e.current(ctx)
	if err != nil {
		return nil, err
	}
	allowed := false
	for position, proof := range e.source.proofs {
		api, parseErr := url.Parse(predecessorText(e.source.nodes[position].profile, "router_api"))
		if parseErr == nil && proof.Tag == tag && api.Host == address {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("ordered measurement cannot dial outside its captured node API")
	}
	connection, err := active.dial(ctx, tag, address)
	_, observeErr := e.current(ctx)
	if err != nil || observeErr != nil || ctx.Err() != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, errors.Join(err, observeErr, ctx.Err())
	}
	return connection, nil
}
