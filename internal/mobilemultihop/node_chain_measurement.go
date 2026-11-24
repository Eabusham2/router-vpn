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
		if _, imported := c.importedPublicIPAt(position); imported {
			hops[position] = hopmeasure.Hop{ID: proof.ProfileID, Role: role, Tag: proof.Tag, Kind: "public-path", Label: fmt.Sprintf("Cumulative path through custom node %d of %d → Cloudflare edge", position+1, len(c.proofs))}
			continue
		}
		hops[position] = hopmeasure.Hop{ID: proof.ProfileID, Role: role, Tag: proof.Tag,
			API: predecessorText(node.profile, "router_api"), Token: predecessorText(node.profile, "api_token"), Proof: proof.NodeID,
			Kind: "private-node", Label: fmt.Sprintf("Cumulative path through node %d of %d", position+1, len(c.proofs))}
	}
	if c.importedNodes != nil && c.importedNodes.customEntry {
		return hopmeasure.NewOrderedImportedEntryContext(ctx, engine, hops)
	}
	if c.importedNodes != nil {
		return hopmeasure.NewOrderedImportedNodesContext(ctx, engine, hops)
	}
	if c.connectSource != nil {
		return hopmeasure.NewOrderedCONNECTPrefixContext(ctx, engine, hops)
	}
	if c.socksSource != nil {
		return hopmeasure.NewOrderedSOCKSPrefixContext(ctx, engine, hops)
	}
	if c.openVPNMiddle != nil {
		return hopmeasure.NewOrderedOpenVPNPrefixContext(ctx, engine, hops)
	}
	if c.hasImportedMiddle() {
		return hopmeasure.NewOrderedImportedSSPrefixContext(ctx, engine, hops)
	}
	if depth := c.ExtendedPairedLocalNodeCount(); depth != 0 {
		return hopmeasure.NewExtendedPairedLocalContext(ctx, engine, hops, depth)
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
		if _, imported := e.source.importedPublicIPAt(position); imported {
			if proof.Tag == tag && address == hopmeasure.PublicAddress {
				allowed = true
			}
			continue
		}
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

// PublicMeasurementCapture exposes only the sealed ordinary SS2022 middle's
// fixed benchmark prefix and aggregate device policy. It grants no resolver,
// arbitrary hostname, physical route, or authority over typed SOCKS/CONNECT.
func (c *NodeChain) PublicMeasurementCapture() (tag string, ipv6 bool, err error) {
	if c == nil || c.importedNodes != nil {
		return "", false, nodeChainError
	}
	captured, ipv6, err := c.PublicMeasurementCaptures()
	if err != nil || len(captured) > 1 {
		return "", false, nodeChainError
	}
	if len(captured) == 0 {
		return "", false, nil
	}
	return captured[0].Tag, ipv6, nil
}

// Every public measurement route belongs to one sealed position and source.
// This grants only the fixed benchmark hostname through the captured resolver;
// it does not grant physical egress or a typed Server execution capability.
type NodeChainPublicMeasurementCapture struct {
	Position     int
	Tag          string
	SourceSHA256 string
}

func (c *NodeChain) PublicMeasurementCaptures() ([]NodeChainPublicMeasurementCapture, bool, error) {
	if c.validateCapture() != nil || c.socksSource != nil || c.connectSource != nil {
		return nil, false, nodeChainError
	}
	return c.publicMeasurementCapturesValidated()
}

func (c *NodeChain) publicMeasurementCapturesValidated() ([]NodeChainPublicMeasurementCapture, bool, error) {
	var captured []NodeChainPublicMeasurementCapture
	ipv6 := true
	for position, node := range c.nodes {
		var profile map[string]any
		if member := c.importedSSMemberAt(position); member != nil {
			profile = member.selection.Profile
		} else if c.openVPNMiddle != nil && position == c.importedMiddlePosition() {
			profile = c.openVPNMiddle.selection.Profile
		} else {
			if node == nil {
				return nil, false, nodeChainError
			}
			profile = node.profile
		}
		mode, _, policyErr := externalDevicePolicy(profile)
		if policyErr != nil {
			return nil, false, nodeChainError
		}
		ipv6 = ipv6 && mode != "off"
		if _, imported := c.importedPublicIPAt(position); imported {
			proof := c.proofs[position]
			captured = append(captured, NodeChainPublicMeasurementCapture{Position: position, Tag: proof.Tag, SourceSHA256: proof.SourceSHA256})
		}
	}
	return captured, len(captured) != 0 && ipv6, nil
}
