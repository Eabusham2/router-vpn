package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"net/url"
	"time"

	"router-vpn/internal/hopmeasure"
)

// This private capability adds only the exact public trial target to the same
// retained packet endpoint. DialPrivate keeps its original private-only contract.
type nodeChainAppendExecutionPacketGrant struct {
	self    *nodeChainAppendExecutionPacketGrant
	request any
	target  string
	current func(context.Context) error
}

type nodeChainAppendExecutionPacketEndpoint interface {
	appendExecutionPacketRequest() any
	dialAppendExecutionPrivate(context.Context, any, string) (net.Conn, error)
	dialAppendExecutionPublic(context.Context, *nodeChainAppendExecutionPacketGrant, string) (net.Conn, error)
}

func newNodeChainAppendExecutionPacketGrant(request any, target string, current func(context.Context) error) (*nodeChainAppendExecutionPacketGrant, error) {
	if request == nil || current == nil || !nodeChainExecutionTarget(target) {
		return nil, errNodeChainAppendExecution
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, errNodeChainAppendExecution
	}
	g := &nodeChainAppendExecutionPacketGrant{request: request, target: net.JoinHostPort(u.Hostname(), "443"), current: current}
	g.self = g
	return g, nil
}

func (g *nodeChainAppendExecutionPacketGrant) validate(ctx context.Context, request any, address string) error {
	if g == nil || g.self != g || ctx == nil || ctx.Err() != nil || request == nil ||
		g.request != request || g.target == "" || address != g.target || g.current == nil {
		return errNodeChainAppendExecution
	}
	return g.current(ctx)
}

// The original candidatePacketRun remains the sole key and device owner.
// This small scope adds the exact append request/Compare target, not another
// reservation ledger, complete-route projection or replacement native factory.
type nodeChainAppendExecutionPacket struct {
	self                *nodeChainAppendExecutionPacket
	run                 *candidatePacketRun
	lifetime            context.Context
	deadline            time.Time
	current             func(context.Context) error
	grant               *nodeChainAppendExecutionPacketGrant
	tag, privateAddress string
}

func (s *nodeChainAppendExecutionRun) reserveLocalPacket(ctx, lifetime context.Context, target string, current func(context.Context) error) (*nodeChainAppendExecutionPacket, error) {
	if s.current(ctx) != nil || lifetime == nil || lifetime.Err() != nil || current == nil ||
		s.packetDeadline.IsZero() || !time.Now().Before(s.packetDeadline) ||
		!nodeChainAppendExecutionPacketMode(s.runtime.preparation.CandidateMode()) {
		return nil, errNodeChainAppendExecution
	}
	p := s.runtime.preparation.original
	if p == nil || p.appendSource == nil || p.original != nil || p.candidates == nil ||
		p.candidates.appendSource != p.appendSource || p.candidates.chain != nil ||
		!p.candidates.preparedNativeResponse || s.source.PacketOptions == "" {
		return nil, errNodeChainAppendExecution
	}
	reader, err := s.runtime.local.retainedPacketEngine(ctx)
	if err != nil || reader == nil {
		return nil, errors.Join(err, errNodeChainAppendExecution)
	}
	q := &NodeChainCandidatePacketRequest{plan: p.candidates, prepared: s.runtime.local, preparedReader: reader, response: s.source}
	q.self = q
	_, tag, _, err := q.ReadPrepared(ctx, reader, p)
	api, apiErr := privateAPI(s.source.API)
	if err != nil || apiErr != nil {
		return nil, errors.Join(err, apiErr, errNodeChainAppendExecution)
	}
	o := &nodeChainAppendExecutionPacket{lifetime: lifetime, deadline: s.packetDeadline, current: current, tag: tag, privateAddress: api.Host}
	o.self = o
	if target != "" {
		o.grant, err = newNodeChainAppendExecutionPacketGrant(q, target, current)
		if err != nil {
			return nil, err
		}
	}
	reserved, err := q.reserve(lifetime)
	if err != nil {
		return nil, err
	}
	var ok bool
	o.run, ok = reserved.(*candidatePacketRun)
	if !ok || o.run == nil || o.run.request != q {
		if reserved != nil {
			return nil, errors.Join(errNodeChainAppendExecution, reserved.Close())
		}
		return nil, errNodeChainAppendExecution
	}
	return o, nil
}

// Callers retain this scope before opening the original device. A late nonnil
// factory result remains on that same run until its original Close joins.
func (o *nodeChainAppendExecutionPacket) open(ctx context.Context) error {
	if o == nil || o.self != o || o.run == nil || o.run.endpoint != nil ||
		o.run.cancel != nil || o.current(ctx) != nil {
		return errNodeChainAppendExecution
	}
	owned, cancel := context.WithDeadline(o.lifetime, o.deadline)
	o.run.cancel = cancel
	stop := context.AfterFunc(ctx, cancel)
	var err error
	o.run.endpoint, err = o.run.open(owned, o.run.request)
	if !stop() || err != nil || o.run.endpoint == nil || ctx.Err() != nil || o.current(ctx) != nil {
		cancel()
		return errors.Join(err, ctx.Err(), errNodeChainAppendExecution)
	}
	original, ok := o.run.endpoint.(nodeChainAppendExecutionPacketEndpoint)
	if !ok || original.appendExecutionPacketRequest() != o.run.request {
		return errNodeChainAppendExecution
	}
	return nil
}

func (o *nodeChainAppendExecutionPacket) dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if o == nil || o.self != o || o.run == nil || o.run.endpoint == nil || tag != o.tag ||
		o.current(ctx) != nil {
		return nil, errNodeChainAppendExecution
	}
	original, ok := o.run.endpoint.(nodeChainAppendExecutionPacketEndpoint)
	if !ok || original.appendExecutionPacketRequest() != o.run.request {
		return nil, errNodeChainAppendExecution
	}
	var conn net.Conn
	var err error
	if address == o.privateAddress {
		conn, err = original.dialAppendExecutionPrivate(ctx, o.run.request, address)
	} else {
		if o.grant == nil || o.grant.validate(ctx, o.run.request, address) != nil {
			return nil, errNodeChainAppendExecution
		}
		conn, err = original.dialAppendExecutionPublic(ctx, o.grant, address)
	}
	// The surrounding original execution-I/O owner keeps every nonnil result,
	// including a late failure, before joining it.
	return conn, errors.Join(err, o.current(ctx), ctx.Err())
}

func (o *nodeChainAppendExecutionPacket) close() error {
	if o == nil {
		return nil
	}
	if o.self != o || o.run == nil {
		return hopmeasure.ErrStale
	}
	return o.run.Close()
}
