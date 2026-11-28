package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// This scope belongs to one original append execution run or Compare trial.
// Its genuine HY2 companion is identity only; no packet reservation is borrowed.
type nodeChainAppendExecutionHysteria struct {
	self                *nodeChainAppendExecutionHysteria
	run                 *nodeChainAppendExecutionRun
	request             *NodeChainCandidatePacketRequest
	reader              NodeChainPreparedPacketEngine
	preparation         *NodeChainCandidatePreparation
	lifetime            context.Context
	deadline            time.Time
	current             func(context.Context) error
	grant               *nodeChainAppendExecutionPacketGrant
	tag, privateAddress string
	endpoint            NodeChainCandidateEndpoint
	cancel              context.CancelFunc
	closeOnce           sync.Once
	closeErr            error
}

func (s *nodeChainAppendExecutionRun) captureLocalHysteria(ctx, lifetime context.Context, target string, current func(context.Context) error) (*nodeChainAppendExecutionHysteria, error) {
	if s.current(ctx) != nil || lifetime == nil || lifetime.Err() != nil || current == nil ||
		s.hysteriaDeadline.IsZero() || !time.Now().Before(s.hysteriaDeadline) || s.runtime.preparation.CandidateMode() != "hysteria2" {
		return nil, errNodeChainAppendExecution
	}
	p := s.runtime.preparation.original
	if p == nil || p.appendSource == nil || p.original != nil || p.candidates == nil ||
		p.candidates.appendSource != p.appendSource || p.candidates.chain != nil || !p.candidates.preparedNativeResponse ||
		s.source.Hysteria2Options == "" || s.source.PacketOptions != "" || s.source.ClientKey != "" || s.source.ServerKey != "" ||
		s.runtime.preparation.policy.validate() != nil || len(s.runtime.preparation.policy.hysteriaCandidates) != len(p.candidates.responses) {
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
	o := &nodeChainAppendExecutionHysteria{run: s, request: q, reader: reader, preparation: p,
		lifetime: lifetime, deadline: s.hysteriaDeadline, current: current, tag: tag, privateAddress: api.Host}
	o.self, q.appendHysteria = o, o
	if target != "" {
		o.grant, err = newNodeChainAppendExecutionPacketGrant(q, target, current)
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

func (o *nodeChainAppendExecutionHysteria) validateRequest(ctx context.Context, q *NodeChainCandidatePacketRequest) error {
	if o == nil || o.self != o || o.run == nil || o.run.runtime == nil || o.preparation == nil || q == nil || q != o.request || q.self != q || q.appendHysteria != o ||
		q.prepared != o.run.runtime.local || q.preparedReader != o.reader || q.plan != o.preparation.candidates ||
		o.preparation != o.run.runtime.preparation.original || q.response != o.run.source || o.lifetime == nil || o.lifetime.Err() != nil ||
		o.current == nil || o.run.runtime.preparation.CandidateMode() != "hysteria2" || !time.Now().Before(o.deadline) {
		return errNodeChainAppendExecution
	}
	return o.current(ctx)
}

// The caller retains this scope before invoking the real native factory. Every
// late nonnil endpoint remains here through the original joined close.
func (o *nodeChainAppendExecutionHysteria) open(ctx context.Context) error {
	if o == nil || o.endpoint != nil || o.cancel != nil || o.validateRequest(ctx, o.request) != nil {
		return errNodeChainAppendExecution
	}
	owned, cancel := context.WithDeadline(o.lifetime, o.deadline)
	o.cancel = cancel
	stop := context.AfterFunc(ctx, cancel)
	var err error
	o.endpoint, err = o.reader.OpenPreparedCandidateEndpointContext(owned, o.request)
	if !stop() || err != nil || o.endpoint == nil || ctx.Err() != nil || o.validateRequest(ctx, o.request) != nil {
		cancel()
		return errors.Join(err, ctx.Err(), errNodeChainAppendExecution)
	}
	original, ok := o.endpoint.(nodeChainAppendExecutionPacketEndpoint)
	if !ok || original.appendExecutionPacketRequest() != o.request {
		return errNodeChainAppendExecution
	}
	return nil
}

func (o *nodeChainAppendExecutionHysteria) dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if o == nil || o.endpoint == nil || tag != o.tag || o.validateRequest(ctx, o.request) != nil {
		return nil, errNodeChainAppendExecution
	}
	original, ok := o.endpoint.(nodeChainAppendExecutionPacketEndpoint)
	if !ok || original.appendExecutionPacketRequest() != o.request {
		return nil, errNodeChainAppendExecution
	}
	var conn net.Conn
	var err error
	if address == o.privateAddress {
		conn, err = original.dialAppendExecutionPrivate(ctx, o.request, address)
	} else {
		if o.grant == nil || o.grant.validate(ctx, o.request, address) != nil {
			return nil, errNodeChainAppendExecution
		}
		conn, err = original.dialAppendExecutionPublic(ctx, o.grant, address)
	}
	return conn, errors.Join(err, o.validateRequest(ctx, o.request), ctx.Err())
}

func (o *nodeChainAppendExecutionHysteria) close() error {
	if o == nil {
		return nil
	}
	if o.self != o || o.request == nil || o.request.appendHysteria != o {
		return errNodeChainAppendExecution
	}
	o.closeOnce.Do(func() {
		if o.cancel != nil {
			o.cancel()
		}
		if o.endpoint != nil {
			o.closeErr = o.endpoint.Close()
		}
	})
	return o.closeErr
}
