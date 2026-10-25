package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"time"

	"router-vpn/internal/hopmeasure"
)

// NewHopMeasurement accepts a real native measurement adapter for this same
// Box. The successful proof owns the selection; callers cannot manufacture a
// private-node API, swap metadata, or turn a failed proof into performance data.
func (r *ExternalProofRequest) NewHopMeasurement(source, capture, session string, engine hopmeasure.Engine) (*hopmeasure.Service, error) {
	if r == nil || !r.Healthy() || session != r.session || engine == nil || engine.Identity() != r.identity {
		return nil, errors.New("external measurement requires its successful captured native proof")
	}
	policy, err := NewExternalPolicy(source, capture)
	if err != nil || policy.Config() != r.policy.Config() || policy.Metadata() != r.policy.Metadata() || policy.SourceSHA256() != r.policy.SourceSHA256() {
		return nil, errors.New("external measurement selection differs from its proved graph")
	}
	hops := make([]hopmeasure.Hop, 0, 2)
	if r.meta.EntryID != "" {
		hop := hopmeasure.Hop{ID: r.meta.EntryID, Role: "entry", Tag: r.meta.EntryTag, Kind: "public-path"}
		if r.meta.EntryNodeID != "" {
			hop.Kind = "private-node"
			hop.API, _ = r.policy.capture.Entry["router_api"].(string)
			hop.Token, _ = r.policy.capture.Entry["api_token"].(string)
			hop.Proof = r.meta.EntryNodeID
		}
		hops = append(hops, hop)
	}
	hops = append(hops, hopmeasure.Hop{ID: r.meta.ExitID, Role: "exit", Tag: ExternalFinalTag, Kind: "public-path"})
	owned := &externalMeasurementEngine{proof: r, engine: engine, identity: r.identity}
	return hopmeasure.New(owned, hops)
}

type externalMeasurementEngine struct {
	proof    *ExternalProofRequest
	engine   hopmeasure.Engine
	identity string
}

func (e *externalMeasurementEngine) VerifyMeasurement(parent context.Context) error {
	if e.Identity() == "" || parent == nil || parent.Err() != nil {
		return errors.New("external measurement owner retired")
	}
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	if err := e.proof.verifyCurrentPath(ctx); err != nil {
		e.proof.Cancel()
		return err
	}
	return nil
}

func (e *externalMeasurementEngine) BeginMeasurement() (func(), error) {
	if e.Identity() == "" {
		return nil, errors.New("external measurement owner retired")
	}
	if scoped, ok := e.engine.(hopmeasure.MeasurementScope); ok {
		return scoped.BeginMeasurement()
	}
	return func() {}, nil
}

func (e *externalMeasurementEngine) Identity() string {
	if e == nil || !e.proof.Healthy() || e.engine.Identity() != e.identity {
		return ""
	}
	return e.identity + ":" + e.proof.session + ":" + e.proof.meta.ConfigSHA256
}
func (e *externalMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if e.Identity() == "" || ctx.Err() != nil {
		return nil, errors.New("external measurement owner retired")
	}
	connection, err := e.engine.Dial(ctx, tag, address)
	if err != nil || e.Identity() == "" || ctx.Err() != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errors.New("external measurement dial failed or became stale")
	}
	return connection, nil
}
