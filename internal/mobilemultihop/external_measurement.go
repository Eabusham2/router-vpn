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
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.NewHopMeasurementContext(ctx, source, capture, session, engine)
}

// Keep native capture and publication inside the original caller's budget.
// The returned service owns subsequent measurement operations independently.
func (r *ExternalProofRequest) NewHopMeasurementContext(ctx context.Context, source, capture, session string, engine hopmeasure.Engine) (*hopmeasure.Service, error) {
	if ctx == nil {
		return nil, errors.New("external measurement has no constructor caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || session != r.session || engine == nil {
		return nil, errors.New("external measurement requires its successful captured native proof")
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	identity, err := externalObservedIdentity(ctx, engine)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if identity == "" || identity != r.identity {
		return nil, errors.New("external measurement native identity changed")
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
	return hopmeasure.NewContext(ctx, owned, hops)
}

type externalMeasurementEngine struct {
	proof    *ExternalProofRequest
	engine   hopmeasure.Engine
	identity string
}

func (e *externalMeasurementEngine) VerifyMeasurement(parent context.Context) error {
	if _, err := e.IdentityContext(parent); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	if err := e.proof.VerifyCurrentPathContext(ctx); err != nil {
		return err
	}
	_, err := e.IdentityContext(ctx)
	return err
}

func (e *externalMeasurementEngine) BeginMeasurement() (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return e.BeginMeasurementContext(ctx)
}

func (e *externalMeasurementEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := e.IdentityContext(ctx); err != nil {
		return nil, err
	}
	release := func() {}
	var err error
	if scoped, ok := e.engine.(hopmeasure.ContextMeasurementScope); ok {
		release, err = scoped.BeginMeasurementContext(ctx)
	} else if _, legacy := e.engine.(hopmeasure.MeasurementScope); legacy {
		return nil, errors.New("external measurement activity has no bounded observation")
	}
	if err == nil && release != nil {
		_, err = e.IdentityContext(ctx)
	}
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, errors.Join(err, ctx.Err(), errors.New("external measurement activity retired"))
	}
	return release, nil
}

func (e *externalMeasurementEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}
func (e *externalMeasurementEngine) IdentityContext(ctx context.Context) (string, error) {
	if e == nil || e.proof == nil || e.engine == nil || e.identity == "" {
		return "", errors.New("external measurement owner is unavailable")
	}
	if err := e.proof.HealthyContext(ctx); err != nil {
		return "", err
	}
	identity, err := externalObservedIdentity(ctx, e.engine)
	if err != nil || ctx.Err() != nil {
		return "", errors.Join(err, ctx.Err())
	}
	if identity != e.identity {
		return "", errors.New("external measurement owner changed")
	}
	// A native callback cannot substitute the proof owner while returning the
	// old measurement identity. Observe that original proof again afterward.
	if err := e.proof.HealthyContext(ctx); err != nil {
		return "", err
	}
	return e.identity + ":" + e.proof.session + ":" + e.proof.meta.ConfigSHA256, nil
}
func (e *externalMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if _, err := e.IdentityContext(ctx); err != nil {
		return nil, err
	}
	connection, err := e.engine.Dial(ctx, tag, address)
	_, observeErr := e.IdentityContext(ctx)
	if err != nil || observeErr != nil || ctx.Err() != nil || connection == nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, errors.Join(err, observeErr, ctx.Err(), errors.New("external measurement dial failed or became stale"))
	}
	return connection, nil
}
