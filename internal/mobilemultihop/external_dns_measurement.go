package mobilemultihop

import (
	"context"
	"errors"
	"time"
)

// DNSMeasurementAuthority exposes only the exact graph and policy already
// proved by this request. Hosts cannot attach a different profile, DNS resolver
// or session to performance data by reusing another successful native proof.
func (r *ExternalProofRequest) DNSMeasurementAuthority(source, capture, session string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return r.DNSMeasurementAuthorityContext(ctx, source, capture, session)
}

func (r *ExternalProofRequest) DNSMeasurementAuthorityContext(ctx context.Context, source, capture, session string) (string, string, error) {
	if ctx == nil {
		return "", "", errors.New("DNS measurement authority has no constructor caller")
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if r == nil || session != r.session {
		return "", "", errors.New("DNS measurement requires its successful captured native proof")
	}
	if err := r.HealthyContext(ctx); err != nil {
		return "", "", err
	}
	policy, err := NewExternalPolicy(source, capture)
	if err != nil || policy.Config() != r.policy.Config() || policy.Metadata() != r.policy.Metadata() || policy.SourceSHA256() != r.policy.SourceSHA256() {
		return "", "", errors.New("DNS measurement selection differs from its proved graph")
	}
	if err := r.VerifyCurrentPathContext(ctx); err != nil {
		return "", "", errors.Join(err, errors.New("DNS measurement transport changed during capture"))
	}
	if err := r.HealthyContext(ctx); err != nil {
		return "", "", err
	}
	return policy.Config(), policy.Metadata(), nil
}
