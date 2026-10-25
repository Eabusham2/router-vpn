package mobilemultihop

import "errors"

// DNSMeasurementAuthority exposes only the exact graph and policy already
// proved by this request. Hosts cannot attach a different profile, DNS resolver
// or session to performance data by reusing another successful native proof.
func (r *ExternalProofRequest) DNSMeasurementAuthority(source, capture, session string) (string, string, error) {
	if r == nil || !r.Healthy() || session != r.session {
		return "", "", errors.New("DNS measurement requires its successful captured native proof")
	}
	policy, err := NewExternalPolicy(source, capture)
	if err != nil || policy.Config() != r.policy.Config() || policy.Metadata() != r.policy.Metadata() || policy.SourceSHA256() != r.policy.SourceSHA256() {
		return "", "", errors.New("DNS measurement selection differs from its proved graph")
	}
	if r.VerifyCurrentPath() != nil {
		return "", "", errors.New("DNS measurement transport changed during capture")
	}
	return policy.Config(), policy.Metadata(), nil
}
