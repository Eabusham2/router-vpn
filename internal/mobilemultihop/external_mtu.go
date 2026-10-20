package mobilemultihop

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
)

// MTUAuthority returns only the optimization policy of this successful proof.
// It never accepts an independent host boolean, saved effective MTU, private
// node credential or profile belonging to a different external selection.
func (r *ExternalProofRequest) MTUAuthority(source, capture string) (string, string, error) {
	if !r.Healthy() {
		return "", "", errors.New("external MTU requires the retained successful exit proof")
	}
	policy, err := NewExternalPolicy(source, capture)
	if err != nil || policy.Config() != r.policy.Config() || policy.Metadata() != r.policy.Metadata() || policy.SourceSHA256() != r.policy.SourceSHA256() {
		return "", "", errors.New("external MTU selection differs from its proved graph")
	}
	jumbo, _ := r.policy.capture.Profile["jumbo_tun"].(bool)
	if entryJumbo, _ := r.policy.capture.Entry["jumbo_tun"].(bool); entryJumbo {
		jumbo = true
	}
	authority, err := json.Marshal(map[string]any{
		"schema": 1, "id": r.meta.ExitID, "source_sha256": r.meta.SourceSHA256,
		"expected_public_ip": r.meta.ExpectedPublicIP, "mtu_policy": r.meta.MTUPolicy,
		"jumbo_tun": jumbo,
	})
	if err != nil || !r.Healthy() {
		return "", "", errors.New("external MTU authority retired before delivery")
	}
	return policy.Config(), string(authority), nil
}

// MTULifetime propagates proof cancellation into an already-running native
// interface transaction or through-TUN socket. The caller must release it.
func (r *ExternalProofRequest) MTULifetime(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || !r.Healthy() {
		return nil, nil, errors.New("external MTU proof lifetime is unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(r.ctx, cancel)
	release := func() { stop(); cancel() }
	if !r.Healthy() {
		release()
		return nil, nil, errors.New("external MTU proof retired during capture")
	}
	return ctx, release, nil
}

// VerifyMTU proves the selected public exit using the supplied OS-TUN-bound
// dialer, while the retained native engine proves the unchanged DNS policy.
// It does not use the internal outbound dialer or the platform default route.
func (r *ExternalProofRequest) VerifyMTU(parent context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	return r.verifyMTU(parent, dial, nil)
}

func (r *ExternalProofRequest) verifyMTU(parent context.Context, dial func(context.Context, string, string) (net.Conn, error), testTLS *tls.Config) error {
	if dial == nil {
		return errors.New("external MTU has no captured system TUN dialer")
	}
	ctx, release, err := r.MTULifetime(parent)
	if err != nil {
		return err
	}
	defer release()
	if r.engine.DNSProof(ctx, r.meta.TUNTag) != nil || !r.Healthy() || ctx.Err() != nil {
		return errors.New("external MTU DNS owner failed proof")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("external MTU proof nonce unavailable")
	}
	data, err := externalProofHTTP(ctx, dial, ExternalFinalTag, "https://1.1.1.1/cdn-cgi/trace?routervpn_mtu="+hex.EncodeToString(nonce[:]), "", testTLS)
	if err != nil || externalTraceAddress(data, r.meta.ExpectedPublicIP) != nil || !r.Healthy() || ctx.Err() != nil {
		return errors.New("external MTU public exit changed or proof failed")
	}
	return nil
}
