package mobiletor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var predecessorNodeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PredecessorProof contains one immutable authenticated Router VPN node proof.
// Its credentials are deliberately private and cannot be replaced after the
// native Tor request captures the corresponding encrypted lower outbound.
type PredecessorProof struct {
	id      string
	address string
	target  string
	token   string
	node    string
}

func NewPredecessorProof(profileJSON string) (*PredecessorProof, error) {
	failure := errors.New("Tor predecessor requires one captured private Router VPN node proof")
	profile, err := profileObject(profileJSON, 256*1024)
	if err != nil || profile["node_kind"] != "router-vpn" || !profileIdentifier.MatchString(profileString(profile, "id")) || !predecessorNodeID.MatchString(profileString(profile, "node_proof_id")) {
		return nil, failure
	}
	api, err := url.Parse(profileString(profile, "router_api"))
	if err != nil || api.Scheme != "http" || api.User != nil || api.RawQuery != "" || api.ForceQuery || api.Fragment != "" || api.RawFragment != "" || api.Opaque != "" || api.RawPath != "" || api.Path != "" && api.Path != "/" {
		return nil, failure
	}
	host, err := netip.ParseAddr(api.Hostname())
	port, portErr := strconv.Atoi(api.Port())
	if err != nil || portErr != nil || host.Is4In6() || host.Zone() != "" || !host.IsPrivate() || port < 1 || port > 65535 || api.Host != net.JoinHostPort(host.String(), strconv.Itoa(port)) {
		return nil, failure
	}
	token := profileString(profile, "api_token")
	if token == "" || len(token) > 4096 || strings.TrimSpace(token) != token {
		return nil, failure
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return nil, failure
		}
	}
	api.Path = "/health"
	return &PredecessorProof{id: profileString(profile, "id"), address: api.Host, target: api.String(), token: token, node: profileString(profile, "node_proof_id")}, nil
}

// Prove sends only GET /health to the captured private literal origin through
// the caller's exact encrypted predecessor. It uses synchronous HTTP parsing:
// no environment proxy, resolver, redirect or background HTTP dial can escape
// the native proof request's lifetime. Cancellation closes the actual socket;
// the caller remains responsible until pending dial/IO/close have returned.
func (p *PredecessorProof) Prove(parent context.Context, dial DialContext) (err error) {
	failure := errors.New("Tor predecessor private node proof failed")
	if p == nil || parent == nil || dial == nil {
		return failure
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return failure
	}
	connection, dialErr := dial(ctx, "tcp", p.address)
	if dialErr != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return failure
	}
	var closeOnce sync.Once
	var closeErr error
	closed := make(chan struct{})
	closeOwned := func() {
		closeOnce.Do(func() {
			closeErr = connection.Close()
			close(closed)
		})
	}
	stop := context.AfterFunc(ctx, closeOwned)
	defer func() {
		if !stop() {
			<-closed
		}
		closeOwned()
		if ctx.Err() != nil || closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) {
			err = failure
		}
	}()
	deadline, _ := ctx.Deadline()
	if ctx.Err() != nil || connection.SetDeadline(deadline) != nil {
		return failure
	}
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, p.target, nil)
	if requestErr != nil {
		return failure
	}
	request.Close = true
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	if request.Write(connection) != nil {
		return failure
	}
	// Bound headers and body together before net/http parses a line. The body
	// has its own smaller bound and strict duplicate-key/type validation.
	response, responseErr := http.ReadResponse(bufio.NewReader(io.LimitReader(connection, 16385)), request)
	if responseErr != nil {
		return failure
	}
	defer func() { closeOwned(); _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return failure
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
	if readErr != nil || len(raw) > 8192 {
		return failure
	}
	proof, proofErr := profileObject(string(raw), 8192)
	if proofErr != nil || len(proof) != 3 || proof["ok"] != true || proof["node_id"] != p.node || proof["proof"] != "router-vpn-private-agent-v1" || ctx.Err() != nil {
		return failure
	}
	return nil
}
