package mobilemtu

import (
	"context"
	"errors"
	"math"
	"net/netip"

	"router-vpn/internal/hopmeasure"
)

// ExternalOwner must re-prove the captured public exit through the actual OS
// TUN and retain the proved native DNS/transport owners. The native constructor
// supplies this authority from the successful retained external proof.
type ExternalOwner interface {
	Owner
	VerifyExternal(context.Context, State) error
}

type externalProfile struct {
	Schema           int    `json:"schema"`
	SourceKind       string `json:"source_kind,omitempty"`
	ID               string `json:"id"`
	SourceSHA256     string `json:"source_sha256"`
	ExpectedPublicIP string `json:"expected_public_ip"`
	MTUPolicy        string `json:"mtu_policy"`
	Jumbo            bool   `json:"jumbo_tun"`
}

type externalMeasurement struct {
	owner   ExternalOwner
	profile externalProfile
	measure func(context.Context, hopmeasure.Engine, hopmeasure.Hop, int) (hopmeasure.Result, error)
}

// NewExternal keeps the same session/path/readback/cancel/rollback state machine
// as private MTU. Its evidence is transferred HTTPS bytes after an actual TUN
// MTU change, explicitly distinct from authenticated UDP packet-size probing.
// No saved effective_mtu or cached sample is accepted as a current measurement.
func NewExternal(owner ExternalOwner, config, authority string, cache Cache) (*Controller, error) {
	return newPublic(owner, config, authority, cache, false)
}

// NewTor uses fresh dynamic Tor proof and the same owned OS-TUN transactions.
// The caller supplies authority captured before native construction; a fixed
// expected exit IP is deliberately not a Tor identity.
func NewTor(owner ExternalOwner, config, authority string, cache Cache) (*Controller, error) {
	return newPublic(owner, config, authority, cache, true)
}

func newPublic(owner ExternalOwner, config, authority string, cache Cache, tor bool) (*Controller, error) {
	if owner == nil {
		return nil, errors.New("external MTU requires a proved native owner")
	}
	var profile externalProfile
	if strictJSON(authority, &profile, 16<<10) != nil || profile.Schema != 1 ||
		!idPattern.MatchString(profile.ID) || !proofPattern.MatchString(profile.SourceSHA256) {
		return nil, errors.New("external MTU requires its exact captured proof authority")
	}
	if tor {
		if profile.SourceKind != "tor" || profile.ExpectedPublicIP != "" {
			return nil, errors.New("Tor MTU requires captured dynamic Tor proof authority")
		}
	} else {
		ip, err := netip.ParseAddr(profile.ExpectedPublicIP)
		if (profile.SourceKind != "" && profile.SourceKind != "external") || err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is4In6() || ip.Zone() != "" {
			return nil, errors.New("external MTU public identity is invalid")
		}
	}
	if profile.MTUPolicy != "auto" && profile.MTUPolicy != "fixed" && profile.MTUPolicy != "manual" && profile.MTUPolicy != "default" {
		return nil, errors.New("external MTU policy is invalid")
	}
	policy := Profile{ID: profile.ID, Proof: profile.SourceSHA256, Automatic: profile.MTUPolicy == "auto", Jumbo: profile.Jumbo}
	controller, err := newController(owner, config, policy, cache)
	if err != nil {
		return nil, err
	}
	var graph map[string]any
	if strictJSON(config, &graph, 4<<20) != nil {
		return nil, errors.New("external MTU graph is invalid")
	}
	route, ok := graph["route"].(map[string]any)
	final := "custom-exit"
	if tor {
		final = "routervpn-tor-exit"
	}
	if !ok || route["final"] != final {
		return nil, errors.New("external MTU must retain the captured external exit route")
	}
	controller.external = &externalMeasurement{owner: owner, profile: profile, measure: hopmeasure.MeasurePath}
	return controller, nil
}

func (e *externalMeasurement) hop() hopmeasure.Hop {
	if e.profile.SourceKind == "tor" {
		return hopmeasure.Hop{ID: e.profile.ID, Role: "exit", Tag: "routervpn-tor-exit", Kind: "public-path", Label: "Tor exit over the system VPN interface"}
	}
	return hopmeasure.Hop{ID: e.profile.ID, Role: "exit", Tag: "custom-exit", Kind: "public-path", Label: "External exit over the system VPN interface"}
}

func (e *externalMeasurement) source() string {
	if e.profile.SourceKind == "tor" {
		return "measured-tor-system-tun-transfer"
	}
	return "measured-public-system-tun-transfer"
}

func (c *Controller) measureExternal(ctx context.Context, engine *probeEngine, mtu int) Candidate {
	result := Candidate{MTU: mtu, LatencyKind: "https-response"}
	if c.external.owner.VerifyExternal(ctx, engine.state) != nil || !c.live(ctx, engine.state) {
		result.Failure = "captured external public exit or DNS proof failed"
		return result
	}
	measurement, err := c.external.measure(ctx, engine, c.external.hop(), 256<<10)
	if err != nil || !c.live(ctx, engine.state) || !measurement.Ready || measurement.Kind != "public-path" ||
		measurement.ID != c.profile.ID || measurement.Role != "exit" || measurement.Idle == nil ||
		measurement.Idle.Samples < 3 || measurement.Idle.Median <= 0 || math.IsNaN(measurement.Idle.Median) || math.IsInf(measurement.Idle.Median, 0) {
		result.Failure = "bounded external HTTPS measurements did not complete"
		return result
	}
	for _, transfer := range []*hopmeasure.Transfer{measurement.Download, measurement.Upload} {
		if transfer == nil || transfer.Bytes != 256<<10 || transfer.Seconds <= 0 || transfer.Mbps <= 0 ||
			math.IsNaN(transfer.Seconds) || math.IsInf(transfer.Seconds, 0) || math.IsNaN(transfer.Mbps) || math.IsInf(transfer.Mbps, 0) {
			result.Failure = "external transfer byte count or rate is invalid"
			return result
		}
	}
	if c.external.owner.VerifyExternal(ctx, engine.state) != nil || !c.live(ctx, engine.state) {
		result.Failure = "external exit changed during the measured transfer"
		return result
	}
	result.Working = true
	result.MedianRTT = measurement.Idle.Median
	result.Download = measurement.Download
	result.Upload = measurement.Upload
	return result
}
