package mobilemtu

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"time"

	"router-vpn/internal/hopmeasure"
)

// ExternalOwner must re-prove the captured public exit through the actual OS
// TUN and retain the proved native DNS/transport owners. The native constructor
// supplies this authority from the successful retained external proof.
type ExternalOwner interface {
	Owner
	VerifyExternal(context.Context, State) error
}

// ExternalMeasurementOwner optionally retains native measurement ownership
// across both fresh proofs and the entire candidate transfer. Release occurs
// before the winner waits for durable cache adoption, allowing that commit to
// request a separate fresh path proof without overlapping the measured work.
// Cancellation alone must not release sockets or native activity still in use.
type ExternalMeasurementOwner interface {
	BeginExternalMeasurement(context.Context, State) (context.Context, context.CancelFunc, error)
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

// Tor HTTPS round trips include a circuit and two fresh exit checks. Keep
// their budget bounded without applying the private LAN probe deadline.
func (c *Controller) measurementBudgets() (operation, candidate, reserve time.Duration) {
	if c.external != nil && c.external.profile.SourceKind == "tor" {
		return 4 * time.Minute, 30 * time.Second, 45 * time.Second
	}
	return 45 * time.Second, 8 * time.Second, 10 * time.Second
}

func (c *Controller) measureExternal(ctx context.Context, engine *probeEngine, mtu int) Candidate {
	result := Candidate{MTU: mtu, LatencyKind: "https-response"}
	if owner, ok := c.external.owner.(ExternalMeasurementOwner); ok {
		parent := ctx
		captured, release, err := owner.BeginExternalMeasurement(ctx, engine.state)
		if release != nil {
			defer release()
		}
		if err != nil || captured == nil || release == nil || parent.Err() != nil || captured.Err() != nil || !c.live(captured, engine.state) {
			result.Failure = "captured external measurement activity is unavailable"
			return result
		}
		// A native owner can narrow the lifetime but cannot detach a candidate
		// from its controller's cancellation or bounded operation deadline.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(captured)
		stop := context.AfterFunc(parent, cancel)
		defer func() { stop(); cancel() }()
	}
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
