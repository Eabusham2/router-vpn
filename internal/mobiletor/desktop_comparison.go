package mobiletor

import (
	"errors"
	"time"
)

// DesktopTorCompareRequest is a private, captured-runtime command. A request
// never grants native ownership: the mailbox must also retain its exact input
// file, current Box, authenticated child and one-use comparison handle.
type DesktopTorCompareRequest struct {
	Schema       int    `json:"schema"`
	SessionID    string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Generation   uint64 `json:"generation"`
	RequestID    string `json:"request_id"`
	Sequence     uint64 `json:"sequence"`
	Action       string `json:"action"`
	Target       string `json:"target"`
	ExpiresAt    int64  `json:"expires_at"`
}

// ResponseNS is exclusively the successful HTTP write-to-validated-body
// duration of Last or External. Mailbox, TLS, control, DNS and cleanup elapsed
// time must never be put in that field. Drained acknowledges actual retained
// comparison resources, not cancellation, a closed controller or child exit.
type DesktopTorCompareStatus struct {
	DesktopTorCompareRequest
	IdentitySHA256 string `json:"identity_sha256,omitempty"`
	Complete       bool   `json:"complete"`
	Drained        bool   `json:"drained"`
	Cancelled      bool   `json:"cancelled"`
	Failed         bool   `json:"failed"`
	StopRequired   bool   `json:"stop_required"`
	ResponseNS     int64  `json:"response_ns,omitempty"`
}

const (
	DesktopTorCompareSchema      = 1
	DesktopTorCompareRequestFile = "tor-compare-request.json"
	DesktopTorCompareCancelFile  = "tor-compare-cancel.json"
	DesktopTorCompareStatusFile  = "tor-compare-status.json"
	DesktopTorComparePrepare     = "prepare"
	DesktopTorCompareVerify      = "verify"
	DesktopTorCompareLast        = "last"
	DesktopTorCompareExternal    = "external"
	DesktopTorCompareClose       = "close"
	DesktopTorCompareFileLimit   = 4096
)

func (r DesktopTorCompareRequest) Budget() time.Duration {
	switch r.Action {
	case DesktopTorComparePrepare:
		return 60 * time.Second
	case DesktopTorCompareVerify, DesktopTorCompareLast, DesktopTorCompareExternal:
		return 10 * time.Second
	case DesktopTorCompareClose:
		return 30 * time.Second
	default:
		return 0
	}
}

func DesktopTorCompareTarget(target string) bool {
	return target == "https://1.1.1.1/cdn-cgi/trace" || target == "https://1.0.0.1/cdn-cgi/trace"
}

// Validate checks a newly issued action, not a retained completion. Completed
// status may outlive the deadline; consumers must match its entire request and
// the independently retained generation before reading the result.
func (r DesktopTorCompareRequest) Validate(now time.Time) error {
	budget := r.Budget()
	if r.Schema != DesktopTorCompareSchema || !desktopHex(r.SessionID, 16) ||
		!desktopHex(r.SourceSHA256, 32) || !desktopHex(r.ConfigSHA256, 32) ||
		r.Generation == 0 || r.Sequence == 0 || !desktopHex(r.RequestID, 16) ||
		!DesktopTorCompareTarget(r.Target) || budget == 0 || r.ExpiresAt <= now.UnixMilli() ||
		r.ExpiresAt > now.Add(budget).UnixMilli() {
		return errors.New("desktop Tor comparison request has an invalid captured identity, action or deadline")
	}
	return nil
}
