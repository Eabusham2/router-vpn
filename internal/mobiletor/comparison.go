package mobiletor

import (
	"context"
	"time"
)

// ComparisonProofMaxAge is the same conservative completed-DNS bound used by
// the native last-relay grant. Host timestamps cannot renew this lifetime.
const ComparisonProofMaxAge = lastRelayProofMaxAge

// Comparison retains one candidate's exact native path and the round's chosen
// external endpoint. Both operands are fresh routed HTTP response times. The
// target is captured before Prepare; no operation may choose a new endpoint,
// reconnect the external anchor or substitute a cached/native RTT.
//
// A nonnil handle remains owned even when its constructor or an operation
// fails. Cancel revokes only its measurement data. Close joins the measurement
// streams and their native capabilities, leaving whole-path stop to the driver.
// An unfinished Close must be retained and retried, including after path stop.
type Comparison interface {
	Prepare(context.Context) error
	Identity() string
	Verify(context.Context) error
	ProbeLast(context.Context) (time.Duration, error)
	ProbeExternal(context.Context, string) (time.Duration, error)
	Cancel()
	Close(context.Context) error
}

// ComparisonCapture is an internal native-host boundary. A full running Box
// supplies its immutable construction identity, successful retained proof,
// exact TUN/activity owner and selected-DNS callback; these values never come
// from a UI request or a control command's echoed fields. Current is a bounded
// memory-only ownership check. DNSProof performs the real captured policy query
// and must return only after that query completes on the owned path.
type ComparisonCapture struct {
	OwnerID, SourceSHA256, SessionID string
	Current                          func() bool
	DNSProof                         func(context.Context) error
}
