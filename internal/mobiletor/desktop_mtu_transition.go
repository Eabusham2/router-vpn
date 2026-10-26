package mobiletor

import "time"

// A reader transition temporarily suspends heartbeat freshness; it is not a
// fresh path, DNS, measurement, or successful replacement proof. The native
// owner publishes this exact bounded admission before touching the live TUN.
const DesktopBridgeMTUTransitionLimit = 15 * time.Second

// A normal control inventory retains its connection-owned context for at most
// five seconds. The shared heartbeat age allows that join and publication; no
// timestamp is advanced while a read or native reader transaction is pending.
const DesktopBridgeHeartbeatMaxAge = 6 * time.Second

type DesktopBridgeMTUTransition struct {
	Schema          int                      `json:"schema"`
	SessionID       string                   `json:"session_id"`
	SourceSHA256    string                   `json:"source_sha256"`
	ConfigSHA256    string                   `json:"config_sha256"`
	Generation      uint64                   `json:"generation"`
	RequestID       string                   `json:"request_id"`
	TransitionID    uint64                   `json:"transition_id"`
	From            DesktopBridgeMTUReadback `json:"from"`
	TargetMTU       int                      `json:"target_mtu"`
	StartedAt       int64                    `json:"started_at"`
	ExpiresAt       int64                    `json:"expires_at"`
	FromHeartbeatAt int64                    `json:"from_heartbeat_at"`
}
