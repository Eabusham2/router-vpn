//go:build linux

package main

import "router-vpn/internal/standardengine"

// Each authenticated packet carries at most one original raw evidence page.
// Six full Ready/retirement pages cannot fit the existing 64-KiB RPC bound.
// Identity and result digests bind independent page reads to the same retained
// transaction; an identifier never creates a native reader or observer.
type linuxStandardServiceMTURequest struct {
	ID          string                               `json:"id,omitempty"`
	MTU         int                                  `json:"mtu,omitempty"`
	DeadlineNS  int64                                `json:"deadline_ns,omitempty"`
	Expected    *standardengine.ReaderBinding        `json:"expected,omitempty"`
	Reservation *standardengine.OperationReservation `json:"reservation,omitempty"`
	Digest      string                               `json:"digest,omitempty"`
	Role        standardengine.OperationRole         `json:"role,omitempty"`
	Phase       standardengine.OperationPhase        `json:"phase,omitempty"`
	Offset      int                                  `json:"offset,omitempty"`
	Retiring    bool                                 `json:"retiring,omitempty"`
}

type linuxStandardServiceMTUResponse struct {
	CaptureSHA256    string                           `json:"capture_sha256"`
	Current          standardengine.ReaderBinding     `json:"current"`
	Ready            string                           `json:"ready,omitempty"`
	Remaining        int                              `json:"remaining"`
	Command          *standardengine.OperationCommand `json:"command,omitempty"`
	Result           *standardengine.OperationResult  `json:"result,omitempty"`
	Binding          *standardengine.ReaderBinding    `json:"binding,omitempty"`
	Evidence         []byte                           `json:"evidence,omitempty"`
	EvidenceSize     int                              `json:"evidence_size,omitempty"`
	NextOffset       int                              `json:"next_offset,omitempty"`
	Addresses        []string                         `json:"addresses,omitempty"`
	Pending          bool                             `json:"pending,omitempty"`
	Settled          bool                             `json:"settled,omitempty"`
	Rejected         *linuxStandardServiceMTURejected `json:"rejected,omitempty"`
	ObservationError string                           `json:"observation_error,omitempty"`
}

const linuxStandardServiceMTUEvidencePart = 8 << 10

// A rejection proves only that this service never submitted the exact intent.
// It is not a native worker result and cannot manufacture joined evidence.
type linuxStandardServiceMTURejected struct {
	ID         string                       `json:"id"`
	DeadlineNS int64                        `json:"deadline_ns"`
	Expected   standardengine.ReaderBinding `json:"expected"`
	Reason     string                       `json:"reason"`
}
