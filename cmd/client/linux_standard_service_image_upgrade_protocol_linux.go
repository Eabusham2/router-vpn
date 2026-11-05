//go:build linux

package main

import (
	"errors"
	"net/netip"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

const linuxStandardImageUpgradeArgument = "--linux-standard-owner-image-upgrade"
const linuxStandardImageUpgradeWorkLimit = 120 * time.Second
const linuxStandardImageUpgradeCleanupLimit = 30 * time.Second

// This envelope is immutable comparison data. Only the original service's
// retained transaction, native creator and authenticated peers supply authority.
type linuxStandardImageUpgradeEnvelope struct {
	Schema             int                              `json:"schema"`
	ID                 string                           `json:"id"`
	DeadlineNS         int64                            `json:"deadline_ns"`
	OldGeneration      linuxStandardGenerationSelection `json:"old_generation"`
	NewGeneration      linuxStandardGenerationSelection `json:"new_generation"`
	ActivationSHA256   string                           `json:"activation_sha256"`
	Root               linuxprotection.NativeObject     `json:"root"`
	Run                linuxprotection.NativeObject     `json:"run"`
	MutationLock       linuxprotection.NativeObject     `json:"mutation_lock"`
	SavedState         linuxprotection.NativeObject     `json:"saved_state"`
	SavedStateSHA256   string                           `json:"saved_state_sha256"`
	ProfileID          string                           `json:"profile_id"`
	ProfileRevision    string                           `json:"profile_revision"`
	HomeLAN            bool                             `json:"home_lan"`
	Endpoints          []netip.Addr                     `json:"endpoints"`
	SourceSHA256       string                           `json:"source_sha256"`
	DestinationSession string                           `json:"destination_session"`
	DestinationSHA256  string                           `json:"destination_sha256"`
}

// FD3 installer control uses one SOCK_SEQPACKET message per canonical JSON
// frame, <=64KiB. Sequence starts at1 and advances exactly once per new action;
// retrying the identical last action returns its retained result. A different
// body at an existing sequence never enters another operation.
type linuxStandardImageUpgradeControl struct {
	Schema            int                                `json:"schema"`
	Sequence          uint64                             `json:"sequence"`
	Action            string                             `json:"action"`
	DeadlineNS        int64                              `json:"deadline_ns"`
	NewGeneration     *linuxStandardGenerationSelection  `json:"new_generation,omitempty"`
	Envelope          *linuxStandardImageUpgradeEnvelope `json:"envelope,omitempty"`
	CleanupDeadlineNS int64                              `json:"cleanup_deadline_ns,omitempty"`
}
type linuxStandardImageUpgradeControlReply struct {
	Schema   int                                       `json:"schema"`
	Sequence uint64                                    `json:"sequence"`
	Action   string                                    `json:"action"`
	Complete bool                                      `json:"complete"`
	Error    string                                    `json:"error,omitempty"`
	Upgrade  *linuxStandardServiceImageUpgradeResponse `json:"upgrade,omitempty"`
}

// Service messages use the existing authenticated canonical service frame.
// Join is the sole action without an envelope: the actual candidate's image,
// fixed argv, namespace and peer pidfd must match the old retained reservation.
type linuxStandardServiceImageUpgradeRequest struct {
	Envelope          *linuxStandardImageUpgradeEnvelope            `json:"envelope,omitempty"`
	Generation        *linuxStandardGenerationSelection             `json:"generation,omitempty"`
	DeadlineNS        int64                                         `json:"deadline_ns,omitempty"`
	Source            *mobiletor.DesktopLinuxClosedTransferSnapshot `json:"source,omitempty"`
	Destination       *mobiletor.DesktopLinuxClosedTransferSnapshot `json:"destination,omitempty"`
	CleanupDeadlineNS int64                                         `json:"cleanup_deadline_ns,omitempty"`
}
type linuxStandardServiceImageUpgradeResponse struct {
	Envelope          linuxStandardImageUpgradeEnvelope             `json:"envelope"`
	Phase             string                                        `json:"phase"`
	CleanupDeadlineNS int64                                         `json:"cleanup_deadline_ns,omitempty"`
	Source            *mobiletor.DesktopLinuxClosedTransferSnapshot `json:"source,omitempty"`
	Destination       *mobiletor.DesktopLinuxClosedTransferSnapshot `json:"destination,omitempty"`
	OldPeer           *linuxprocess.Observation                     `json:"old_peer,omitempty"`
	NewPeer           *linuxprocess.Observation                     `json:"new_peer,omitempty"`
	CoordinatorPeer   *linuxprocess.Observation                     `json:"coordinator_peer,omitempty"`
	Frozen            bool                                          `json:"frozen"`
	SourceRemoved     bool                                          `json:"source_removed"`
	Ready             bool                                          `json:"ready"`
	OldJoined         bool                                          `json:"old_joined"`
	RollbackAllowed   bool                                          `json:"rollback_allowed"`
	ActivationAllowed bool                                          `json:"activation_allowed"`
}

func linuxStandardImageSelectionValid(s linuxStandardGenerationSelection) bool {
	return s.Schema == 1 && linuxStandardGenerationHex(s.Generation) && linuxStandardGenerationHex(s.ImageSHA256)
}
func (e linuxStandardImageUpgradeEnvelope) validate() error {
	if e.Schema != 1 || !validControllerOwnerToken(e.ID) || e.DeadlineNS <= 0 || !linuxStandardImageSelectionValid(e.OldGeneration) || !linuxStandardImageSelectionValid(e.NewGeneration) || e.OldGeneration.Generation == e.NewGeneration.Generation || !linuxStandardGenerationHex(e.ActivationSHA256) || !linuxStandardGenerationHex(e.SavedStateSHA256) || !validProfileID(e.ProfileID) || !linuxStandardGenerationHex(e.ProfileRevision) || !linuxStandardGenerationHex(e.SourceSHA256) || !validControllerOwnerToken(e.DestinationSession) || !linuxStandardGenerationHex(e.DestinationSHA256) || len(e.Endpoints) == 0 || len(e.Endpoints) > 16 {
		return errors.New("image upgrade changed immutable original scope")
	}
	for _, object := range []linuxprotection.NativeObject{e.Root, e.Run, e.MutationLock, e.SavedState} {
		if object.Inode == 0 || object.UID != 0 || object.Mode&0022 != 0 {
			return errors.New("image upgrade lost original private object")
		}
	}
	var last netip.Addr
	for _, endpoint := range e.Endpoints {
		if !endpoint.IsValid() || endpoint != endpoint.Unmap() || endpoint.Zone() != "" || endpoint.IsUnspecified() || endpoint.IsMulticast() || last.IsValid() && last.Compare(endpoint) >= 0 {
			return errors.New("image upgrade changed original endpoint set")
		}
		last = endpoint
	}
	return nil
}
func linuxStandardImageUpgradePhase(value string) bool {
	switch value {
	case "reserved", "successor-prepared", "frozen", "code-verified", "source-removed", "successor-published", "successor-ready", "settled", "aborting", "aborted":
		return true
	}
	return false
}
