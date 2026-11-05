//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/mobiletor"
	"time"
)

func (s *linuxStandardService) imageRequest(ctx context.Context, peer *linuxStandardServicePeer, role string, q linuxStandardServiceRequest) (*linuxStandardServiceImageUpgradeResponse, *os.File, error) {
	if q.ImageUpgrade == nil || q.MTU != nil || q.Reverse != nil || q.Transfer != nil || q.Directory != "" || q.ConfigSHA256 != "" || q.ProfileID != "" || q.ProfileSHA256 != "" || q.NetworkID != "" || q.RouterID != "" || q.Endpoint != "" || q.RuntimeMode != "" || q.Base != "" || q.Release || q.ProfileRevision != "" || q.ResultRevision != "" {
		return nil, nil, errors.New("image action supplied cross-scope data")
	}
	if err := peer.Current(ctx); err != nil {
		return nil, nil, err
	}
	if q.Action == "image-reservation" && role == "coordinator" {
		t := s.imageUpgrade
		r := q.ImageUpgrade
		if t == nil || t.coordinator == nil || t.coordinator.record != peer.record || r.Generation == nil || *r.Generation != t.envelope.NewGeneration || r.DeadlineNS != t.envelope.DeadlineNS || r.Envelope != nil || r.Source != nil || r.Destination != nil || r.CleanupDeadlineNS != 0 {
			return nil, nil, errors.New("original image reservation is not retained for this peer")
		}
		return t.view(), nil, nil
	}
	if q.Action == "image-prepare" && role == "coordinator" {
		t, err := s.reserveImage(ctx, peer, q.ImageUpgrade)
		if t == nil {
			return nil, nil, err
		}
		return t.view(), nil, err
	}
	t := s.imageUpgrade
	if t == nil {
		return nil, nil, errors.New("image action has no original reservation")
	}
	if q.Action == "image-join" && role == "successor" {
		r := q.ImageUpgrade
		if t.candidate || r.Generation == nil || *r.Generation != t.envelope.NewGeneration || r.Envelope != nil || t.phase != "reserved" && t.phase != "successor-prepared" || time.Now().UnixNano() >= t.envelope.DeadlineNS || t.envelope.validate() != nil {
			return t.view(), nil, errors.New("successor did not match exact original reservation")
		}
		if t.successor != nil && t.successor.record != peer.record {
			return t.view(), nil, errors.New("successor process replaced original candidate")
		}
		if t.successor == nil {
			t.successor = peer
		}
		return t.view(), s.imageAuthority.owner, nil
	}
	if t.candidate && t.coordinator == nil && role == "coordinator" && peer.record == t.expectedCoordinator {
		t.coordinator = peer
	}
	if role != "coordinator" || t.coordinator == nil || t.coordinator.record != peer.record || q.ImageUpgrade.Envelope == nil || !reflect.DeepEqual(*q.ImageUpgrade.Envelope, t.envelope) || q.Session != t.envelope.ID {
		return t.view(), nil, errors.New("image action changed original peer or envelope")
	}
	if err := s.imageBoundary(ctx, t); err != nil {
		return t.view(), nil, err
	}
	if q.Action == "image-status" {
		err := s.imageCurrent(ctx, t)
		return t.view(), nil, err
	}
	cleanup := q.Action == "image-cleanup" || q.Action == "image-abort" || q.Action == "image-code-restored" ||
		(t.cleanupDeadline > 0 || q.ImageUpgrade.CleanupDeadlineNS > 0 || time.Now().UnixNano() >= t.envelope.DeadlineNS && t.removed) &&
			(q.Action == "image-commit" || q.Action == "image-activation-published" || q.Action == "image-settle")
	call, cancel, err := t.context(ctx, cleanup, q.ImageUpgrade.CleanupDeadlineNS)
	if err != nil {
		return t.view(), nil, err
	}
	defer cancel()
	if t.candidate {
		return s.imageCandidateRequest(call, q)
	}
	switch q.Action {
	case "image-cleanup":
		// Only activates the original retained clock; supplies no new native work.

	case "image-successor-started":
		if t.successor == nil || q.ImageUpgrade.Destination == nil {
			return t.view(), nil, errors.New("successor has not joined original reservation")
		}
		if err = t.successor.Current(call); err != nil {
			break
		}
		d := *q.ImageUpgrade.Destination
		if err = d.Validate(); err != nil {
			break
		}
		if !d.Standard || d.Capture.SessionID != t.envelope.DestinationSession || d.Capture.SourceSHA256 != t.envelope.DestinationSHA256 || d.HomeLAN != t.envelope.HomeLAN || !reflect.DeepEqual(d.Endpoints, t.envelope.Endpoints) {
			err = errors.New("candidate inventory changed captured policy")
			break
		}
		if err = mobiletor.ReadDesktopLinuxClosedTransferCurrent(call, d); err != nil {
			break
		}
		if t.destination != nil && !reflect.DeepEqual(*t.destination, d) {
			err = errors.New("candidate inventory replaced original acknowledgement")
			break
		}
		t.destination = &d
		t.phase = "successor-prepared"
	case "image-freeze":
		if t.phase != "successor-prepared" && t.phase != "frozen" {
			err = errors.New("freeze requires actual two creator preparation")
			break
		}
		if err = t.successor.Current(call); err != nil {
			break
		}
		if _, err = t.transfer.Snapshot(call); err != nil {
			break
		}
		if err = s.imageReleaseSource(call); err == nil {
			t.phase = "frozen"
		}
	case "image-code-promoted":
		if t.phase != "frozen" && t.phase != "code-verified" {
			err = errors.New("code verification has no original frozen window")
			break
		}
		t.phase = "code-verified"
	case "image-commit":
		if t.phase != "code-verified" && t.phase != "source-removed" {
			err = errors.New("image commit has no verified new code")
			break
		}
		lease, e := acquireLegacyExitMutationLease(call, s.root)
		if e != nil {
			err = e
			break
		}
		err = t.transfer.Commit(call, *t.destination, lease.lock)
		lease.Close()
		if err == nil {
			t.removed = true
			t.phase = "source-removed"
		}
	case "image-settle":
		if !t.removed {
			err = errors.New("old creator cannot settle before actual removal")
			break
		}
		if !t.oldTransferFinished {
			var committed bool
			committed, err = t.transfer.Finish(call)
			if err != nil || !committed {
				err = errors.Join(err, errors.New("old creator removal is not settled"))
				break
			}
			t.oldTransferFinished = true
		}
		err = t.slot.finishImageTransfer(call)
		if err == nil {
			t.phase = "settled"
			s.quiescing = true
		}
	case "image-abort":
		if t.transfer != nil {
			var removed bool
			removed, err = t.transfer.Result(call)
			if err != nil {
				break
			}
			if removed {
				t.removed = true
				t.phase = "source-removed"
			}
		}
		if t.transfer == nil {
			lease, e := acquireLegacyExitMutationLease(call, s.root)
			if e != nil {
				err = e
				break
			}
			err = t.slot.current(call, lease)
			lease.Close()
			if err != nil {
				break
			}
		}
		if t.removed {
			return t.view(), nil, nil
		}
		if err = s.imageReleaseSource(call); err == nil {
			t.phase = "aborting"
		}
	case "image-code-restored":
		if t.phase != "aborting" {
			err = errors.New("image abort has no original rollback window")
			break
		}
		if err = s.imageAcquireSource(call, t.oldGeneration); err != nil {
			break
		}
		if t.transfer != nil {
			var committed bool
			committed, err = t.transfer.Finish(call)
			if err == nil && committed {
				err = errors.New("image abort unexpectedly committed")
			}
		}
		if err == nil {
			image, imageErr := os.Lstat(filepath.Join(s.root, "router-vpn-client"))
			if imageErr != nil {
				err = imageErr
				break
			}
			s.image = image
			t.phase = "aborted"
		}
	default:
		err = errors.New("image action is unavailable")
	}
	return t.view(), nil, err
}
