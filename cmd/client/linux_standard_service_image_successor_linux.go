//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
	"syscall"
)

// Discovery identifies code only. The original live source must authenticate
// this exact image/process and transfer its held owner-lock open description.
func captureLinuxStandardImageSuccessor(ctx context.Context, root string, old *linuxStandardServiceGeneration, image os.FileInfo, namespace os.FileInfo) (*linuxStandardServiceGeneration, *linuxStandardImageUpgrade, *os.File, error) {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return nil, nil, nil, err
	}
	generation := filepath.Base(filepath.Dir(path))
	if !linuxStandardGenerationHex(generation) || path != filepath.Join(root+".service-generations", generation, "router-vpn-client") {
		return nil, nil, nil, errors.New("candidate is outside immutable generation store")
	}
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, nil, nil, err
	}
	digest, err := linuxStandardGenerationHash(ctx, f)
	_ = f.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	next, err := captureLinuxStandardServiceGenerationSelection(ctx, root, linuxStandardGenerationSelection{Schema: 1, Generation: generation, ImageSHA256: digest})
	if err != nil {
		return nil, nil, nil, err
	}
	if !os.SameFile(image, next.imageInfo) {
		next.Close()
		return nil, nil, nil, errors.New("candidate image changed during generation capture")
	}
	client := &linuxStandardImageClient{generation: old, namespace: namespace}
	reply, owner, err := client.call(ctx, "image-join", generation[:32], &linuxStandardServiceImageUpgradeRequest{Generation: &next.selection})
	if err != nil || reply == nil || owner == nil {
		next.Close()
		if client.peer != nil {
			client.peer.Close()
		}
		return nil, nil, nil, errors.Join(err, errors.New("candidate has no original owner-lock transfer"))
	}
	fail := func(err error) (*linuxStandardServiceGeneration, *linuxStandardImageUpgrade, *os.File, error) {
		owner.Close()
		next.Close()
		client.peer.Close()
		return nil, nil, nil, err
	}
	if err = reply.Envelope.validate(); err != nil {
		return fail(err)
	}
	if reply.Envelope.NewGeneration != next.selection || reply.Envelope.OldGeneration != old.selection || reply.Source == nil || reply.Source.Validate() != nil || linuxStandardImageDigest(*reply.Source) != reply.Envelope.SourceSHA256 || reply.CoordinatorPeer == nil {
		return fail(errors.New("candidate join changed immutable transfer scope"))
	}
	actual, err := owner.Stat()
	named, nameErr := os.Lstat(filepath.Join(linuxStandardServiceDirectory, "owner.lock"))
	if err != nil || nameErr != nil || !legacyExitPrivate(actual, false) || !os.SameFile(actual, named) {
		return fail(errors.Join(err, nameErr, errors.New("candidate did not inherit original owner-lock inode")))
	}
	if err = syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(err)
	}
	t := &linuxStandardImageUpgrade{envelope: reply.Envelope, phase: "reserved", candidate: true, oldGeneration: old, newGeneration: next, oldPeer: client.peer, source: *reply.Source, expectedCoordinator: *reply.CoordinatorPeer}
	return next, t, owner, nil
}
func (s *linuxStandardService) prepareImageSuccessor(ctx context.Context) error {
	t := s.imageUpgrade
	if t == nil || !t.candidate {
		return errors.New("candidate has no original admitted transfer")
	}
	if err := s.imageBoundary(ctx, t); err != nil {
		return err
	}
	if err := t.oldPeer.Current(ctx); err != nil {
		return err
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return err
	}
	defer lease.Close()
	for _, v := range []struct {
		info os.FileInfo
		want linuxprocess.Object
	}{{lease.rootInfo, linuxprocess.Object(t.envelope.Root)}, {lease.runInfo, linuxprocess.Object(t.envelope.Run)}, {lease.lockInfo, linuxprocess.Object(t.envelope.MutationLock)}} {
		got, e := desktopLinuxNodeObjectOf(v.info)
		if e != nil || linuxprocess.Object(got) != v.want {
			return errors.Join(e, errors.New("candidate changed original state boundary"))
		}
	}
	if t.slot == nil {
		expected, e := legacyExitCaptureState(lease)
		if e != nil {
			return e
		}
		if expected.absent || linuxStandardImageBytesDigest(expected.body) != t.envelope.SavedStateSHA256 {
			expected.Close()
			return errors.New("candidate changed original saved state")
		}
		object, e := desktopLinuxNodeObjectOf(expected.info)
		if e != nil || object != t.envelope.SavedState {
			expected.Close()
			return errors.Join(e, errors.New("candidate saved inode replaced"))
		}
		boot, e := readDesktopLinuxNodeBootID()
		if e != nil {
			expected.Close()
			return e
		}
		// Current public saved policy has one literal endpoint; native DTO supports
		// canonical multiple endpoints without allowing an invented state layout.
		var saved legacyExitProtectionState
		if e = decodeRelayControlJSON(expected.body, &saved); e != nil {
			expected.Close()
			return e
		}
		t.slot = &legacyExitProtectionSlot{app: s.app, root: s.root, namespace: s.namespace, policy: "always", profileID: t.envelope.ProfileID, endpoint: saved.Endpoint, homeLAN: t.envelope.HomeLAN, boot: boot, expected: expected}
	}
	if t.slot.kernel == nil {
		if err = mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, t.source); err != nil {
			return err
		}
		t.slot.kernel, err = createLegacyExitNativeProtection(ctx, t.envelope.DestinationSession, t.envelope.DestinationSHA256, t.envelope.Endpoints, t.envelope.HomeLAN, lease.lock)
		if err != nil {
			return err
		}
		if t.slot.kernel == nil {
			return errors.New("candidate constructor returned no retained owner")
		}
	}
	native, ok := t.slot.kernel.(*legacyExitNativeProtection)
	if !ok {
		return errors.New("candidate lost actual native creator")
	}
	if t.pin == nil {
		t.pin, err = native.PinImagePredecessor(ctx, t.envelope.ID, lease.lock)
		if err != nil {
			return err
		}
	}
	snapshot, err := t.pin.Snapshot(ctx)
	if err != nil {
		return err
	}
	if t.destination != nil && !reflect.DeepEqual(*t.destination, snapshot) {
		return errors.New("candidate receipt changed original acknowledgement")
	}
	t.destination = &snapshot
	t.phase = "successor-prepared"
	return nil
}
func (s *linuxStandardService) imageCandidateRequest(ctx context.Context, q linuxStandardServiceRequest) (*linuxStandardServiceImageUpgradeResponse, *os.File, error) {
	t := s.imageUpgrade
	var err error
	switch q.Action {
	case "image-successor-started":
		err = s.prepareImageSuccessor(ctx)
	case "image-freeze":
		if t.phase != "successor-prepared" && t.phase != "frozen" {
			err = errors.New("candidate freeze before actual preparation")
			break
		}
		if _, err = t.pin.Snapshot(ctx); err == nil {
			err = s.imageReleaseSource(ctx)
		}
		if err == nil {
			t.phase = "frozen"
		}
	case "image-code-promoted":
		if t.phase != "frozen" && t.phase != "code-verified" {
			err = errors.New("candidate code verification outside frozen phase")
			break
		}
		err = s.imageAcquireSource(ctx, t.newGeneration)
		if err == nil {
			t.phase = "code-verified"
		}
	case "image-commit":
		if t.phase != "code-verified" && t.phase != "successor-published" {
			err = errors.New("candidate publish before original code verification")
			break
		}
		err = t.pin.Resolve(ctx, t.source, true)
		if err != nil {
			break
		}
		t.removed = true
		lease, e := acquireLegacyExitMutationLease(ctx, s.root)
		if e != nil {
			err = e
			break
		}
		err = t.slot.publish(ctx, lease, func() error { return t.pin.Resolve(ctx, t.source, true) })
		lease.Close()
		if err == nil {
			t.slot.detached = true
			s.bootFailure = nil
			s.boot = t.slot
			t.phase = "successor-published"
		}
	case "image-activation-published":
		if err = s.loadProfilesContext(ctx); err != nil {
			break
		}
		if err = desktopnetwork.LockContext(ctx, &s.app.mu); err != nil {
			break
		}
		profile, exists := s.app.profileByIDLocked(t.envelope.ProfileID)
		s.app.mu.Unlock()
		revision, e := linuxStandardProfileDigest(profile)
		if e != nil || !exists || revision != t.envelope.ProfileRevision {
			err = errors.Join(e, errors.New("candidate READY changed original selected profile"))
			break
		}
		if !t.removed || !t.slot.persisted {
			err = errors.New("candidate READY before actual state publication")
			break
		}
		selected, e := captureLinuxStandardServiceGeneration(ctx, s.root)
		if e != nil {
			err = e
			break
		}
		if selected == nil {
			err = errors.New("candidate activation is absent")
			break
		}
		same := selected.selection == t.newGeneration.selection
		selected.Close()
		if !same {
			err = errors.New("candidate activation selected another generation")
			break
		}
		lease, e := acquireLegacyExitMutationLease(ctx, s.root)
		if e != nil {
			err = e
			break
		}
		err = t.slot.current(ctx, lease)
		lease.Close()
		if err != nil {
			break
		}
		image, e := os.Lstat(filepath.Join(s.root, "router-vpn-client"))
		if e != nil {
			err = e
			break
		}
		s.image = image
		err = s.notifyBoot(ctx, nil)
		if err == nil {
			t.ready = true
			t.phase = "successor-ready"
		}
	case "image-settle":
		if !t.ready {
			err = errors.New("candidate cannot settle before READY")
			break
		}
		var dead bool
		dead, err = t.oldPeer.Retired()
		if err == nil && !dead {
			err = errors.New("old original service has not joined")
		}
		if err == nil {
			if _, e := os.Lstat(t.oldGeneration.socket(linuxStandardServiceDirectory)); !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(e, errors.New("old original listener remains"))
			}
		}
		if err == nil {
			err = s.imageCurrent(ctx, t)
		}
		if err == nil {
			t.joined = true
			t.phase = "settled"
		}
	case "image-abort":
		if t.removed {
			err = errors.New("candidate cannot rollback removed original creator")
			break
		}
		err = s.imageReleaseSource(ctx)
		if err == nil {
			t.phase = "aborting"
		}
	case "image-code-restored":
		if t.phase != "aborting" {
			err = errors.New("candidate abort has no original rollback phase")
			break
		}
		if t.pin != nil && !t.abortPinResolved {
			err = t.pin.Resolve(ctx, t.source, false)
			if err != nil {
				break
			}
			t.abortPinResolved = true
		}
		if t.slot != nil && t.slot.kernel != nil {
			if !t.abortReleased {
				lease, e := acquireLegacyExitMutationLease(ctx, s.root)
				if e != nil {
					err = e
					break
				}
				err = t.slot.kernel.Release(ctx, lease.lock)
				lease.Close()
				if err != nil {
					break
				}
				t.abortReleased = true
			}
			if !t.abortClosed {
				err = t.slot.kernel.Close(ctx)
				if err != nil {
					break
				}
				t.abortClosed = true
			}
			if err != nil {
				break
			}
			err = t.slot.expected.Close()
		}
		if err == nil {
			t.phase = "aborted"
			s.quiescing = true
		}
	default:
		err = errors.New("candidate image action unavailable")
	}
	return t.view(), nil, err
}
