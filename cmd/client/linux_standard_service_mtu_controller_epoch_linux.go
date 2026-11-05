//go:build linux

package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// One retained transition belongs to the controller's original pre-launch
// observer. Receiving a service result cannot create or replace this token.
type linuxStandardControllerMTUTransition struct {
	key      standardengine.OperationKey
	observer *desktopnetwork.Transition
	digest   string
	original string
}

func (n *linuxStandardRequestEpoch) beginMTU(ctx context.Context, key standardengine.OperationKey) error {
	if n == nil || n.startup == nil || n.mtuTransition != nil || key.CaptureSHA256 != standardengine.SHA256(n.startup.Capture) ||
		key.Original != n.mtuBinding || key.Sequence != 0 && key.Sequence <= n.mtuSequence || key.DeadlineNS <= time.Now().UnixNano() ||
		!desktopMTURequestPattern.MatchString(key.ID) {
		return errors.New("standard MTU transition lost its original controller capture")
	}
	if ctx == nil {
		return errors.New("standard MTU transition has no caller")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || key.DeadlineNS > deadline.UnixNano() {
		return errors.New("standard MTU transition renewed its caller deadline")
	}
	if err := n.current(ctx, true); err != nil {
		return err
	}
	before, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt)
	if err != nil || standardengine.SHA256([]byte(n.mtuReceipt)) != key.Original.InitialReceiptSHA256 {
		return n.fail(errors.New("standard MTU transition changed its original native reader receipt"))
	}
	tracker, ok := n.observer.(interface {
		BeginRetained(context.Context, *desktopnetwork.DesktopNetworkReceipt) (*desktopnetwork.Transition, error)
	})
	if !ok {
		return errors.New("standard controller lacks its original retained transition capability")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return err
	}
	transition, err := tracker.BeginRetained(ctx, &before)
	if transition != nil {
		n.mtuTransition = &linuxStandardControllerMTUTransition{key: key, observer: transition, original: n.mtuReceipt}
	}
	if err != nil {
		return err
	}
	if transition == nil {
		return n.fail(errors.New("standard controller did not retain its admitted transition"))
	}
	if key.Sequence != 0 {
		n.mtuSequence = key.Sequence
	}
	return n.sources(ctx)
}

// A native worker must already have joined. The raw Ready and retirement pages
// remain distinct: a partially-created reader is never manufactured into Ready.
// The caller independently verifies the result digest over these exact pages.
func (n *linuxStandardRequestEpoch) endMTU(ctx context.Context, history standardengine.OperationReport) error {
	if n == nil || n.mtuTransition == nil || n.mtuTransition.key != history.Command.Reservation.Key ||
		!history.Result.WorkerJoined || history.Result.Pending || !desktopMTUPathPattern.MatchString(history.Result.Digest) {
		return errors.New("standard controller MTU result lacks its joined original operation")
	}
	op := n.mtuTransition
	if op.digest != "" {
		if op.digest != history.Result.Digest {
			return n.fail(errors.New("standard controller received changed joined MTU evidence"))
		}
		return n.sources(ctx)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return err
	}
	current, err := validateLinuxStandardServiceMTUReport(history, op.original)
	if err != nil {
		return n.fail(err)
	}
	for _, evidence := range history.Readers {
		if evidence == nil {
			continue
		}
		if len(evidence.Ready) != 0 {
			receipt, _ := desktopnetwork.ParseDesktopNetworkReceipt(string(evidence.Ready))
			if err := op.observer.Record(ctx, receipt); err != nil {
				return err
			}
		}
		if len(evidence.Retirement) != 0 {
			receipt, _ := desktopnetwork.ParseDesktopNetworkRetirementReceipt(string(evidence.Retirement))
			if err := op.observer.RecordRetirement(ctx, receipt); err != nil {
				return err
			}
		}
	}
	if err := op.observer.Complete(ctx, current); err != nil {
		return err
	}
	if current != nil {
		n.mtuReceipt = string(history.Readers[history.Result.CurrentRole].Ready)
		n.mtuBinding = history.Readers[history.Result.CurrentRole].Binding
	} else {
		n.mtuReceipt = ""
		n.mtuBinding = standardengine.ReaderBinding{}
	}
	op.digest = history.Result.Digest
	return n.sources(ctx)
}

// Both original observers use this parser, independently, on the authenticated
// raw child pages. The common digest proves correspondence, not native health.
func validateLinuxStandardServiceMTUReport(h standardengine.OperationReport, original string) (*desktopnetwork.DesktopNetworkReceipt, error) {
	bad := errors.New("standard MTU raw reader history changed its captured native identity")
	digest, err := standardengine.OperationResultDigest(h)
	if err != nil || digest != h.Result.Digest || !h.Result.WorkerJoined || h.Result.Pending ||
		h.Readers[standardengine.OriginalReader] == nil || string(h.Readers[standardengine.OriginalReader].Ready) != original ||
		standardengine.SHA256([]byte(original)) != h.Command.Reservation.Key.Original.InitialReceiptSHA256 ||
		h.Command.MTU < 1280 || h.Command.MTU > 9000 {
		return nil, bad
	}
	var current *desktopnetwork.DesktopNetworkReceipt
	for role, evidence := range h.Readers {
		if evidence == nil {
			continue
		}
		var receipt *desktopnetwork.DesktopNetworkReceipt
		if len(evidence.Ready) != 0 {
			parsed, err := desktopnetwork.ParseDesktopNetworkReceipt(string(evidence.Ready))
			if err != nil || parsed.TargetOS != "linux" {
				return nil, bad
			}
			receipt = &parsed
		}
		if len(evidence.Retirement) != 0 {
			parsed, err := desktopnetwork.ParseDesktopNetworkRetirementReceipt(string(evidence.Retirement))
			if err != nil || parsed.TargetOS != "linux" {
				return nil, bad
			}
			if receipt != nil && (!parsed.Created || parsed.Unindexed || parsed.Incarnation != receipt.Incarnation || parsed.Name != receipt.Name || parsed.Index != receipt.Index) {
				return nil, bad
			}
			if receipt != nil {
				for _, address := range receipt.Addresses {
					found := false
					for _, retired := range parsed.Addresses {
						if address == retired {
							found = true
							break
						}
					}
					if !found {
						return nil, bad
					}
				}
				for _, object := range receipt.Objects {
					found := false
					for _, retired := range parsed.Objects {
						if object == retired {
							found = true
							break
						}
					}
					if !found {
						return nil, bad
					}
				}
			}
		}
		if standardengine.OperationRole(role) == h.Result.CurrentRole {
			current = receipt
		}
	}
	if h.Result.CurrentRole == standardengine.NoReader {
		if !h.Result.Failed {
			return nil, bad
		}
		return nil, nil
	}
	if current == nil || !h.Result.Failed && current.MTU != h.Command.MTU {
		return nil, bad
	}
	return current, nil
}

// The controller admitted before the service reserved an FD11 slot. Only the
// returned exact key may fill in its sequence; identity and budget cannot move.
func (n *linuxStandardRequestEpoch) bindMTU(key standardengine.OperationKey) error {
	if n == nil || n.mtuTransition == nil {
		return errors.New("standard MTU response preceded controller admission")
	}
	expected := n.mtuTransition.key
	if expected.Sequence != 0 {
		if key == expected {
			return nil
		}
		return errors.New("standard MTU admission was replaced")
	}
	expected.Sequence = key.Sequence
	if expected != key || key.Sequence == 0 || key.Sequence <= n.mtuSequence {
		return errors.New("standard MTU service changed original admission or reused sequence")
	}
	n.mtuSequence = key.Sequence
	n.mtuTransition.key = key
	return nil
}

// Clear only after the service has acknowledged the very same joined digest
// and settled both original observers. Until then another candidate is blocked.
func (n *linuxStandardRequestEpoch) settledMTU(ctx context.Context, key standardengine.OperationKey, digest string) error {
	if n == nil || n.mtuTransition == nil || n.mtuTransition.key != key || n.mtuTransition.digest == "" || n.mtuTransition.digest != digest {
		return errors.New("standard controller MTU settlement changed its original result")
	}
	if err := n.sources(ctx); err != nil {
		return err
	}
	n.mtuTransition = nil
	if n.mtuReceipt == "" {
		return n.fail(errors.New("standard MTU transaction retired its current reader"))
	}
	return n.current(ctx, true)
}

// Rejection is accepted only after the service has definitively fenced this
// exact intent against submission and completed its own original observer.
// There is no native worker/receipt to invent for a command never submitted.
func (n *linuxStandardRequestEpoch) rejectMTU(ctx context.Context, rejected linuxStandardServiceMTURejected) error {
	if n == nil || n.mtuTransition == nil {
		return errors.New("standard MTU rejection lost original controller admission")
	}
	op := n.mtuTransition
	if op.digest != "" || op.key.ID != rejected.ID || op.key.DeadlineNS != rejected.DeadlineNS || op.key.Original != rejected.Expected || n.mtuBinding != rejected.Expected {
		return errors.New("standard MTU rejection changed original admission")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return err
	}
	original, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt)
	if err != nil {
		return err
	}
	if err := op.observer.Complete(ctx, &original); err != nil {
		return err
	}
	n.mtuTransition = nil
	return n.current(ctx, true)
}

// Only the caller that has not sent any service command may abandon this local
// observer admission. Once a write is possible, service rejection/join is needed.
func (n *linuxStandardRequestEpoch) abandonUnsentMTU(ctx context.Context, key standardengine.OperationKey) error {
	if n == nil || n.mtuTransition == nil {
		return nil
	}
	if n.mtuTransition.key != key || n.mtuTransition.digest != "" {
		return errors.New("standard MTU unsent admission was replaced")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return err
	}
	original, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt)
	if err != nil {
		return err
	}
	if err := n.mtuTransition.observer.Complete(ctx, &original); err != nil {
		return err
	}
	n.mtuTransition = nil
	return n.current(ctx, true)
}

// An owned Stop may retire an unhealthy activation using validated actual
// joined history. This grants cleanup only, never observer settlement or health.
func (n *linuxStandardRequestEpoch) retireMTUForStop(ctx context.Context, report standardengine.OperationReport) error {
	if n == nil || n.mtuTransition == nil || n.mtuTransition.key != report.Command.Reservation.Key {
		return errors.New("standard MTU Stop lost its original joined transaction")
	}
	current, err := validateLinuxStandardServiceMTUReport(report, n.mtuTransition.original)
	if err != nil {
		return err
	}
	if current != nil {
		n.mtuReceipt = string(report.Readers[report.Result.CurrentRole].Ready)
		n.mtuBinding = report.Readers[report.Result.CurrentRole].Binding
	} else {
		n.mtuReceipt = ""
		n.mtuBinding = standardengine.ReaderBinding{}
	}
	n.fail(errors.New("standard MTU activation is retiring without a healthy observer settlement"))
	if err := n.close(ctx); err != nil {
		return err
	}
	n.mtuTransition = nil
	return nil
}

func (n *linuxStandardRequestEpoch) retireRejectedMTUForStop(ctx context.Context, rejected linuxStandardServiceMTURejected) error {
	if n == nil || n.mtuTransition == nil {
		return errors.New("standard MTU Stop rejection lost original admission")
	}
	key := n.mtuTransition.key
	if n.mtuTransition.digest != "" || key.ID != rejected.ID || key.DeadlineNS != rejected.DeadlineNS || key.Original != rejected.Expected || n.mtuBinding != rejected.Expected || standardengine.SHA256([]byte(n.mtuReceipt)) != rejected.Expected.InitialReceiptSHA256 {
		return errors.New("standard MTU Stop rejection changed original unsent intent")
	}
	if _, err := desktopnetwork.ParseDesktopNetworkReceipt(n.mtuReceipt); err != nil {
		return err
	}
	n.fail(errors.New("standard MTU rejected activation is retiring without a healthy observer settlement"))
	if err := n.close(ctx); err != nil {
		return err
	}
	n.mtuTransition = nil
	return nil
}
