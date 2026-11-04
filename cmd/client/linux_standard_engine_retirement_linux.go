//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
	"runtime"
	"time"
)

// The original child result and complete native readback are both required.
// A signal/nonzero exit, TUN disappearance or engine process join alone never
// authorizes guard release. These failures retain the original owner for a
// later explicit recovery; no deletion authority is inferred from the dump.
func (n *linuxStandardEngine) routingRetired(ctx context.Context) error {
	if n == nil || n.owner == nil || n.tracker == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("standard native retirement lost original evidence")
	}
	o := n.owner
	completion := o.completion
	if !o.started || !o.processRetired || completion == nil || completion.command != o.command || completion.done != o.done || o.done == nil {
		return errors.New("standard native retirement has no original child completion")
	}
	select {
	case <-completion.done:
	default:
		return errors.New("standard native retirement has not joined its original completion")
	}
	if completion.failure != nil {
		return errors.Join(errors.New("original standard engine did not complete native cleanup successfully"), completion.failure)
	}
	if completion.state == nil || completion.state != o.command.ProcessState || o.command.Process == nil || completion.state.Pid() != o.command.Process.Pid || !completion.state.Exited() || !completion.state.Success() {
		return errors.New("original standard engine has no successful created-child exit state")
	}
	if n.cleanup == nil {
		return errors.New("standard native retirement lost original inherited result object")
	}
	result, err := n.cleanup.ReadResult(n.captureSHA)
	if err != nil {
		return err
	}
	if !result.Complete {
		return errors.New("original native cleanup result remains pending")
	}
	if result.Sequence == 0 && result.StartupFailed {
		raw, err := standardengine.ReadSealed(n.capture, 2048)
		if err != nil {
			return err
		}
		capture, err := standardengine.DecodeCapture(raw, n.captureSHA)
		if err != nil {
			return err
		}
		if result.DeadlineNS > capture.DeadlineNS {
			return errors.New("self cleanup extended the original startup deadline")
		}
	}
	if result.Sequence != 0 {
		deadline, issued := n.cleanupRequests[result.Sequence]
		if !issued || deadline != result.DeadlineNS {
			return errors.New("native cleanup result has no original issued attempt")
		}
	}
	retirement, err := desktopnetwork.ParseDesktopNetworkRetirementReceipt(result.Ledger)
	if err != nil {
		return err
	}
	if prior := n.routingReceipt; prior != nil {
		if !retirement.Created || retirement.Unindexed || retirement.Index != prior.Index || retirement.Name != prior.Name || retirement.Incarnation != prior.Incarnation {
			return errors.New("native cleanup result changed its original ready TUN")
		}
		owned := make(map[string]bool, len(retirement.Objects))
		for _, object := range retirement.Objects {
			owned[object.Key()] = true
		}
		for _, object := range prior.Objects {
			if !owned[object.Key()] {
				return errors.New("native cleanup result omitted original acknowledged routing")
			}
		}
	}
	reader, ok := n.tracker.(interface {
		RoutingAbsent(context.Context, *desktopnetwork.DesktopNetworkRetirementReceipt) error
	})
	if !ok {
		return errors.New("standard native retirement omitted its original routing observer")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	if err := reader.RoutingAbsent(ctx, &retirement); err != nil {
		return err
	}
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	return ctx.Err()
}

func (n *linuxStandardEngine) retainRoutingReceipt(receipt desktopnetwork.DesktopNetworkReceipt) {
	copy := receipt
	copy.Addresses = append([]string(nil), receipt.Addresses...)
	copy.Objects = append([]desktopnetwork.DesktopNetworkObject(nil), receipt.Objects...)
	n.routingReceipt = &copy
}

// The original service writes a bounded attempt before signaling its original
// child. A timeout leaves the same process/control object retained; no SIGKILL
// escalation can replace the child's actual cleanup acknowledgement.
func (n *linuxStandardEngine) requestCleanup(ctx context.Context) error {
	if n == nil || n.cleanup == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native cleanup request lost its original caller")
	}
	if err := n.cleanup.Current(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("native cleanup request has no original deadline")
	}
	if maximum := time.Now().Add(15 * time.Second); deadline.After(maximum) {
		deadline = maximum
	}
	// A serial failed result settles that attempt and every older attempt.
	// Complete, unknown or torn results never permit discarding prior success.
	if result, err := n.cleanup.ReadResult(n.captureSHA); err == nil && !result.Complete && result.Sequence != 0 {
		if deadline, issued := n.cleanupRequests[result.Sequence]; issued && deadline == result.DeadlineNS {
			for sequence := range n.cleanupRequests {
				if sequence <= result.Sequence {
					delete(n.cleanupRequests, sequence)
				}
			}
		}
	}
	if len(n.cleanupRequests) >= 32 {
		return errors.New("original native cleanup has too many unsettled attempts")
	}
	if n.cleanupSequence == ^uint64(0) {
		return errors.New("native cleanup sequence exhausted")
	}
	n.cleanupSequence++
	n.cleanupDeadline = deadline.UnixNano()
	if n.cleanupRequests == nil {
		n.cleanupRequests = make(map[uint64]int64)
	}
	n.cleanupRequests[n.cleanupSequence] = n.cleanupDeadline
	request := standardengine.CleanupRequest{Schema: 1, CaptureSHA256: n.captureSHA, Sequence: n.cleanupSequence, DeadlineNS: n.cleanupDeadline}
	if err := n.cleanup.WriteRequest(request); err != nil {
		return err
	}
	return ctx.Err()
}
