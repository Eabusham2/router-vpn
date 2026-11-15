//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

type windowsCONNECTExecutionObservation struct {
	Connected, PublicConnect, Restored  bool
	Requested, Winner, Source, Transfer string
	PID                                 int
	Ready                               mobilemultihop.DesktopNodeChainExecutionReadyRecord
	Comparison                          json.RawMessage
}

func windowsCONNECTExecutionObserve(ctx context.Context, a *app) (windowsCONNECTExecutionObservation, error) {
	var result windowsCONNECTExecutionObservation
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return result, errors.Join(err, errors.New("original execution owner absent"))
	}
	s := owner.session
	if err = s.Current(ctx); err != nil {
		return result, err
	}
	e := s.execution
	if e == nil || e.physical != nil || e.connectPhysical == nil || s.launch.ownedNode == nil || e.original != s.launch.chain || e.original.connectPolicy == nil || e.original.policy != nil {
		return result, errors.New("original typed Windows physical owner changed")
	}
	process, ok := desktopOwnedNodeProcess(s.launch).(*desktopNodeWindowsJournalProcess)
	if !ok || process == nil || process.launch != s.launch || process.attempt != s.launch.ownedNode.attempt || process.attempt.connectChain != e.original.connectPolicy || process.attempt.chain != nil || process.slot != s.launch.ownedNode.slot {
		return result, errors.New("original Windows process/slot/typed policy changed")
	}
	e.mu.Lock()
	if e.ready != nil {
		result.Ready = *e.ready
	}
	e.mu.Unlock()
	_, meta, capture, err := e.readPolicy()
	if err != nil || meta.TargetOS != "windows" || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Host != "192.168.50.133" {
		return result, errors.Join(err, errors.New("original physical/DNS capture changed"))
	}
	if s.launch.command == nil || s.launch.command.Process == nil {
		return result, errors.New("original native process absent")
	}
	result.PID = s.launch.command.Process.Pid
	result.Source = meta.SourceSHA256
	result.Transfer = result.Ready.TransferSHA256
	result.Requested = e.preparation.Execution()
	result.Winner = result.Ready.Progress.Execution
	result.Comparison, _ = json.Marshal(result.Ready.Progress.Comparison)
	a.mu.Lock()
	result.Connected = a.state.Connected && a.cmd == s.launch.command
	a.mu.Unlock()
	if !result.Connected || result.Transfer == "" || result.Ready.Kind != "routervpn-node-chain-connect-execution-ready-v1" || result.Ready.InterfaceName != "router-vpn" || result.Ready.InterfaceIndex == 0 || !result.Ready.Progress.DNSProven {
		return result, errors.New("selected Windows TUN/DNS proof absent")
	}
	return result, nil
}

// Retained sessions are captured before public Disconnect removes its registry.
// Replacement revokes observation but cannot substitute retirement authority.
func windowsCONNECTExecutionRetired(ctx context.Context, a *app, sessions []*desktopNodeChainExecutionSession) error {
	if len(sessions) == 0 {
		return errors.New("no original entered Windows session captured")
	}
	a.mu.Lock()
	connected := a.state.Connected
	a.mu.Unlock()
	if connected {
		return errors.New("retired execution remained Connected")
	}
	for _, s := range sessions {
		if s == nil || s.app != a || s.execution == nil || s.execution.connectPhysical == nil || s.execution.physical != nil || s.launch.ownedNode == nil {
			return errors.New("retirement replaced original typed owner")
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		process, ok := desktopOwnedNodeProcess(s.launch).(*desktopNodeWindowsJournalProcess)
		if !closed || !ok || process == nil || process.attempt != s.launch.ownedNode.attempt || process.attempt.connectChain != s.execution.original.connectPolicy || process.attempt.chain != nil || !process.slot.provedEmpty() {
			return errors.New("original Windows child/slot did not join")
		}
		outcome, err := process.JournalOutcome()
		if err != nil || outcome.Validate() != nil {
			return errors.Join(err, errors.New("authenticated child outcome absent"))
		}
		capture := process.controller
		if capture == nil || len(capture.directories) != 1 {
			return errors.New("original journal location changed")
		}
		journal, err := windowsprotection.OpenProtectionJournal(ctx, capture.parent, capture.directories[0])
		if err != nil {
			if journal != nil {
				err = errors.Join(err, journal.Close())
			}
			return err
		}
		head, err := journal.Snapshot(ctx)
		err = errors.Join(err, journal.Close())
		if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
			return errors.Join(err, errors.New("original WFP journal did not settle"))
		}
	}
	absent, err := mobiletor.ProbeDesktopWindowsProtectionAbsent(ctx)
	if err != nil || !absent {
		return errors.Join(err, errors.New("original WFP rules survived Disconnect"))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Name == "router-vpn" {
			return errors.New("original TUN survived Disconnect")
		}
	}
	return nil
}
