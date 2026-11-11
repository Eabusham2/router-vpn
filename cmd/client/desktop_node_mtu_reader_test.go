package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// The real sealed policy and private-file parent protocol run here. Only the
// native child and the host's kernel/proof observation are controlled; these
// tests do not claim an actual Darwin descriptor, PF grant or device mutation.
type desktopNodeMTUForeignImported struct{ desktopImportedPlatformRuntime }

func desktopNodeMTUReaderFixture(t *testing.T, policy *mobilemultihop.DesktopNodeChainPolicy) *desktopNodeMTUFixture {
	t.Helper()
	fixture := newDesktopNodeMTUFixture(t)
	meta := policy.Metadata()
	fixture.launch.mtuSession, fixture.launch.configSHA256 = meta.SessionID, meta.ConfigSHA256
	fixture.launch.chain = &desktopNodeChainLaunch{policy: policy, platform: &desktopNodeChainPlatformRuntime{}}
	fixture.base.Session, fixture.base.Config = meta.SessionID, meta.ConfigSHA256
	fixture.base.Interface = "utun991"
	if err := fixture.publish(fixture.base, false); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestDesktopNodeMTUDarwinReaderMailboxLifecycle(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, ending := range []string{"commit", "restore", "close"} {
		t.Run(ending, func(t *testing.T) {
			fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
			commands := startDesktopNodeMTUFixtureChild(t, fixture, func(_ desktopNodeMTUCommand, next *desktopNodeMTURecord) {
				next.Interface = fmt.Sprintf("utun%d", 990+next.Reader)
			})
			type marker struct{}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), marker{}, ending), 3*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			kernel, err := openDesktopNodeMTUOwnerContext(ctx, fixture.launch,
				mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: fixture.base.MTU}, strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			owner := kernel.(*desktopNodeMTUOwner)
			if owner.record.Reader != fixture.base.Reader || owner.record.Interface != fixture.base.Interface {
				t.Fatal("begin changed the original native reader before verifier installation")
			}
			proofs := 0
			owner.verifyReaderChange = func(call context.Context, previous, next desktopNodeMTURecord) error {
				if owner.mu.TryLock() {
					owner.mu.Unlock()
					return errors.New("reader proof escaped the original raw owner lock")
				}
				bound, bounded := call.Deadline()
				if !bounded || bound.After(deadline) || call.Value(marker{}) != ending || call.Err() != nil ||
					previous != owner.record || owner.pending == nil || next.Request != owner.pending.Request ||
					next.Generation != owner.pending.Generation || next.Reader != previous.Reader+1 ||
					next.Interface == previous.Interface || next.Index == previous.Index {
					return errors.New("reader proof lost the original caller, pending nonce or predecessor")
				}
				if _, err := readDesktopRuntimeFileContext(call, fixture.launch, "node-mtu-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
					return errors.New("reader proof preceded command consumption")
				}
				actual, err := readDesktopNodeMTUContext(call, fixture.launch)
				if err != nil || actual != next {
					return errors.New("reader proof did not receive the exact native acknowledgement")
				}
				proofs++
				return nil
			}
			before, err := owner.ReadContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			next, err := owner.ChangeContext(ctx, before, 1380)
			if err != nil || next.Interface != "utun992" || next.Identity == before.Identity || proofs != 1 {
				t.Fatal("proved native utun successor was not adopted", next, proofs, err)
			}
			if ending == "commit" {
				if err := owner.CommitContext(ctx); err != nil {
					t.Fatal(err)
				}
			} else if ending == "restore" {
				restored, err := owner.RestoreContext(ctx)
				if err != nil || restored.Interface != "utun993" || restored.MTU != before.MTU || proofs != 2 {
					t.Fatal("rollback did not prove its own new utun reader", restored, proofs, err)
				}
			}
			if err := owner.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			wantProofs, wantMTU := 2, before.MTU
			if ending == "commit" {
				wantProofs, wantMTU = 1, 1380
			}
			if proofs != wantProofs || owner.record.MTU != wantMTU || owner.record.Active || !owner.closed {
				t.Fatal("final reader ownership or lifecycle changed", owner.record, proofs)
			}
			if state, restored := owner.CleanupRestored(); restored != (ending != "commit") ||
				restored && (state.Interface != "utun993" || state.MTU != before.MTU) {
				t.Fatal("cleanup lost the exact proved rollback reader", state, restored)
			}
			finalAction := "rollback"
			if ending == "commit" {
				finalAction = "commit"
			}
			for index, action := range []string{"begin", "set", finalAction} {
				select {
				case command := <-commands:
					if command.Action != action || command.Reader != uint64(index/2+1) {
						t.Fatal("native lifecycle changed its original operation sequence", command, action)
					}
				case <-ctx.Done():
					t.Fatal("native lifecycle command was missing", ctx.Err())
				}
			}
		})
	}
}

func TestDesktopNodeMTUDarwinReaderRejectsUnprovedOrForeignSuccessor(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, fault := range []string{
		"missing-verifier", "missing-chain", "missing-platform", "missing-policy", "ordinary-external",
		"imported-entry", "imported-platform", "tor", "policy-config", "policy-session",
		"same-reader", "reader-jump", "wrong-lease", "wrong-value", "same-reader-new-index",
		"fixed-name", "empty-number", "upper-case", "unicode-number", "separator", "old-fixed-name",
	} {
		t.Run(fault, func(t *testing.T) {
			fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
			owner := fixture.owner(true)
			called := 0
			owner.verifyReaderChange = func(context.Context, desktopNodeMTURecord, desktopNodeMTURecord) error {
				called++
				return nil
			}
			switch fault {
			case "missing-verifier":
				owner.verifyReaderChange = nil
			case "missing-chain":
				fixture.launch.chain = nil
			case "missing-platform":
				fixture.launch.chain.platform = nil
			case "missing-policy":
				fixture.launch.chain.policy = nil
			case "ordinary-external":
				fixture.launch.external = &desktopExternalRuntime{}
			case "imported-entry":
				fixture.launch.importedEntry = true
			case "imported-platform":
				// The original imported family has its own retained platform.
				// The concrete implementation is irrelevant to this raw gate.
				fixture.launch.importedPlatform = &desktopNodeMTUForeignImported{}
			case "tor":
				fixture.launch.tor = &desktopTorRuntime{}
			case "policy-config":
				fixture.launch.configSHA256, owner.record.Config = strings.Repeat("d", 64), strings.Repeat("d", 64)
			case "policy-session":
				fixture.launch.mtuSession, owner.record.Session = strings.Repeat("d", 32), strings.Repeat("d", 32)
			case "old-fixed-name":
				owner.record.Interface = "router-vpn"
			}
			command, ack := nodeMTUAck(owner, "set", 1380)
			ack.Interface = "utun992"
			switch fault {
			case "same-reader":
				ack.Reader, ack.Index, ack.MTU = owner.record.Reader, owner.record.Index, owner.record.MTU
				command.Value = ack.MTU
			case "same-reader-new-index":
				ack.Reader = owner.record.Reader
			case "reader-jump":
				ack.Reader = owner.record.Reader + 2
			case "wrong-lease":
				ack.Lease = strings.Repeat("e", 32)
			case "wrong-value":
				ack.MTU = 1390
			case "fixed-name":
				ack.Interface = "router-vpn"
			case "empty-number":
				ack.Interface = "utun"
			case "upper-case":
				ack.Interface = "UTUN992"
			case "unicode-number":
				ack.Interface = "utun９９２"
			case "separator":
				ack.Interface = "utun-992"
			}
			before := owner.record
			owner.pending = &command
			if err := fixture.publish(ack, true); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err := owner.drainContext(ctx); err == nil {
				t.Fatal("unproved or foreign native interface was adopted", fault)
			}
			if called != 0 || owner.record != before || owner.pending != &command || owner.closed || owner.committed {
				t.Fatal("rejected interface replaced or discarded the original cleanup owner", fault, called)
			}
		})
	}
}

func TestDesktopNodeMTUDarwinReaderProofFailureRetainsExactRetry(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, fault := range []string{"missing-native-proof", "cancelled-during-proof"} {
		t.Run(fault, func(t *testing.T) {
			fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
			owner := fixture.owner(true)
			command, ack := nodeMTUAck(owner, "set", 1380)
			ack.Interface = "utun992"
			before := owner.record
			owner.pending = &command
			if err := fixture.publish(ack, true); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			proofErr := errors.New("original native proof or retired kernel predecessor is unavailable")
			owner.verifyReaderChange = func(call context.Context, previous, next desktopNodeMTURecord) error {
				calls++
				if previous != before || next.Interface != ack.Interface || next.Reader != ack.Reader || owner.record != before {
					return errors.New("retry changed its captured reader proof inputs")
				}
				if calls == 1 {
					if fault == "cancelled-during-proof" {
						cancel()
						return nil
					}
					return proofErr
				}
				return call.Err()
			}
			err := owner.drainContext(ctx)
			if fault == "missing-native-proof" && !errors.Is(err, proofErr) ||
				fault == "cancelled-during-proof" && !errors.Is(err, context.Canceled) ||
				owner.pending != &command || owner.record != before || calls != 1 {
				t.Fatal("failed proof lost its exact pending operation", err, calls)
			}
			retry, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := owner.drainContext(retry); err != nil || calls != 2 || owner.pending != nil ||
				owner.record.Request != command.Request || owner.record.Interface != "utun992" || owner.record.Reader != ack.Reader {
				t.Fatal("original consumed acknowledgement could not be retried exactly", err, calls)
			}
		})
	}
}

func TestDesktopNodeMTUDarwinReaderExpiryUsesSameProofAndReaderBudget(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, kind := range []string{"one-reader", "pending-two-readers", "proof-refused", "missing-proof", "same-reader", "reader-jump", "unconsumed-command", "cancelled-proof"} {
		t.Run(kind, func(t *testing.T) {
			fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
			owner := fixture.owner(true)
			owner.record.MTU = 1380
			before := owner.record
			ack := before
			ack.Reader, ack.Index, ack.Interface, ack.MTU = before.Reader+1, before.Index+1, "utun992", owner.originalMTU
			ack.Active, ack.Restored, ack.Expired = false, true, true
			ack.Failure = "captured MTU lease expired; original MTU restored"
			if kind == "pending-two-readers" || kind == "unconsumed-command" {
				command, _ := nodeMTUAck(owner, "set", 1360)
				owner.pending = &command
				ack.Generation, ack.Request = command.Generation, command.Request
				ack.Reader, ack.Index, ack.Interface = before.Reader+2, before.Index+2, "utun993"
				if kind == "unconsumed-command" {
					if err := writeDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", []byte("{}"), true); err != nil {
						t.Fatal(err)
					}
				}
			}
			pending := owner.pending
			if kind == "same-reader" {
				ack.Reader, ack.Index, ack.MTU = before.Reader, before.Index, before.MTU
				owner.originalMTU = before.MTU
			} else if kind == "reader-jump" {
				ack.Reader = before.Reader + 3
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			called := 0
			owner.verifyReaderChange = func(call context.Context, previous, next desktopNodeMTURecord) error {
				called++
				if previous != before || next != ack || owner.record != before || call.Err() != nil {
					return errors.New("expiry proof changed its exact predecessor or receipt")
				}
				if kind == "proof-refused" {
					return errors.New("original kernel reader retirement was not confirmed")
				}
				if kind == "cancelled-proof" {
					cancel()
				}
				return nil
			}
			if kind == "missing-proof" {
				owner.verifyReaderChange = nil
			}
			if err := fixture.publish(ack, false); err != nil {
				t.Fatal(err)
			}
			actual, err := readDesktopNodeMTUContext(ctx, fixture.launch)
			if err != nil {
				t.Fatal(err)
			}
			ack = actual
			restored, err := owner.acceptExpiredRestorationContext(ctx, ack)
			valid := kind == "one-reader" || kind == "pending-two-readers"
			if valid {
				if err != nil || !restored || called != 1 || owner.record != ack || owner.pending != nil ||
					!owner.committed || !owner.record.Restored || owner.record.MTU != owner.originalMTU {
					t.Fatal("proved expiry did not retain its exact original-value successor", err, called)
				}
			} else if restored || owner.record != before || owner.pending != pending || owner.committed ||
				kind != "unconsumed-command" && err == nil {
				t.Fatal("invalid expiry released or replaced its original lease", kind, restored, err)
			}
		})
	}
}

func TestDesktopNodeMTUDarwinRejectedMutationStillRequiresSuccessorProof(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, proved := range []bool{false, true} {
		t.Run(fmt.Sprint(proved), func(t *testing.T) {
			fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
			owner := fixture.owner(true)
			before := owner.record
			command, ack := nodeMTUAck(owner, "set", 1380)
			ack.Interface, ack.MTU, ack.Failure = "utun992", owner.originalMTU, "captured TUN operation rejected"
			owner.pending = &command
			called := 0
			owner.verifyReaderChange = func(context.Context, desktopNodeMTURecord, desktopNodeMTURecord) error {
				called++
				if !proved {
					return errors.New("failed native mutation has no proved rollback reader")
				}
				return nil
			}
			if err := fixture.publish(ack, true); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := owner.drainContext(ctx); err == nil || called != 1 {
				t.Fatal("native rejection became success or skipped reader proof", err, called)
			}
			if proved {
				if owner.pending != nil || owner.record.Reader != ack.Reader || owner.record.Interface != ack.Interface ||
					owner.record.MTU != owner.originalMTU || !owner.record.Active || owner.record.Failure == "" {
					t.Fatal("proved failed mutation lost its retained owned rollback reader", owner.record)
				}
			} else if owner.pending != &command || owner.record != before {
				t.Fatal("unproved failed mutation replaced its cleanup owner")
			}
		})
	}
}

func TestDesktopNodeMTUReaderSuccessionKeepsFixedTargetContracts(t *testing.T) {
	for _, target := range []string{"windows", "linux", "ordinary"} {
		t.Run(target, func(t *testing.T) {
			policyTarget := target
			if target == "ordinary" {
				policyTarget = "darwin"
			}
			_, sealed := desktopNodeChainLaunchFixture(t, 3, policyTarget)
			for _, rename := range []bool{false, true} {
				t.Run(fmt.Sprint(rename), func(t *testing.T) {
					fixture := desktopNodeMTUReaderFixture(t, sealed.chain.policy)
					if target == "ordinary" {
						fixture.launch.chain = nil
					}
					owner := fixture.owner(true)
					before := owner.record
					command, ack := nodeMTUAck(owner, "set", 1380)
					if rename {
						ack.Interface = "utun992"
					}
					owner.pending = &command
					called := 0
					owner.verifyReaderChange = func(context.Context, desktopNodeMTURecord, desktopNodeMTURecord) error {
						called++
						return nil
					}
					if err := fixture.publish(ack, true); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					err := owner.drainContext(ctx)
					if called != 0 || rename && (err == nil || owner.record != before || owner.pending != &command) ||
						!rename && (err != nil || owner.pending != nil || owner.record.Interface != before.Interface || owner.record.Reader != before.Reader+1) {
						t.Fatal("fixed-name target changed its original native reader contract", target, rename, called, err)
					}
				})
			}
		})
	}
}
