//go:build linux && routervpn_linux_guardian

package linuxprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "routervpn-owned-socket-helper" {
		if err := mobiletor.RunDesktopLinuxSocketHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		os.Exit(0)
	}
}

func requireNodeControlNamespace(t *testing.T) {
	t.Helper()
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node control requires its actual isolated native guardian namespace", err)
	}
}

type nodeControlOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *nodeControlOutput) Write(body []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(body)
}
func (o *nodeControlOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

type nodeControlNativeOwner struct {
	parent    *linuxprocess.Witness
	bootstrap *linuxprocess.Bootstrap
	command   *exec.Cmd
	joined    chan struct{}
	joinErr   error
	cancel    context.CancelFunc
	output    nodeControlOutput
	baseline  *mobiletor.DesktopLinuxNodeBaseline
}

// The first Err read under the original control gate belongs to enter's
// mandatory post-acquire cancellation check. The second cancels a genuinely
// live caller after entry, without changing any native owner or kernel result.
// With the old direct-context read it lands inside Bootstrap.CheckCapture;
// with the independent observation it lands at Current's final caller check.
type nodeControlCancelEntered struct {
	context.Context
	cancel context.CancelFunc
	gate   <-chan struct{}
	checks atomic.Uint32
}

func (c *nodeControlCancelEntered) Err() error {
	if len(c.gate) == 0 && c.checks.Add(1) == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func checkNodeControlEnteredCancellation(t *testing.T, ctx context.Context, control *NodeControl) {
	t.Helper()
	strictCaller, strictCancel := context.WithCancel(ctx)
	defer strictCancel()
	strictEntered := &nodeControlCancelEntered{Context: strictCaller, cancel: strictCancel, gate: control.gate}
	if err := control.CurrentContext(strictEntered); !errors.Is(err, context.Canceled) || strictEntered.checks.Load() < 2 || control.uncertain != nil {
		t.Fatal("strict read changed original caller or retirement authority", err, strictEntered.checks.Load(), control.uncertain)
	}
	if err := control.CurrentContext(ctx); err != nil {
		t.Fatal("strict expiry retired actual admitted native participants", err)
	}
	caller, cancel := context.WithCancel(ctx)
	defer cancel()
	entered := &nodeControlCancelEntered{Context: caller, cancel: cancel, gate: control.gate}
	if err := control.Current(entered); !errors.Is(err, context.Canceled) || entered.checks.Load() < 2 || caller.Err() != context.Canceled {
		t.Fatal("entered read-only Current did not retain its actual caller cancellation", err, entered.checks.Load())
	}
	if control.uncertain != nil {
		t.Fatal("cancelled read-only Current poisoned its original retirement authority", control.uncertain)
	}
	if err := control.Current(ctx); err != nil {
		t.Fatal("cancelled read-only Current lost its still-live original native participants", err)
	}
}

func startNodeControlChild(t *testing.T, scenario string) (*nodeControlNativeOwner, NodeSelection) {
	t.Helper()
	requireNodeControlNamespace(t)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	selection := NodeSelection{SessionID: hex.EncodeToString(nonce[:]), SourceSHA256: strings.Repeat("4", 64),
		ConfigSHA256: strings.Repeat("5", 64), Policy: "always"}
	owner := &nodeControlNativeOwner{joined: make(chan struct{})}
	var err error
	owner.parent, err = linuxprocess.CaptureSelf(context.Background())
	if err != nil {
		if owner.parent != nil {
			_ = owner.parent.Close(context.Background())
		}
		t.Fatal(err)
	}
	observation, err := owner.parent.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := owner.parent.DuplicateDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	channel, childEndpoint, err := linuxprocess.ChannelPair()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(selection)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	owner.cancel = cancel
	owner.command = exec.CommandContext(ctx, image, "-test.run=^TestLinuxNodeControlNativeWorker$", "-test.count=1", "-test.timeout=23s")
	owner.command.Env = []string{"PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_LINUX_GUARDIAN_TEST_NS=1",
		"ROUTERVPN_NODE_CONTROL_CASE=" + scenario, "ROUTERVPN_NODE_CONTROL_SELECTION=" + string(body)}
	owner.command.ExtraFiles = []*os.File{childEndpoint, directory}
	pidfd := -1
	owner.command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	owner.command.Stdout, owner.command.Stderr = &owner.output, &owner.output
	if err := owner.command.Start(); err != nil {
		_ = childEndpoint.Close()
		_ = directory.Close()
		_ = channel.Close(context.Background())
		_ = owner.parent.Close(context.Background())
		cancel()
		t.Fatal(err)
	}
	go func() { owner.joinErr = owner.command.Wait(); close(owner.joined) }()
	t.Cleanup(func() {
		if owner.bootstrap != nil {
			_ = owner.bootstrap.Close(context.Background())
		} else {
			_ = channel.Close(context.Background())
		}
		cancel()
		<-owner.joined
		if owner.baseline != nil {
			// This original disposable fixture creator cleans only after its
			// actual engine joined and native closed readback succeeds. This
			// is test namespace cleanup, not a production journal settlement.
			if err := owner.baseline.ObserveClosed(context.Background()); err == nil {
				if err := owner.baseline.Release(context.Background()); err != nil {
					t.Error(err)
				}
			}
			if err := owner.baseline.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}
		if err := owner.parent.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := errors.Join(childEndpoint.Close(), directory.Close()); err != nil || pidfd < 0 {
		t.Fatal("actual Node control launch lost its original inherited files or clone pidfd", err)
	}
	commandCapture, _ := selection.CaptureSHA256()
	owner.bootstrap, err = linuxprocess.BindCreatedChild(ctx, channel, owner.parent, os.NewFile(uintptr(pidfd), "node-control-original-clone"),
		owner.command.Process.Pid, observation.Image, commandCapture)
	if err != nil {
		t.Fatal("actual Node child authentication failed", err, owner.output.String())
	}
	return owner, selection
}

func TestLinuxNodeControlNativeWorker(t *testing.T) {
	scenario := os.Getenv("ROUTERVPN_NODE_CONTROL_CASE")
	if scenario == "" {
		return
	}
	requireNodeControlNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var selection NodeSelection
	if err := json.Unmarshal([]byte(os.Getenv("ROUTERVPN_NODE_CONTROL_SELECTION")), &selection); err != nil || selection.Validate() != nil {
		t.Fatal("native fixture lost its independently captured selection", err)
	}
	channel, err := linuxprocess.CaptureChannel(os.NewFile(3, "original-node-control-channel"))
	if err != nil {
		t.Fatal(err)
	}
	commandCapture, _ := selection.CaptureSHA256()
	bootstrap, err := linuxprocess.BindInheritedParent(ctx, channel, os.NewFile(4, "original-node-control-parent"), commandCapture)
	if bootstrap != nil {
		defer bootstrap.Close(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNodeParentControl(ctx, bootstrap, selection); err == nil {
		t.Fatal("actual child process claimed its parent's control role")
	}
	if scenario == "foreign-selection" {
		selection.HomeLAN = !selection.HomeLAN
	}
	control, err := NewNodeChildControl(ctx, bootstrap, selection)
	if err != nil {
		t.Fatal(err)
	}
	capture := mobiletor.DesktopSocketCapture{SessionID: selection.SessionID, SourceSHA256: selection.SourceSHA256, NetworkID: strings.Repeat("6", 32)}
	if scenario == "before-baseline" {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if _, err := control.CreateBaseline(cancelled, capture); err == nil {
			t.Fatal("cancelled preparation sent a new baseline request")
		}
		if err := control.Retire(ctx, nil); err != nil {
			t.Fatal(err)
		}
		return
	}
	_, err = control.CreateBaseline(ctx, capture)
	if scenario == "foreign-selection" {
		if err == nil {
			t.Fatal("foreign selected policy obtained a baseline receipt")
		}
		return
	}
	if scenario == "refuse-creation" {
		if !errors.Is(err, ErrNodeControlRefused) {
			t.Fatal("actual refusal was not delivered before source creation", err)
		}
		if err := control.Retire(ctx, nil); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		t.Fatal(err)
	}
	options := mobiletor.DesktopLinuxSocketOptions{Interfaces: []mobiletor.DesktopLinuxSocketInterface{{Name: physical.Name,
		Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}}}
	source, err := mobiletor.NewDesktopLinuxNodeSocketPolicy(ctx, capture, options)
	if source != nil {
		defer func() {
			if err := source.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal("native child failed to create its actual unused guardian", err)
	}
	protection, err := source.ObservePreparedProtection(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	guardian, err := source.ObservePreparedGuardian(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	prepared := NodePreparedRecord{Protection: protection, Guardian: guardian, Policy: selection.Policy}
	if scenario == "foreign-engine" || scenario == "foreign-network" {
		changed := prepared
		if scenario == "foreign-engine" {
			changed.Guardian.Engine.StartTicks++
			changed.Guardian.Guardian.StartTicks++
		} else {
			changed.Protection.Capture.NetworkID = strings.Repeat("7", 32)
		}
		digest, _ := selection.ControlSHA256()
		body, err := CanonicalNodeControlMessage(NodeControlMessage{Schema: 1, Kind: NodeControlKind, Sequence: 3,
			SelectionSHA256: digest, Action: "prepared", Prepared: &changed})
		if err != nil {
			t.Fatal("malformed native substitution fixture", err)
		}
		if err := bootstrap.Send(ctx, body); err != nil {
			t.Fatal(err)
		}
		if _, err := bootstrap.Receive(ctx); err == nil {
			t.Fatal("foreign native engine or network received admission")
		}
		return
	}
	if scenario == "before-admission" {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if err := control.AdmitSource(cancelled, prepared); err == nil {
			t.Fatal("cancelled preparation requested native admission")
		}
	} else if scenario != "foreign-sequence" {
		err = control.AdmitSource(ctx, prepared)
		if scenario == "refuse-admission" {
			if !errors.Is(err, ErrNodeControlRefused) {
				t.Fatal("actual admission refusal was not retained", err)
			}
		} else if err != nil || control.Current(ctx) != nil {
			t.Fatal("actual native source was not admitted by its exact parent", err)
		}
	}
	if scenario == "cancelled-current-child" {
		checkNodeControlEnteredCancellation(t, ctx, control)
	}
	if scenario == "delayed-original-retirement" {
		// A bounded original cleanup phase can exceed a single channel
		// exchange. Keep the admitted native source live until that phase
		// finishes; only its subsequent actual Close/ObserveJoinedSource
		// may produce the authenticated retirement record.
		timer := time.NewTimer(6 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	if err := source.Close(ctx); err != nil {
		t.Fatal(err)
	}
	joined, err := source.ObserveJoinedSource(ctx, capture)
	if err != nil {
		t.Fatal(err)
	}
	if scenario == "foreign-sequence" {
		digest, _ := selection.ControlSHA256()
		retired := NodeRetirementRecord{Source: &joined}
		body, err := CanonicalNodeControlMessage(NodeControlMessage{Schema: 1, Kind: NodeControlKind, Sequence: 5,
			SelectionSHA256: digest, Action: "retired", Retired: &retired})
		if err != nil {
			t.Fatal(err)
		}
		if err := bootstrap.Send(ctx, body); err != nil {
			t.Fatal(err)
		}
		if _, err := bootstrap.Receive(ctx); err == nil {
			t.Fatal("skipped preparation obtained a terminal acknowledgement")
		}
		return
	}
	foreign := joined.Clone()
	foreign.Capture.NetworkID = strings.Repeat("8", 32)
	if err := control.Retire(ctx, &foreign); err == nil {
		t.Fatal("foreign source join entered the original terminal phase")
	}
	err = control.Retire(ctx, &joined)
	if scenario == "current-original-closed" {
		if err == nil {
			t.Fatal("child completed retirement through its actually closed original bootstrap")
		}
		return
	}
	if scenario == "terminal-payload" {
		if err == nil {
			t.Fatal("child accepted a packet in place of original-channel EOF")
		}
		return
	}
	if scenario == "wrong-retirement-ack" {
		if err == nil {
			t.Fatal("child accepted a different final source-join receipt")
		}
		return
	}
	if err != nil || !control.closedAck || !control.peerEOF || control.Current(ctx) == nil {
		t.Fatal("native child did not retain final acknowledgement through strict original-channel EOF", err)
	}
}

func TestDesktopLinuxGuardianKernelNodeControl(t *testing.T) {
	for _, scenario := range []string{"admitted", "refuse-creation", "refuse-admission", "before-baseline", "before-admission",
		"foreign-selection", "foreign-sequence", "foreign-engine", "foreign-network", "terminal-payload", "wrong-retirement-ack",
		"cancelled-current-parent", "cancelled-current-child", "current-original-closed", "delayed-original-retirement"} {
		t.Run(scenario, func(t *testing.T) {
			owner, selection := startNodeControlChild(t, scenario)
			ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
			defer cancel()
			if _, err := NewNodeChildControl(ctx, owner.bootstrap, selection); err == nil {
				t.Fatal("actual parent process claimed its child's control role")
			}
			control, err := NewNodeParentControl(ctx, owner.bootstrap, selection)
			if err != nil {
				t.Fatal(err)
			}
			createCalls, admitCalls := 0, 0
			err = control.ServePreparation(ctx, func(ctx context.Context, capture mobiletor.DesktopSocketCapture) (mobiletor.DesktopLinuxNodeCreationRecord, error) {
				createCalls++
				if scenario == "refuse-creation" {
					return mobiletor.DesktopLinuxNodeCreationRecord{}, context.Canceled
				}
				var err error
				owner.baseline, err = mobiletor.NewDesktopLinuxNodeBaseline(ctx, capture, selection.HomeLAN)
				if err != nil {
					return mobiletor.DesktopLinuxNodeCreationRecord{}, err
				}
				return owner.baseline.Created(ctx)
			}, func(ctx context.Context, record NodePreparedRecord) error {
				admitCalls++
				if owner.baseline == nil {
					return errors.New("native admission preceded original creation")
				}
				if err := owner.baseline.BindPrepared(ctx, record.Protection); err != nil {
					return err
				}
				if scenario == "refuse-admission" {
					return context.Canceled
				}
				return nil
			})
			if scenario == "cancelled-current-parent" {
				if err != nil {
					t.Fatal("actual native admission failed before entered cancellation", err, owner.output.String())
				}
				checkNodeControlEnteredCancellation(t, ctx, control)
			}
			foreign := strings.HasPrefix(scenario, "foreign-")
			if scenario == "current-original-closed" {
				if err != nil {
					t.Fatal("actual native admission failed before original channel closure", err, owner.output.String())
				}
				if err := owner.bootstrap.Close(ctx); err != nil {
					t.Fatal("original native bootstrap did not close", err)
				}
				failure := control.Current(ctx)
				if failure == nil || control.uncertain == nil || failure != control.uncertain || control.Current(ctx) != failure {
					t.Fatal("read-only Current revived an actually closed original native owner", failure)
				}
			} else if foreign {
				if err == nil || admitCalls != 0 || scenario == "foreign-selection" && createCalls != 0 {
					t.Fatal("foreign native selection, engine, network or order reached a native mutation callback", err, createCalls, admitCalls)
				}
				if control.Current(ctx) == nil {
					t.Fatal("failed native exchange reported current admission")
				}
			} else {
				switch scenario {
				case "refuse-creation", "refuse-admission":
					if !errors.Is(err, ErrNodeControlRefused) {
						t.Fatal("native refusal did not preserve its cleanup phase", err)
					}
				case "before-baseline", "before-admission":
					if !errors.Is(err, ErrNodeControlRetired) || admitCalls != 0 || scenario == "before-baseline" && createCalls != 0 {
						t.Fatal("cancelled native preparation lost its original early retirement", err)
					}
				default:
					if err != nil {
						t.Fatal("actual native admission failed", err, owner.output.String())
					}
				}
				retired, err := control.ReceiveRetirement(ctx)
				if err != nil || retired.Validate() != nil {
					t.Fatal("actual native source join was not delivered", err, owner.output.String())
				}
				if control.Current(ctx) == nil {
					t.Fatal("retired source continued to advertise admission")
				}
				if err := control.AcknowledgeRetirement(ctx, nil); err == nil {
					t.Fatal("native retirement acknowledged without original closed readback")
				}
				if err := control.AcknowledgeRetirement(ctx, func(context.Context, NodeRetirementRecord) error {
					return errors.New("closed readback temporarily failed")
				}); err == nil {
					t.Fatal("failed closed readback became an acknowledged retirement")
				}
				if scenario == "wrong-retirement-ack" {
					digest, _ := selection.ControlSHA256()
					body, err := CanonicalNodeControlMessage(NodeControlMessage{Schema: 1, Kind: NodeControlKind, Sequence: 6,
						SelectionSHA256: digest, Action: "closed", ReceiptSHA256: strings.Repeat("a", 64)})
					if err != nil {
						t.Fatal(err)
					}
					_ = owner.bootstrap.Send(ctx, body)
				} else {
					err = control.AcknowledgeRetirement(ctx, func(ctx context.Context, observed NodeRetirementRecord) error {
						if observed.Source != nil && retired.Source == nil {
							return errors.New("native closure substituted a source")
						}
						if owner.baseline == nil {
							return mobiletor.ReadDesktopLinuxProtectionAbsence(ctx)
						}
						return owner.baseline.ObserveClosed(ctx)
					})
					if err != nil {
						t.Fatal("actual closed readback failed before terminal acknowledgement", err, owner.output.String())
					}
					if scenario == "terminal-payload" {
						_ = owner.bootstrap.Send(ctx, []byte("unexpected-terminal-packet"))
					}
				}
			}
			if err := owner.bootstrap.Close(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal("actual original engine did not join after terminal channel closure", ctx.Err(), owner.output.String())
			case <-owner.joined:
			}
			if owner.joinErr != nil || owner.command.ProcessState == nil {
				t.Fatal("actual native child did not finish its required protocol boundary", owner.joinErr, owner.output.String())
			}
			if owner.baseline != nil {
				if err := owner.baseline.ObserveClosed(ctx); err != nil {
					t.Fatal("joined engine left its original baseline open", err)
				}
				if err := owner.baseline.Release(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
				t.Fatal("original fixture cleanup left a native protection owner", err)
			}
		})
	}
}
