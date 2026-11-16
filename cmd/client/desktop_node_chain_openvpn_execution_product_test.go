package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

func TestDesktopOpenVPNExecutionPublic3Server(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 3, "server", "server")
}
func TestDesktopOpenVPNExecutionPublic3CompareLocal(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 3, "auto", "local")
}
func TestDesktopOpenVPNExecutionPublic3CompareServer(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 3, "auto", "server")
}
func TestDesktopOpenVPNExecutionPublic4Server(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 4, "server", "server")
}
func TestDesktopOpenVPNExecutionPublic4CompareLocal(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 4, "auto", "local")
}
func TestDesktopOpenVPNExecutionPublic4CompareServer(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 4, "auto", "server")
}
func TestDesktopOpenVPNExecutionPublic8Server(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 8, "server", "server")
}
func TestDesktopOpenVPNExecutionPublic8CompareLocal(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 8, "auto", "local")
}
func TestDesktopOpenVPNExecutionPublic8CompareServer(t *testing.T) {
	testDesktopOpenVPNExecutionPublicFixture(t, 8, "auto", "server")
}

func testDesktopOpenVPNExecutionPublicFixture(t *testing.T, count int, requested, winner string) {
	if (runtime.GOOS != "linux" && runtime.GOOS != "windows") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("public controller model requires its Windows or Linux host")
	}
	a, selected, captured, _, server := desktopOpenVPNExecutionLaunchFixture(t, count, "windows", requested)
	t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(a); desktopComparisons.Delete(a) })
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selected)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner, openvpnServer: server}
	a.connectionContext, a.connectionCancel = nil, nil
	a.state.Mode, a.state.Phase = "off", "off"
	release, err := a.holdCapturedMTU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	opened := 0
	driver := &desktopOrderedExecutionRuntime{
		capture: func(ctx context.Context, owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
			if owner != a || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodeChainSelectedReferences(f.selection.Nodes)) || !reflect.DeepEqual(modes, []string{"shadowsocks"}) {
				return selection, errors.New("OpenVPN public capture changed original full path")
			}
			return f.selection, ctx.Err()
		},
		prepare: func(ctx context.Context, owner *app, selection multihopSelection, choice string) (*desktopNodeChainExecutionSession, error) {
			opened++
			if owner != a || selection.Native != f.selection.Native || choice != requested {
				return nil, errors.New("OpenVPN public preparation replaced its captured selection")
			}
			request := &desktopNodeChainExecutionRequest{capture: f.capture, native: selection.Native, requested: choice}
			launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, f.capture, selection, nil, request)
			if err != nil {
				return nil, err
			}
			f.launch = launch
			return &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: selection}, ctx.Err()
		},
	}
	request := orderedPublicRequest(t, a, nodeChainSelectedReferences(f.selection.Nodes))
	request.Execution = requested
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)), nativeMultihopConnectRuntime{execution: driver})
	if response.Code != http.StatusOK {
		t.Fatalf("OpenVPN public Connect %d: %s", response.Code, response.Body.String())
	}
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		t.Fatal("OpenVPN Connect lost original execution owner", err)
	}
	if opened != 1 || f.starts != 1 || !a.state.Connected || owner.session.graph.Execution != winner || a.connectionContext != nil || owner.session.execution.openvpnPhysical == nil {
		t.Fatal("OpenVPN public transaction replayed Compare or lost typed selected ownership")
	}
	if err := owner.session.Current(context.Background()); err != nil {
		t.Fatal("OpenVPN request completion revoked original connection", err)
	}
	// Join only the modeled in-process watcher. The following actual status
	// observation still validates its original process, source and ready owner.
	watchDone := desktopOwnedNodeMonitorDone(f.launch)
	join, cancelJoin := context.WithTimeout(context.Background(), 15*time.Second)
	err = stopDesktopOwnedNodeMonitor(join, f.launch)
	if err == nil && watchDone != nil {
		err = joinDesktopOwnedNodeMonitorStop(join, a, watchDone)
	}
	cancelJoin()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDesktopMultihopRoutes(mux, a)
	status := httptest.NewRecorder()
	mux.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	var body map[string]any
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &body) != nil || body["connected"] != true || body["execution"] != winner || !reflect.DeepEqual(body["ordered_openvpn_executions"], []any{"local", "server", "auto"}) {
		t.Fatalf("OpenVPN status lost actual selected proof: %d %s", status.Code, status.Body.String())
	}
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || body["requested_execution"] != requested || body["execution"] != winner || len(body["nodes"].([]any)) != count {
		t.Fatal("OpenVPN public response changed requested execution or ordered members")
	}
	var actual, original mobilemultihop.NodeChainSource
	source := captured.chain.policy.OriginalChain()
	input, err := source.LaunchInput()
	if err != nil || json.Unmarshal([]byte(input), &original) != nil || json.Unmarshal([]byte(owner.session.execution.preparation.LocalSource()), &actual) != nil || actual.Schema != 5 || len(actual.Nodes) != count || actual.IdentitySources[count-2] != "" || !reflect.DeepEqual(actual.Nodes, original.Nodes) || !reflect.DeepEqual(actual.IdentitySources, original.IdentitySources) {
		t.Fatal("OpenVPN Connect changed imported credentials or original paired final", err)
	}
	proof := owner.session.native.execution
	if proof.openvpnPhysical != owner.session.execution.openvpnPhysical || proof.connectPhysical != nil || proof.physical != nil {
		t.Fatal("OpenVPN public graph borrowed another physical proof")
	}
	for _, fault := range []string{"physical", "projection", "CONNECT", "winner", "endpoint"} {
		changed := *proof
		switch fault {
		case "physical":
			copy := *proof.openvpnPhysical
			changed.openvpnPhysical = &copy
		case "projection":
			copy := *proof.projection
			changed.projection = &copy
		case "CONNECT":
			changed.connectPhysical = &mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy{}
		case "winner":
			changed.winner.EntryID = "foreign"
		case "endpoint":
			changed.target = mobilemultihop.Targets[0]
		}
		if err := changed.currentContext(context.Background(), f.launch, *owner.session.graph); err == nil {
			t.Fatal("OpenVPN public proof accepted a substituted retained owner", fault)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := proof.currentContext(cancelled, f.launch, *owner.session.graph); !errors.Is(err, context.Canceled) {
		t.Fatal("OpenVPN proof observation discarded caller cancellation", err)
	}
	if err := proof.currentContext(context.Background(), f.launch, *owner.session.graph); err != nil {
		t.Fatal("cancelled OpenVPN observation revoked the original retained connection", err)
	}
	stop, err := a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := stop.Retire(context.Background(), owner.session.launch.command, false); err != nil {
		t.Fatal(err)
	}
}

func prepareDesktopOpenVPNExecutionModel(t *testing.T, count int, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	a, selection, _, _, server := desktopOpenVPNExecutionLaunchFixture(t, count, "windows", requested)
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner, openvpnServer: server}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: selection.Native, requested: requested}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	return f, &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: selection}
}
func TestDesktopOpenVPNExecutionRestoreKeepsWinnerEndpointAndMTU(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, s := prepareDesktopOpenVPNExecutionModel(t, 3, "auto", winner)
			if err := s.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			restore, err := s.CaptureRestore(f.operation)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("unjoined OpenVPN owner restored")
			}
			held := errors.New("original OpenVPN child still joining")
			f.processes[0].closeErr = held
			if err := restore.retireContext(context.Background()); !errors.Is(err, held) || s.launch.ownedNode.retired {
				t.Fatal("failed OpenVPN join discarded original owner", err)
			}
			f.processes[0].closeErr = nil
			if err := restore.retireContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			<-f.pulseDone
			next, execution, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			last, present, err := execution.preparation.OpenVPNDesktopLast()
			if err != nil || !present || last.Execution() != winner || last.Target() != mobilemultihop.Targets[1] || f.starts != 1 {
				t.Fatal("OpenVPN restoration reran Compare or changed endpoint", err)
			}
			_, meta, _, err := next.chain.policy.PhysicalReadValidated()
			if err != nil || execution.preparation.LocalSource() != s.execution.preparation.LocalSource() || next.chain.selection.Native != s.selection.Native || meta.RestoredMTU != f.live.MTU || execution.openvpnPhysical == nil || execution.connectPhysical != nil || execution.physical != nil {
				t.Fatal("OpenVPN restore changed original source, native owner or readback MTU", err)
			}
		})
	}
}

func TestDesktopOpenVPNExecutionReadyRejectsChangedReceipt(t *testing.T) {
	f, session := prepareDesktopOpenVPNExecutionModel(t, 4, "auto", "server")
	if err := session.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	watchDone := desktopOwnedNodeMonitorDone(f.launch)
	join, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := stopDesktopOwnedNodeMonitor(join, f.launch)
	if err == nil && watchDone != nil {
		err = joinDesktopOwnedNodeMonitorStop(join, f.a, watchDone)
	}
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	// Serialize only the explicit child heartbeat model. Every invocation still
	// parses the actual private receipt with the original typed parent parser.
	f.heartbeat.Lock()
	defer f.heartbeat.Unlock()
	execution := session.execution
	raw, err := json.Marshal(f.executionModel.ready)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"generic-kind", "CONNECT-kind", "identity", "transfer", "preparation", "reader", "MTU", "selected-proof"} {
		t.Run(fault, func(t *testing.T) {
			var changed mobilemultihop.DesktopNodeChainExecutionReadyRecord
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("original ready fixture")
			}
			changed.ObservedAt = time.Now().UnixMilli()
			switch fault {
			case "generic-kind":
				changed.Kind = "routervpn-node-chain-execution-ready-v1"
			case "CONNECT-kind":
				changed.Kind = "routervpn-node-chain-connect-execution-ready-v1"
			case "identity":
				changed.Identity.NetworkID += "-foreign"
			case "transfer":
				changed.TransferSHA256 = strings.Repeat("e", 64)
			case "preparation":
				changed.PreparationSourceSHA256 = strings.Repeat("e", 64)
			case "reader":
				changed.Reader++
			case "MTU":
				changed.MTU--
			case "selected-proof":
				changed.Progress.PublicProven = false
			}
			desktopOwnedNodeTestWrite(t, f.launch, "node-chain-execution-ready.json", changed)
			if _, err := execution.readReadyContext(f.operation, f.launch, execution.ready.TransferSHA256, execution.started, false, f.live); err == nil {
				t.Fatal("OpenVPN parent accepted a substituted selected receipt")
			}
		})
	}
	f.executionModel.ready.ObservedAt = time.Now().UnixMilli()
	desktopOwnedNodeTestWrite(t, f.launch, "node-chain-execution-ready.json", f.executionModel.ready)
	if _, err := execution.readReadyContext(f.operation, f.launch, execution.ready.TransferSHA256, execution.started, false, f.live); err != nil {
		t.Fatal("original OpenVPN receipt could not retry after refused substitutions", err)
	}
}
