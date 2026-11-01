//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

const linuxNodeTransactionMarker = "ROUTERVPN_LINUX_TRANSACTION_ENGINE"

func init() {
	// Descendants execute the same real pinned image, with the shipping helper
	// arguments and sanitized environment. Dispatch them before the fixture.
	if len(os.Args) == 3 && os.Args[1] == "routervpn-owned-socket-helper" {
		if err := mobiletor.RunDesktopLinuxSocketHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(119)
		}
		os.Exit(0)
	}
	if os.Getenv(linuxNodeTransactionMarker) != "1" {
		return
	}
	if err := linuxNodeTransactionEngine(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(118)
	}
	os.Exit(0)
}

func linuxTransactionMarker(directory, name string) error {
	return os.WriteFile(filepath.Join(directory, name), []byte("original fixture rendezvous\n"), 0600)
}

func linuxTransactionWait(ctx context.Context, directory, name string) error {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if info, err := os.Lstat(filepath.Join(directory, name)); err == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
				return errors.New("transaction rendezvous lost its private real file")
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// The fixture models graph readiness only. It actually recompiles the private
// sealed policy, authenticates inherited originals, creates the real guardian,
// and uses the shipping control and transaction code. It claims no TUN, DNS,
// Router proof or off-LAN traffic acceptance.
func linuxNodeTransactionEngine() error {
	if os.Geteuid() != 0 || len(os.Args) != 18 || os.Args[1] != "routervpn-node" {
		return errors.New("transaction engine lost its exact native invocation")
	}
	values := map[string]string{}
	for index := 2; index < len(os.Args); index += 2 {
		values[os.Args[index]] = os.Args[index+1]
	}
	if values["--linux-parent-channel"] != "3" || values["--linux-parent-directory"] != "4" {
		return errors.New("transaction engine lost its original inherited descriptors")
	}
	image := os.NewFile(5, "original-transaction-image")
	defer image.Close()
	if err := linuxprocess.SetCloseOnExec(image); err != nil {
		return err
	}
	graph, stopGraph := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stopGraph()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	directory := values["--runtime-dir"]
	raw, err := os.ReadFile(filepath.Join(directory, "node-source.json"))
	if err != nil {
		return err
	}
	original, err := mobilemultihop.ParseNodeLaunchInput(string(raw))
	if err != nil {
		return err
	}
	policy, err := mobilemultihop.NewDesktopNodePolicy(original, values["--session"], "linux")
	if err != nil {
		return err
	}
	meta := policy.Metadata()
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	captureDigest, err := selection.CaptureSHA256()
	if err != nil || meta.SourceSHA256 != values["--physical-source-sha256"] || meta.ConfigSHA256 != values["--config-sha256"] ||
		captureDigest != values["--linux-parent-capture"] {
		return errors.New("transaction engine substituted its independently compiled private policy")
	}
	channel, err := linuxprocess.CaptureChannel(os.NewFile(3, "original-transaction-channel"))
	if err != nil {
		if channel != nil {
			_ = channel.Close(ctx)
		}
		return err
	}
	bootstrap, err := linuxprocess.BindInheritedParent(ctx, channel, os.NewFile(4, "original-transaction-parent"), captureDigest)
	if bootstrap != nil {
		defer bootstrap.Close(context.Background())
	}
	if err != nil {
		return err
	}
	control, err := linuxprotection.NewNodeChildControl(ctx, bootstrap, selection)
	if err != nil {
		return err
	}
	network := physicalNetworkIdentity()
	if len(network) != 64 {
		return errors.New("transaction engine has no actual physical network identity")
	}
	capture := mobiletor.DesktopSocketCapture{SessionID: selection.SessionID, SourceSHA256: selection.SourceSHA256, NetworkID: network[:32]}
	_, err = control.CreateBaseline(ctx, capture)
	if err != nil {
		if !errors.Is(err, linuxprotection.ErrNodeControlRefused) {
			return err
		}
		return control.Retire(ctx, nil)
	}
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		return err
	}
	options := mobiletor.DesktopLinuxSocketOptions{Interfaces: []mobiletor.DesktopLinuxSocketInterface{{Name: physical.Name,
		Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}}}
	source, err := mobiletor.NewDesktopLinuxNodeSocketPolicy(ctx, capture, options)
	if source != nil {
		defer source.Close(context.Background())
	}
	if err != nil {
		return err
	}
	protection, err := source.ObservePreparedProtection(ctx, capture)
	if err != nil {
		return err
	}
	guardian, err := source.ObservePreparedGuardian(ctx, capture)
	if err != nil {
		return err
	}
	if scenario := os.Getenv("ROUTERVPN_LINUX_TRANSACTION_CASE"); scenario == "changed-profile" || scenario == "shutdown-before-admission" {
		if err := linuxTransactionMarker(directory, "prepared"); err != nil {
			return err
		}
		if err := linuxTransactionWait(ctx, directory, "continue"); err != nil {
			return err
		}
	}
	err = control.AdmitSource(ctx, linuxprotection.NodePreparedRecord{Protection: protection, Guardian: guardian, Policy: selection.Policy})
	if err == nil {
		select {
		case <-graph.Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	} else if !errors.Is(err, linuxprotection.ErrNodeControlRefused) {
		return err
	}
	if err := source.Close(ctx); err != nil {
		return err
	}
	joined, err := source.ObserveJoinedSource(ctx, capture)
	if err != nil {
		return err
	}
	if err := control.Retire(ctx, &joined); err != nil {
		return err
	}
	if err := bootstrap.Close(ctx); err != nil {
		return err
	}
	if scenario := os.Getenv("ROUTERVPN_LINUX_TRANSACTION_CASE"); scenario == "engine-join" || scenario == "shutdown-retry" {
		if err := linuxTransactionMarker(directory, "eof"); err != nil {
			return err
		}
		return linuxTransactionWait(ctx, directory, "finish")
	}
	return nil
}

func linuxTransactionProfile(policy string) (common.RouterProfile, *mobilemultihop.NodeProfile, error) {
	raw := []byte("[Interface]\nPrivateKey = " + testWGKey('p') + "\nAddress = 10.77.0.2/32\nDNS = 192.168.50.133\n\n[Peer]\nPublicKey = " + testWGKey('q') + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.18.0.2:51820\nPersistentKeepalive = 25\n")
	node, err := nodeProofIDFromWGConfig(raw)
	if err != nil {
		return common.RouterProfile{}, nil, err
	}
	profile := common.RouterProfile{ID: "transaction-home", NodeKind: "router-vpn", Name: "Original transaction",
		NodeProofID: node, Endpoint: "198.18.0.2", RouterAPI: "http://10.77.0.1:8787", APIToken: "private-transaction-token",
		AdGuardIPv4: "192.168.50.133", HomeLANAccess: false, IPv6Mode: "on", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: policy}
	files := map[string][]byte{"wg.conf": raw, "wg-socks.conf": []byte(strings.ReplaceAll(string(raw), "0.0.0.0/0, ::/0", "10.77.0.0/24"))}
	original, _, err := compileDesktopNode(context.Background(), profile, "wg", files, nil, nil)
	return profile, original, err
}

func linuxTransactionStart(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, journal *desktopLinuxNodeJournal,
	predecessor *desktopLinuxNodeTransaction, session, policyName, scenario string) (*desktopLinuxNodeTransaction, context.CancelFunc, string, error) {
	profile, original, err := linuxTransactionProfile(policyName)
	if err != nil {
		return nil, nil, "", err
	}
	policy, err := mobilemultihop.NewDesktopNodePolicy(original, session, "linux")
	if err != nil {
		return nil, nil, "", err
	}
	input, err := original.LaunchInput()
	if err != nil {
		return nil, nil, "", err
	}
	directory := filepath.Join(linuxOwnedControllerRoot, "runtime", "transaction-"+session)
	if err := os.Mkdir(directory, 0700); err != nil {
		return nil, nil, "", err
	}
	if err := os.WriteFile(filepath.Join(directory, "node-source.json"), []byte(input), 0600); err != nil {
		return nil, nil, "", err
	}
	meta := policy.Metadata()
	capture, err := linuxprotection.NodeCommandCaptureSHA256(session, meta.SourceSHA256, meta.ConfigSHA256)
	if err != nil {
		return nil, nil, "", err
	}
	arguments := []string{"routervpn-node", "--runtime-dir", directory, "--session", session, "--config-sha256", meta.ConfigSHA256,
		"--physical-source-sha256", meta.SourceSHA256, "--physical-transfer-sha256", strings.Repeat("4", 64)}
	process, err := startDesktopLinuxNodeProcessWithVerifier(ctx, parent, arguments, []string{linuxNodeTransactionMarker + "=1",
		"ROUTERVPN_LINUX_TRANSACTION_CASE=" + scenario, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}, directory, capture,
		func(context.Context, string) (string, error) {
			return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
		})
	if err != nil {
		if process != nil {
			_ = process.Close(ctx)
		}
		return nil, nil, "", err
	}
	operation, cancelOperation := context.WithCancel(ctx)
	a.mu.Lock()
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	a.cmd, a.connectionContext, a.connectionCancel = process.command, operation, cancelOperation
	a.state.RouterID, a.state.RuntimeMode = profile.ID, meta.Mode
	a.state.DAITA, a.state.Jumbo, a.state.Socks = profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled
	a.mu.Unlock()
	transaction, err := newDesktopLinuxNodeTransaction(operation, parent, journal, process, policy, predecessor)
	if err != nil {
		cancelOperation()
		if transaction != nil {
			_ = transaction.Close(ctx)
		} else {
			_ = process.Close(ctx)
		}
	}
	return transaction, cancelOperation, directory, err
}

// Hold the original callback after the actual application records cancellation
// intent. The child still sends its authenticated baseline request while the
// original operation context is live; that exact request must be refused before
// any durable intent or native baseline can be created.
func linuxTransactionPrepareAfterCancelIntent(ctx context.Context, transaction *desktopLinuxNodeTransaction) (result error) {
	a := transaction.parent.app
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.mu.Lock()
	original := a.connectionCancel
	if a.connectionContext != transaction.operation || original == nil || transaction.operation.Err() != nil {
		a.mu.Unlock()
		return errors.New("cancel-intent fixture lost its original live application operation")
	}
	a.connectionCancel = func() {
		close(entered)
		<-release
		original()
	}
	a.mu.Unlock()
	go func() {
		defer close(joined)
		a.cancelConnectionOperation()
	}()
	defer func() {
		close(release)
		join, cancelJoin := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelJoin()
		select {
		case <-joined:
			if transaction.operation.Err() != context.Canceled {
				result = errors.Join(result, errors.New("released cancellation did not join its original callback"))
			}
		case <-join.Done():
			result = errors.Join(result, errors.New("original cancellation callback did not join"))
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		return ctx.Err()
	}
	a.mu.Lock()
	captured := a.connectionContext == transaction.operation && a.connectionCancelIntent == transaction.operation
	a.mu.Unlock()
	if !captured || transaction.operation.Err() != nil || ctx.Err() != nil {
		return errors.New("cancellation intent was not captured before the original live callback")
	}
	before := transaction.head
	err := transaction.ServePreparation(ctx)
	if !errors.Is(err, linuxprotection.ErrNodeControlRefused) || !transaction.served || transaction.baseline != nil ||
		transaction.created != nil || transaction.pending != nil || transaction.journal.pending != nil ||
		transaction.nativeCommitted || transaction.admitted || transaction.operation.Err() != nil {
		return errors.Join(err, errors.New("cancellation intent reached native preparation before its original callback ran"))
	}
	selected, snapshotErr := transaction.journal.Snapshot(ctx)
	if snapshotErr != nil || !sameDesktopLinuxJournalSelection(selected, before.Record) || transaction.head.SHA256 != before.SHA256 ||
		mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.Join(snapshotErr, errors.New("refused cancellation intent changed original durable or native protection"))
	}
	return nil
}

func linuxTransactionPrepare(ctx context.Context, transaction *desktopLinuxNodeTransaction, scenario, directory string, cancel context.CancelFunc) error {
	if scenario == "cancel-intent-before-prepare" {
		return linuxTransactionPrepareAfterCancelIntent(ctx, transaction)
	}
	if scenario == "cancelled-before-prepare" {
		cancel()
	}
	if scenario == "changed-profile" {
		result := make(chan error, 1)
		go func() { result <- transaction.ServePreparation(ctx) }()
		if err := linuxTransactionWait(ctx, directory, "prepared"); err != nil {
			return err
		}
		transaction.parent.app.mu.Lock()
		transaction.parent.app.profiles.Profiles[0].APIToken = "replacement-private-token"
		transaction.parent.app.mu.Unlock()
		if err := linuxTransactionMarker(directory, "continue"); err != nil {
			return err
		}
		select {
		case err := <-result:
			if !errors.Is(err, linuxprotection.ErrNodeControlRefused) || transaction.nativeCommitted || transaction.admitted {
				return errors.Join(err, errors.New("changed saved profile reached original native admission"))
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if scenario == "partial-prepare-write" {
		var original syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil || original.Cur < 512 {
			return errors.Join(err, errors.New("transaction fixture has no bounded file-size limit"))
		}
		limited := original
		limited.Cur = 512
		signal.Ignore(syscall.SIGXFSZ)
		defer signal.Reset(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
			return err
		}
		err := transaction.ServePreparation(ctx)
		if restore := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); restore != nil {
			return restore
		}
		if !errors.Is(err, linuxprotection.ErrNodeControlRefused) || transaction.baseline != nil || transaction.pending == nil || transaction.journal.pending == nil {
			return errors.Join(err, errors.New("native creation escaped its incomplete durable prepare intent"))
		}
		partial, readErr := transaction.journal.readFile(transaction.journal.slots[transaction.journal.pending.slot], linuxprotection.JournalRecordLimit)
		if readErr != nil || len(partial) != 512 {
			return errors.Join(readErr, errors.New("transaction did not retain the actual torn inactive journal slot"))
		}
		return nil
	}
	err := transaction.ServePreparation(ctx)
	if scenario == "cancelled-before-prepare" {
		if !errors.Is(err, linuxprotection.ErrNodeControlRefused) || transaction.baseline != nil || transaction.pending != nil {
			return errors.Join(err, errors.New("cancelled request obtained a native baseline"))
		}
		return nil
	}
	if err != nil || !transaction.admitted || !transaction.nativeCommitted || transaction.head.Record.Committed.Engine == nil {
		return errors.Join(err, errors.New("original transaction did not reach its actual durable admission"))
	}
	return nil
}

func linuxTransactionRetire(ctx context.Context, transaction *desktopLinuxNodeTransaction, scenario, directory string) error {
	if scenario == "engine-join" {
		short, cancel := context.WithCancel(ctx)
		result := make(chan error, 1)
		go func() { result <- transaction.Retire(short) }()
		if err := linuxTransactionWait(ctx, directory, "eof"); err != nil {
			cancel()
			return err
		}
		cancel()
		err := <-result
		if err == nil || transaction.engineJoined || transaction.head.Record.Committed.Engine == nil || transaction.retired {
			return errors.Join(err, errors.New("durable settlement preceded original engine join"))
		}
		if err := transaction.baseline.ObserveClosed(ctx); err != nil {
			return err
		}
		if err := linuxTransactionMarker(directory, "finish"); err != nil {
			return err
		}
	}
	if err := transaction.Retire(ctx); err != nil {
		return err
	}
	if !transaction.engineJoined || !transaction.retired || transaction.process.command.ProcessState == nil || transaction.pending != nil ||
		transaction.head.Record.Phase != "settled" || transaction.head.Record.Committed.Engine != nil {
		return errors.New("transaction retirement omitted its actual process join or complete durable settlement")
	}
	if transaction.nativeCommitted {
		if transaction.head.Record.Committed.Target == nil || transaction.baseline.ObserveClosed(ctx) != nil {
			return errors.New("temporary retirement released original closed protection")
		}
	} else if transaction.head.Record.Committed.Target != nil {
		return errors.New("failed initial transaction retained a false committed target")
	}
	return nil
}

func linuxNodeTransactionFixture(controller *ownedDesktopController, scenario string) error {
	a := &app{localController: controller, cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
		ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
		StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "transaction-parent-rendezvous")
	defer gate.Close()
	var one [1]byte
	if _, err := io.ReadFull(gate, one[:]); err != nil || one[0] != 1 {
		return errors.Join(err, errors.New("transaction fixture lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	journal, err := createDesktopLinuxNodeJournal(ctx, parent)
	if journal != nil {
		defer journal.Close(context.Background())
	}
	if err != nil {
		return err
	}
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	policyName := "on-connect"
	if scenario == "always-successor" || scenario == "shutdown-always" || scenario == "shutdown-successor-first" {
		policyName = "always"
	}
	transaction, stopOperation, directory, err := linuxTransactionStart(ctx, a, parent, journal, nil, strings.Repeat("1", 32), policyName, scenario)
	if err != nil {
		return err
	}
	defer stopOperation()
	defer transaction.Close(context.Background())
	if strings.HasPrefix(scenario, "shutdown-") {
		return linuxTransactionShutdownFixture(ctx, a, parent, journal, transaction, scenario, directory, stopOperation)
	}
	if err := linuxTransactionPrepare(ctx, transaction, scenario, directory, stopOperation); err != nil {
		return err
	}
	if scenario == "request-ended" {
		// Successful Connect ends its request context while the owned engine
		// survives. Retirement must use the captured owner, not this request.
		stopOperation()
		a.mu.Lock()
		a.connectionContext, a.connectionCancel = nil, nil
		a.mu.Unlock()
	}
	if err := linuxTransactionRetire(ctx, transaction, scenario, directory); err != nil {
		return err
	}
	if scenario == "always-successor" {
		if err := transaction.ReleaseOnDisconnect(ctx); err != nil || transaction.baseline.ObserveClosed(ctx) != nil {
			return errors.Join(err, errors.New("ordinary disconnect released Always protection"))
		}
		if mobiletor.ReadDesktopLinuxNodeAbsence(ctx, transaction.selection.SessionID) == nil ||
			mobiletor.ReadDesktopLinuxNodeAbsence(ctx, strings.Repeat("3", 32)) != nil ||
			mobiletor.ReadDesktopLinuxNodeAbsence(ctx, "../another-table") == nil {
			return errors.New("session absence confused the retained original with another strictly captured candidate")
		}
		successor, cancelSuccessor, successorDirectory, err := linuxTransactionStart(ctx, a, parent, journal, transaction,
			strings.Repeat("2", 32), "on-connect", "successor")
		if err != nil {
			return err
		}
		defer cancelSuccessor()
		defer successor.Close(context.Background())
		if err := linuxTransactionPrepare(ctx, successor, "successor", successorDirectory, cancelSuccessor); err != nil {
			return err
		}
		if err := linuxTransactionRetire(ctx, successor, "successor", successorDirectory); err != nil {
			return err
		}
		if !transaction.superseded || transaction.successor != nil || transaction.head.SHA256 != successor.head.SHA256 {
			return errors.New("actual native succession lost the reserved original predecessor")
		}
		if err := transaction.Close(ctx); err != nil {
			return err
		}
		transaction = successor
	}
	if err := transaction.ReleaseOnDisconnect(ctx); err != nil {
		return err
	}
	selected, err := journal.Snapshot(ctx)
	if err != nil || selected.Record.Phase != "settled" || selected.Record.Committed.Target != nil || selected.Record.Committed.Engine != nil ||
		mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.Join(err, errors.New("explicit On-connect release lacks durable and actual native absence"))
	}
	if err := transaction.Close(ctx); err != nil {
		return err
	}
	if err := journal.Close(ctx); err != nil {
		return err
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeTransaction(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node transaction requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range []string{"on-connect", "request-ended", "always-successor", "cancelled-before-prepare", "cancel-intent-before-prepare", "changed-profile", "partial-prepare-write", "engine-join"} {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "transaction/"+scenario)
			child.retire(t, "")
		})
	}
}
