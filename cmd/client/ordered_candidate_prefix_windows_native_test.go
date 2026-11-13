//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
	"router-vpn/internal/windowsprotection"
)

// The copied test image retains the shipping immutable-package, pipe/token,
// pinned TLS and Job entry. Only this explicit native-test compilation adds a
// read-only inspection endpoint; all candidate actions are shipping handlers.
func init() {
	if len(os.Args) < 2 {
		return
	}
	if handled, err := bundledNativeUtility(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Args[1] != windowsbootstrap.ControllerArgument {
		return
	}
	if err := windowsPrefixController(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func windowsPrefixController() error {
	controller, err := prepareNativeOwnedController(os.Args[1:])
	if err != nil {
		return err
	}
	if controller == nil {
		return errors.New("prefix test did not capture original controller")
	}
	defer controller.close()
	if err := validateNativeOwnedStartup(controller); err != nil {
		return err
	}
	capture, ok := controller.nativeOwner.(*windowsOwnedController)
	if !ok || capture.protectedSelf == nil || capture.protectedSelf.Verify() != nil {
		return errors.New("prefix test lost protected controller image")
	}
	raw, err := readPrivateRuntimeSnapshot(filepath.Join(capture.dataRoot, "client.json"), maxPrivateStoreBytes)
	if err != nil {
		return err
	}
	var config common.ClientConfig
	if json.Unmarshal(raw, &config) != nil {
		return errors.New("prefix test lost original configuration")
	}
	if err := controller.validateConfiguration(&config); err != nil {
		return err
	}
	raw, err = os.ReadFile(config.ModesFile)
	if err != nil {
		return err
	}
	var modes []common.Mode
	if json.Unmarshal(raw, &modes) != nil {
		return errors.New("prefix test lost captured catalog")
	}
	modes, err = controller.captureModes(modes)
	if err != nil {
		return err
	}
	a := &app{cfg: config, localController: controller, modes: modes, state: state{Mode: "off", Phase: "off"}}
	if err := a.loadProfiles(); err != nil {
		return err
	}
	a.state.RouterID = a.profiles.SelectedID
	if err := a.initializeDesktopNodeRecovery(); err != nil {
		return err
	}
	original := cloneRouterProfileStore(a.profiles)
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, a)
	mux.HandleFunc("/api/native-prefix-capture", func(w http.ResponseWriter, r *http.Request) {
		result, err := windowsPrefixInspect(r.Context(), a, original)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	listener, err := net.Listen("tcp", linuxOwnedControllerAddress)
	if err != nil {
		return err
	}
	secured, err := controller.captureListener(listener)
	if err != nil {
		listener.Close()
		return err
	}
	return serveClientHTTP(newControllerShutdown(a, controller.ownerToken), secured, mux, nil)
}

type windowsPrefixInspection struct {
	Connected      bool                                                       `json:"connected"`
	ProfileSame    bool                                                       `json:"profile_same"`
	NativeJoined   bool                                                       `json:"native_joined"`
	JournalSettled bool                                                       `json:"journal_settled"`
	PolicyProfile  string                                                     `json:"policy_profile"`
	Proof          *mobilemultihop.DesktopNodeCandidatePreparationReadyRecord `json:"proof,omitempty"`
}

func windowsPrefixInspect(ctx context.Context, a *app, original common.RouterProfileStore) (windowsPrefixInspection, error) {
	var result windowsPrefixInspection
	a.mu.Lock()
	result.Connected, result.ProfileSame = a.state.Connected, reflect.DeepEqual(a.profiles, original)
	a.mu.Unlock()
	if result.Connected || !result.ProfileSame {
		return result, errors.New("prefix test changed ordinary Home or original saved control")
	}
	control := viaEntryControlFor(a)
	control.mu.Lock()
	owner := control.owner
	control.mu.Unlock()
	if owner == nil {
		return result, nil
	}
	select {
	case <-owner.done:
	default:
		return result, nil
	}
	p := owner.preparation
	if p == nil || p.owner != owner || p.launch == nil || p.launch.candidatePrefix == nil || p.launch.chain != nil || p.launch.ownedNode == nil {
		return result, errors.New("prefix DOWN lost distinct original native owner")
	}
	launch := p.launch
	launch.candidatePrefix.mu.Lock()
	result.Proof = launch.candidatePrefix.ready
	launch.candidatePrefix.mu.Unlock()
	launch.workspaceMu.Lock()
	retired := launch.ownedNode.retired
	ordinary := launch.ownedNode.ready
	launch.workspaceMu.Unlock()
	if result.Proof == nil || !result.Proof.Prepared || result.Proof.ApplicationOpen || result.Proof.DNSOpen || ordinary != nil || !retired {
		return result, errors.New("prefix DOWN omitted actual closed native proof")
	}
	process, ok := desktopOwnedNodeProcess(launch).(*desktopNodeWindowsJournalProcess)
	if !ok || process == nil || process.capture.ProfileID != original.SelectedID || launch.candidatePrefix.policy.Metadata().PolicyProfileID != original.SelectedID || launch.profileID == original.SelectedID {
		return result, errors.New("prefix journal lost full saved control attribution")
	}
	if result.Proof.Validate(launch.candidatePrefix.policy, launch.ownedNode.attempt.digest) != nil || result.Proof.Identity.SessionID != launch.mtuSession || result.Proof.Generation != 1 {
		return result, errors.New("prefix review borrowed another native proof, transfer or session")
	}
	record, err := process.JournalOutcome()
	if err != nil {
		return result, err
	}
	result.PolicyProfile = process.capture.ProfileID
	result.NativeJoined = true
	// The child outcome is its last authenticated acknowledgment. The parent
	// subsequently settles joined Engine=nil and removes on-connect protection
	// in a separate durable transaction. Reopen that same original journal for
	// independent readback; never treat the earlier child outcome as DOWN.
	if record.Validate() != nil || !launch.ownedNode.slot.provedEmpty() {
		return result, errors.New("prefix DOWN omitted exact child outcome or joined empty slot")
	}
	capture := process.controller
	if capture == nil || len(capture.directories) != 1 {
		return result, errors.New("prefix journal readback lost original controller data handle")
	}
	journal, err := windowsprotection.OpenProtectionJournal(ctx, capture.parent, capture.directories[0])
	if err != nil {
		if journal != nil {
			err = errors.Join(err, journal.Close())
		}
		return result, err
	}
	head, err := journal.Snapshot(ctx)
	err = errors.Join(err, journal.Close())
	if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
		return result, errors.Join(err, errors.New("prefix DOWN retained actual durable engine or on-connect protection"))
	}
	result.JournalSettled = true
	absent, err := mobiletor.ProbeDesktopWindowsProtectionAbsent(ctx)
	if err != nil || !absent {
		return result, errors.Join(err, errors.New("prefix DOWN retained actual scoped WFP protection"))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return result, err
	}
	for _, iface := range interfaces {
		if uint32(iface.Index) == result.Proof.InterfaceIndex || iface.Name == result.Proof.InterfaceName {
			return result, errors.New("prefix DOWN retained or replaced its actual original TUN")
		}
	}
	return result, nil
}

type windowsPrefixPeerReply struct {
	Schema   int    `json:"schema"`
	Address  string `json:"address"`
	PublicCA string `json:"public_ca"`
	Prefixes []struct {
		Mode             string `json:"mode"`
		ParametersSHA256 string `json:"parameters_sha256,omitempty"`
		RawUDP           int64  `json:"raw_udp"`
		TCP              int64  `json:"tcp"`
		UDP              int64  `json:"udp"`
		ProofQueries     uint64 `json:"proof_queries"`
		AuthRefusals     uint64 `json:"auth_refusals"`
	} `json:"prefixes"`
	Final struct {
		Schema             int    `json:"schema"`
		Address            string `json:"address"`
		PublicCA           string `json:"public_ca"`
		EntryPublicIP      string `json:"entry_public_ip"`
		FinalPublicIP      string `json:"final_public_ip"`
		EntryRawUDP        int64  `json:"entry_raw_udp"`
		EntryTCP           int64  `json:"entry_tcp"`
		EntryUDP           int64  `json:"entry_udp"`
		FinalRawTCP        int64  `json:"final_raw_tcp"`
		FinalRawUDP        int64  `json:"final_raw_udp"`
		FinalTCP           int64  `json:"final_tcp"`
		FinalUDP           int64  `json:"final_udp"`
		EntryPublicQueries uint64 `json:"entry_public_queries"`
		FinalPublicQueries uint64 `json:"final_public_queries"`
		RouterQueries      uint64 `json:"router_queries"`
		DNSQueries         uint64 `json:"dns_queries"`
		DirectQueries      uint64 `json:"direct_queries"`
	} `json:"final"`
}

type windowsPrefixOutput struct {
	sync.Mutex
	bytes.Buffer
}

func (b *windowsPrefixOutput) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *windowsPrefixOutput) String() string { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

func windowsPrefixRead(t *testing.T, reader *bufio.Reader, value any) {
	t.Helper()
	type outcome struct {
		raw []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() { raw, err := reader.ReadSlice('\n'); done <- outcome{append([]byte(nil), raw...), err} }()
	select {
	case result := <-done:
		if result.err != nil || len(result.raw) > 32768 || json.Unmarshal(result.raw, value) != nil {
			t.Fatal("original Windows peer lost bounded reply", result.err, string(result.raw))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("original Windows peer reply deadline")
	}
}

func windowsPrefixPeerStart(t *testing.T, modes []string) (*windowsPrefixPeer, func() windowsPrefixPeerReply) {
	t.Helper()
	peer := windowsPrefixPeerKeys(t, 3)
	windowsPrefixSetModes(t, peer, modes)
	image := os.Getenv("ROUTERVPN_WINDOWS_PREFIX_PEER")
	if !filepath.IsAbs(image) {
		t.Fatal("prefix peer requires original compiled image")
	}
	imageCapture, err := windowscontroller.PinImage(image)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := imageCapture.Close(); err != nil {
			t.Error(err)
		}
	})
	command := exec.Command(imageCapture.Path(), "-test.run=^TestRouterVPNDesktopWindowsPrefixReferenceProcess$", "-test.count=1", "-test.timeout=100s")
	command.Env = append(os.Environ(), "ROUTERVPN_WINDOWS_PREFIX_REFERENCE=1", "ROUTERVPN_NODE_CHAIN_REFERENCE_CHILD=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := new(windowsPrefixOutput)
	command.Stderr = diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatal(err)
	}
	if err := process.VerifyImage(imageCapture); err != nil {
		command.Process.Kill()
		command.Wait()
		process.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		input.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("encrypted prefix peer did not join", err, diagnostic.String())
			}
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("encrypted prefix peer forced termination", diagnostic.String())
		}
		output.Close()
		if err := process.Close(); err != nil {
			t.Error(err)
		}
	})
	reader := bufio.NewReaderSize(output, 32769)
	var physical struct {
		Schema  int    `json:"schema"`
		Address string `json:"physical_address"`
	}
	windowsPrefixRead(t, reader, &physical)
	if physical.Schema != 1 || physical.Address == "" {
		t.Fatal("prefix peer omitted actual current physical interface")
	}
	request := map[string]any{"schema": 1, "address": physical.Address, "client_address": physical.Address, "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": windowsPrefixProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token"}
	if err := json.NewEncoder(input).Encode(request); err != nil {
		t.Fatal(err)
	}
	windowsPrefixRead(t, reader, &peer.reply)
	if peer.reply.Schema != 1 || peer.reply.Address != net.JoinHostPort(physical.Address, "51820") || len(peer.reply.Prefixes) != 2 || peer.reply.PublicCA == "" {
		t.Fatal("prefix peer changed original physical/key inventory")
	}
	return peer, func() windowsPrefixPeerReply {
		if _, err := io.WriteString(input, "stats\n"); err != nil {
			t.Fatal(err)
		}
		var value windowsPrefixPeerReply
		windowsPrefixRead(t, reader, &value)
		if value.Address != peer.reply.Address || value.PublicCA != peer.reply.PublicCA {
			t.Fatal("prefix peer replaced original identity")
		}
		return value
	}
}

func windowsPrefixWrite(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsInstalledPrefixCandidates(t *testing.T) {
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("installed prefix acceptance requires actual elevated Windows", err)
	}
	root := os.Getenv("ROUTERVPN_WINDOWS_PREFIX_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("installed prefix gate has no original package root")
	}
	if err := ensurePrivateRuntimeDirectory(root); err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"RouterVPN.exe", "router-vpn-client.exe"} {
		input, err := os.Open(image)
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		err = errors.Join(copyErr, input.Close(), output.Close())
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"wg-save", "wg-cancel", "awg-fast-save", "awg-fast-cancel", "awg-strong-save", "awg-strong-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(filepath.Join(root, "RouterVPN.exe"), "-test.v", "-test.run=^TestWindowsPrefixLauncher$", "-test.count=1", "-test.timeout=110s", "--", root, scenario)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("installed prefix %s failed: %v\n%s", scenario, err, output)
			}
			witness := "verified installed Windows selected prefix: " + scenario
			if !strings.Contains(string(output), witness) {
				t.Fatal("installed prefix omitted its exact original lifecycle receipt", string(output))
			}
			t.Log(witness)
		})
	}
}

func TestWindowsPrefixLauncher(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 2 {
		t.Fatal("prefix launcher lost original case")
	}
	root, scenario := arguments[0], arguments[1]
	modes := []string{"wg", "wg"}
	switch scenario {
	case "wg-save", "wg-cancel":
	case "awg-fast-save", "awg-fast-cancel":
		modes = []string{"awg2-fast", "wg"}
	case "awg-strong-save", "awg-strong-cancel":
		modes = []string{"awg2-strong", "awg2-fast"}
	default:
		t.Fatal("unknown finite prefix scenario")
	}
	peer, observe := windowsPrefixPeerStart(t, modes)
	profiles, assets := windowsPrefixPrefixCandidateSources(t, peer)
	if !strings.Contains(string(assets[profiles.SelectedID]["shadowsocks"]["sing-box.json"]), `"server_port":1`) ||
		!strings.Contains(string(assets["installed-prefix-candidate"]["shadowsocks"]["sing-box.json"]), `"server_port":8388`) {
		t.Fatal("prefix fixture lost deliberately unavailable original final or independent candidate endpoint")
	}
	for _, directory := range []string{"client", "modes", "runtime"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for id, variants := range assets {
		for mode, files := range variants {
			directory := filepath.Join(root, "generated", id, mode)
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for name, raw := range files {
				if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	windowsPrefixWrite(t, filepath.Join(root, "routers.json"), profiles)
	windowsPrefixWrite(t, filepath.Join(root, "client.json"), map[string]any{"listen": linuxOwnedControllerAddress, "modes_file": filepath.Join(root, "modes.json"), "scripts_dir": filepath.Join(root, "modes"), "state_file": filepath.Join(root, "state.json"), "profiles_file": filepath.Join(root, "routers.json")})
	catalog := []byte(`[{"id":"wg","name":"WireGuard","command":["./run-platform.sh","run-mode.sh","wg"],"check_command":["./check-mode.sh","wg"],"stop_command":["./stop-mode-platform.sh"]}]`)
	for name, raw := range map[string][]byte{"modes.json": catalog, "logical-modes.json": []byte("[]"), "client/native-wireguard-windows.ps1": []byte("# immutable unused adapter\n"), "client/native-windows-mode.ps1": []byte("# immutable unused adapter\n")} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(filepath.Join(root, "routers.json"))
	if err != nil {
		t.Fatal(err)
	}
	storeApp := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}}
	storeBefore, err := loadConnectionProfileStore(storeApp)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, stateErr := os.ReadFile(filepath.Join(root, "state.json"))
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		t.Fatal(stateErr)
	}
	client, closeController := windowsPrefixLaunch(t, root)
	defer closeController()
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	call := func(method, path string, value any) controllertransport.Response {
		t.Helper()
		var raw []byte
		var err error
		if value != nil {
			raw, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		response, err := client.Request(ctx, method, path, raw, 1<<20)
		if err != nil {
			t.Fatal("captured prefix TLS request", err)
		}
		if response.Status >= 200 && response.Status < 300 && strings.HasPrefix(path, "/api/multihop/saved-candidates") {
			var envelope map[string]any
			if json.Unmarshal(response.Body, &envelope) != nil || envelope["scope"] != orderedCandidateSavedPrefixScope || envelope["application_open"] != false || envelope["dns_open"] != false || envelope["proof_scope"] != "selected-prefix" {
				t.Fatal("prefix TLS response acquired ordinary application/DNS purpose", string(response.Body))
			}
		}
		return response
	}
	const base = "/api/multihop/saved-candidates"
	response := call(http.MethodGet, base+"/catalog?scope="+orderedCandidateSavedPrefixScope+"&prefix_position=1", nil)
	var catalogResponse struct {
		Token      string                   `json:"view_token"`
		Samples    int                      `json:"samples"`
		Candidates []orderedCandidateChoice `json:"candidates"`
	}
	if response.Status != 200 || json.Unmarshal(response.Body, &catalogResponse) != nil || len(catalogResponse.Token) != 64 || catalogResponse.Samples != 50 {
		t.Fatal("prefix catalog", response.Status, string(response.Body))
	}
	var choice *orderedCandidateChoice
	for i := range catalogResponse.Candidates {
		if catalogResponse.Candidates[i].ID == "installed-prefix-candidate" {
			choice = &catalogResponse.Candidates[i]
		}
	}
	if choice == nil || choice.SaveReason != "" {
		t.Fatal("unopened final suppressed independent prefix candidate", string(response.Body))
	}
	id, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": id, "view_token": catalogResponse.Token, "prefix_position": 1, "candidate_ids": []string{choice.ID}, "samples": 50}
	response = call(http.MethodPost, base, request)
	if response.Status != 202 {
		t.Fatal("prefix native Test did not return202", response.Status, string(response.Body))
	}
	var status struct {
		RequestID string                       `json:"request_id"`
		ViewToken string                       `json:"view_token"`
		Running   bool                         `json:"running"`
		Accepted  bool                         `json:"accepted"`
		Reviewing bool                         `json:"reviewing"`
		Down      bool                         `json:"native_down"`
		Drained   bool                         `json:"drained"`
		Cleanup   bool                         `json:"cleanup_pending"`
		Failure   string                       `json:"failure"`
		Rows      []hopmeasure.CandidateStatus `json:"results"`
	}
	for {
		response = call(http.MethodGet, base+"?request_id="+id, nil)
		if response.Status != 200 || json.Unmarshal(response.Body, &status) != nil || status.RequestID != id || status.ViewToken != catalogResponse.Token {
			t.Fatal("prefix native status", response.Status, string(response.Body))
		}
		inspection := call(http.MethodGet, "/api/native-prefix-capture", nil)
		if inspection.Status != 200 {
			t.Fatal("prefix original owner inspection", inspection.Status, string(inspection.Body))
		}
		if status.Running && (status.Accepted || status.Reviewing || len(status.Rows) != 0) {
			t.Fatal("prefix choices preceded original native DOWN")
		}
		if !status.Running {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !status.Accepted || !status.Reviewing || !status.Down || status.Drained || status.Cleanup || status.Failure != "" || len(status.Rows) != 1 {
		t.Fatal("prefix did not reach joined native DOWN review", string(response.Body))
	}
	row := status.Rows[0]
	if row.CandidateID != choice.ID || row.PrefixPosition != 1 || !row.Complete || !row.Drained || len(row.Results) != 1 || row.Results[0].Benchmark == nil || row.Results[0].Benchmark.Attempts != 50 || row.Results[0].Benchmark.Distribution == nil || row.Results[0].Benchmark.Distribution.Samples != 50 {
		t.Fatal("prefix result lost actual fifty samples", row)
	}
	response = call(http.MethodGet, "/api/native-prefix-capture", nil)
	var proof windowsPrefixInspection
	if response.Status != 200 || json.Unmarshal(response.Body, &proof) != nil || !proof.NativeJoined || !proof.JournalSettled || !proof.ProfileSame || proof.Connected || proof.PolicyProfile != profiles.SelectedID || proof.Proof == nil || proof.Proof.InterfaceIndex == 0 || proof.Proof.InterfaceName == "" || proof.Proof.MTU < 576 || len(proof.Proof.Prefixes) != 2 {
		t.Fatal("prefix lost actual native TUN/journal/closed proof", string(response.Body))
	}
	counters := observe()
	if counters.Final.FinalRawTCP != 50 || counters.Final.FinalTCP != 0 || counters.Final.FinalUDP != 0 || counters.Final.RouterQueries != 0 || counters.Final.DNSQueries != 0 || counters.Final.FinalPublicQueries != 0 || counters.Final.DirectQueries != 0 {
		t.Fatal("prefix fifty handshakes used the saved final, ordinary DNS or direct path", counters)
	}
	for i, prefix := range counters.Prefixes {
		if prefix.Mode != modes[i] || prefix.RawUDP == 0 || prefix.TCP == 0 || prefix.ProofQueries == 0 || prefix.AuthRefusals != 0 || !proof.Proof.Prefixes[i].Proven {
			t.Fatal("prefix skipped independently encrypted private proof", i, prefix)
		}
	}
	wrong := map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": id, "view_token": strings.Repeat("0", 64)}
	if response = call(http.MethodPost, base+"/cancel", wrong); response.Status != 409 {
		t.Fatal("prefix foreign result view cancelled original owner")
	}
	if strings.HasSuffix(scenario, "-save") {
		value := map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": id, "view_token": catalogResponse.Token, "candidate_id": choice.ID, "name": "Explicit native prefix draft", "proposed_path": choice.Proposal}
		response = call(http.MethodPost, base+"/save-profile", value)
		var saved struct {
			Saved   bool   `json:"saved"`
			ID      string `json:"saved_profile_id"`
			Down    bool   `json:"native_down"`
			Drained bool   `json:"drained"`
		}
		if response.Status != 200 || json.Unmarshal(response.Body, &saved) != nil || !saved.Saved || !validProfileID(saved.ID) || !saved.Down || !saved.Drained {
			t.Fatal("explicit prefix Save lost native DOWN", response.Status, string(response.Body))
		}
		storeAfter, err := loadConnectionProfileStore(storeApp)
		if err != nil || len(storeAfter.Profiles) != len(storeBefore.Profiles)+1 || !reflect.DeepEqual(storeAfter.Profiles[:len(storeBefore.Profiles)], storeBefore.Profiles) {
			t.Fatal("native prefix Save replaced original named profiles", err)
		}
		record := storeAfter.Profiles[len(storeAfter.Profiles)-1]
		if record.ID != saved.ID || record.NodeID != choice.ID || record.Prefs == nil || !record.Prefs.MultihopEnabled || record.Prefs.MultihopExecution != "local" || !reflect.DeepEqual(record.Prefs.MultihopNodes, choice.Proposal) {
			t.Fatal("native prefix Save omitted complete next-connection path")
		}
		committed, err := os.ReadFile(connectionProfileStorePath(storeApp))
		if err != nil {
			t.Fatal(err)
		}
		response = call(http.MethodPost, base+"/save-profile", value)
		var repeated struct {
			ID string `json:"saved_profile_id"`
		}
		if response.Status != 200 || json.Unmarshal(response.Body, &repeated) != nil || repeated.ID != saved.ID {
			t.Fatal("native prefix Save retry lost original committed result")
		}
		after, err := os.ReadFile(connectionProfileStorePath(storeApp))
		if err != nil || !bytes.Equal(after, committed) {
			t.Fatal("native prefix Save retry duplicated or rewrote profile", err)
		}
	} else {
		response = call(http.MethodPost, base+"/cancel", map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": id, "view_token": catalogResponse.Token})
		if response.Status != 200 {
			t.Fatal("explicit prefix Cancel failed", response.Status, string(response.Body))
		}
		storeAfter, err := loadConnectionProfileStore(storeApp)
		if err != nil || !reflect.DeepEqual(storeBefore, storeAfter) {
			t.Fatal("native prefix Cancel changed named profiles", err)
		}
	}
	after, err := os.ReadFile(filepath.Join(root, "routers.json"))
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("prefix Test/decision rewrote original saved control", err)
	}
	stateAfter, afterStateErr := os.ReadFile(filepath.Join(root, "state.json"))
	if !bytes.Equal(stateBefore, stateAfter) || errors.Is(stateErr, os.ErrNotExist) != errors.Is(afterStateErr, os.ErrNotExist) || afterStateErr != nil && !errors.Is(afterStateErr, os.ErrNotExist) {
		t.Fatal("native prefix Test/decision persisted temporary StartupLast or usage", afterStateErr)
	}
	closeController()
	t.Log("verified installed Windows selected prefix: " + scenario)
}

func windowsPrefixLaunch(t *testing.T, root string) (*controllertransport.Client, func()) {
	t.Helper()
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	image, err := windowscontroller.PinImage(filepath.Join(root, "router-vpn-client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments, err := windowsbootstrap.Arguments(pipe.Name(), uint32(os.Getpid()), executable)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(image.Path(), arguments...)
	diagnostic := new(windowsPrefixOutput)
	command.Stdout, command.Stderr = diagnostic, diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	var client *controllertransport.Client
	closeOwner := func() {
		once.Do(func() {
			pipe.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Error("actual prefix controller failed", err, diagnostic.String())
				}
			case <-time.After(15 * time.Second):
				command.Process.Kill()
				<-done
				t.Error("actual prefix controller failed to join", diagnostic.String())
			}
			if client != nil {
				client.Close()
			}
			process.Close()
			image.Close()
		})
	}
	t.Cleanup(closeOwner)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	frame, err := pipe.ReadFrame(ctx)
	if err != nil {
		t.Fatal("prefix actual child handshake", err, diagnostic.String())
	}
	peer, err := pipe.VerifyPeer(process, image)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := process.Identity()
	if err != nil || peer.Identity.Primary || !primary.Primary || !primary.Elevated || !primary.Administrator || peer.Identity.SID != primary.SID || peer.Identity.AuthenticationID != primary.AuthenticationID {
		t.Fatal("prefix child lost original native token", err)
	}
	peer.Process.Close()
	hello, err := windowsbootstrap.DecodeHello(frame, process.PID())
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := windowsbootstrap.NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	private, err := windowsbootstrap.EncodeCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.WriteFrame(ctx, private); err != nil {
		t.Fatal(err)
	}
	client, err = controllertransport.NewClient(process, hello.TLSPin, credentials.AccessToken, credentials.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if err = client.VerifyIdentity(ctx); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("prefix pinned TLS identity", ctx.Err(), diagnostic.String())
		}
		if err := process.Alive(); err != nil {
			t.Fatal(err, diagnostic.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return client, closeOwner
}
