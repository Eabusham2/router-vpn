package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// A comparison-only typed host boundary. The policy is the real sealed ordered
// policy, while native reader/proof success is explicit controlled input. This
// model cannot start a native host or prove PF, utun or a private device path.
type mtuSuccessionComparisonKernel struct {
	*mtuCapabilityKernel
	owner                          *mtuLiveOwner
	initial, previous, next        mtuKernelState
	expectCleanup, refuse          bool
	calls, cleanupCalls            int
	cleanup                        mtuKernelState
	cleanupPresent                 bool
}

func (kernel *mtuSuccessionComparisonKernel) validateMTUInterfaceSuccession(initial, previous, next mtuKernelState, cleanup bool) error {
	kernel.calls++
	if cleanup {
		kernel.cleanupCalls++
	}
	if kernel.owner.mu.TryLock() {
		kernel.owner.mu.Unlock()
		return errors.New("outer interface proof escaped the original operation lock")
	}
	if initial != kernel.initial || previous != kernel.previous || next != kernel.next || cleanup != kernel.expectCleanup {
		return errors.New("outer interface proof changed its exact captured receipts")
	}
	if kernel.refuse {
		return errors.New("original native reader or kernel retirement is unproved")
	}
	return nil
}

func (kernel *mtuSuccessionComparisonKernel) Restore() (mtuKernelState, error) {
	return mtuKernelState{}, errors.New("comparison model cannot perform a native rollback")
}

func (kernel *mtuSuccessionComparisonKernel) CleanupRestored() (mtuKernelState, bool) {
	return kernel.cleanup, kernel.cleanupPresent
}

func mtuSuccessionComparisonModel(policy *mobilemultihop.DesktopNodeChainPolicy) (*mtuLiveOwner, *mtuSuccessionComparisonKernel) {
	command := &exec.Cmd{Path: "unstarted-ordered-interface-comparison"}
	platform := &desktopNodeChainPlatformRuntime{}
	chain := &desktopNodeChainLaunch{policy: policy, platform: platform}
	launch := &desktopNodeLaunch{command: command, chain: chain}
	native := &nativeMultihopRuntime{launch: launch}
	captured := &mtuNodeChainSnapshot{Launch: launch, Chain: chain, Platform: platform, Policy: policy}
	path := &mtuMultihopSnapshot{Chain: captured, Native: native, Command: command,
		Graph: activeMultihopGraph{Execution: "local", ChainNodes: 3}}
	initial := mtuKernelState{Interface: "utun991", Family: 4, Index: 991, MTU: 1400, Identity: "original-native-reader-1"}
	kernel := &mtuSuccessionComparisonKernel{mtuCapabilityKernel: &mtuCapabilityKernel{state: initial},
		initial: initial, previous: initial, next: initial}
	owner := &mtuLiveOwner{a: &app{}, snapshot: mtuRetestSnapshot{Multihop: path}, command: command,
		kernel: kernel, initial: initial, current: initial, token: strings.Repeat("a", 32), done: make(chan struct{})}
	kernel.owner = owner
	return owner, kernel
}

func TestMTUInterfaceSuccessionReadbackRequiresTypedOriginalProof(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, kind := range []string{"current", "changed-reader", "cleanup", "refused-proof", "refused-cleanup"} {
		t.Run(kind, func(t *testing.T) {
			owner, kernel := mtuSuccessionComparisonModel(sealed.chain.policy)
			next := owner.current
			cleanup := kind == "cleanup" || kind == "refused-cleanup"
			if kind != "current" {
				next.Interface, next.Index, next.Identity = "utun992", 992, "original-native-reader-2"
				if !cleanup {
					next.MTU = 1320
				}
			}
			kernel.next, kernel.expectCleanup = next, cleanup
			kernel.refuse = strings.HasPrefix(kind, "refused")
			before := owner.current
			owner.mu.Lock()
			err := owner.validateInterfaceReadbackLocked(before, next, cleanup)
			owner.mu.Unlock()
			if (err == nil) == kernel.refuse || kernel.calls != 1 || owner.current != before {
				t.Fatal("interface proof was skipped, accepted refusal, or itself changed ownership", kind, err, kernel.calls)
			}
			if cleanup && kernel.cleanupCalls != 1 {
				t.Fatal("cleanup borrowed the live measurement proof")
			}
		})
	}
}

func TestMTUInterfaceSuccessionRejectsSubstitutedOwnerAndFamily(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	_, fixed := desktopNodeChainLaunchFixture(t, 3, "linux")
	for _, fault := range []string{
		"path", "chain", "native", "launch", "platform", "policy", "target", "launch-chain",
		"chain-platform", "chain-policy", "native-launch", "command", "launch-command",
		"server-execution", "one-node", "nine-nodes", "original-name", "current-name", "next-name",
		"family", "index", "identity",
	} {
		t.Run(fault, func(t *testing.T) {
			owner, kernel := mtuSuccessionComparisonModel(sealed.chain.policy)
			path, captured := owner.snapshot.Multihop, owner.snapshot.Multihop.Chain
			previous, next := owner.current, owner.current
			next.Interface, next.Index, next.Identity = "utun992", 992, "original-native-reader-2"
			switch fault {
			case "path":
				owner.snapshot.Multihop = nil
			case "chain":
				path.Chain = nil
			case "native":
				path.Native = nil
			case "launch":
				captured.Launch = nil
			case "platform":
				captured.Platform = nil
			case "policy":
				captured.Policy = nil
			case "target":
				captured.Policy, captured.Chain.policy = fixed.chain.policy, fixed.chain.policy
			case "launch-chain":
				captured.Launch.chain = &desktopNodeChainLaunch{}
			case "chain-platform":
				captured.Chain.platform = nil
			case "chain-policy":
				captured.Chain.policy = fixed.chain.policy
			case "native-launch":
				path.Native.launch = &desktopNodeLaunch{}
			case "command":
				path.Command = &exec.Cmd{}
			case "launch-command":
				captured.Launch.command = &exec.Cmd{}
			case "server-execution":
				path.Graph.Execution = "server"
			case "one-node":
				path.Graph.ChainNodes = 1
			case "nine-nodes":
				path.Graph.ChainNodes = 9
			case "original-name":
				owner.initial.Interface = "router-vpn"
			case "current-name":
				previous.Interface = "router-vpn"
			case "next-name":
				next.Interface = "utun９９２"
			case "family":
				next.Family = 6
			case "index":
				next.Index = 0
			case "identity":
				next.Identity = ""
			}
			kernel.previous, kernel.next = previous, next
			owner.mu.Lock()
			err := owner.validateInterfaceReadbackLocked(previous, next, false)
			owner.mu.Unlock()
			if err == nil || kernel.calls != 0 {
				t.Fatal("substituted scope reached the retained native proof", fault, err, kernel.calls)
			}
		})
	}
}

func TestMTUInterfaceSuccessionMeasurementKeepsOriginalAndCurrentIdentity(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	for _, fault := range []string{"valid", "historical-current", "foreign-original", "missing-original",
		"wrong-policy", "missing-policy", "wrong-token", "family", "original-mtu", "live-original",
		"closed", "native-proof"} {
		t.Run(fault, func(t *testing.T) {
			owner, kernel := mtuSuccessionComparisonModel(sealed.chain.policy)
			owner.current = mtuKernelState{Interface: "utun993", Family: 4, Index: 993, MTU: 1400, Identity: "original-native-reader-3"}
			kernel.previous, kernel.next = owner.current, owner.current
			live := mtuLiveSnapshot{Owner: owner, Interface: owner.initial.Interface, Family: 4, OriginalMTU: 1400}
			result := mtuMeasurementResult{OwnerToken: owner.token, Interface: owner.current.Interface,
				OriginalInterface: owner.initial.Interface, InterfacePolicy: mtuDarwinOrderedInterfacePolicy,
				Family: 4, OriginalMTU: 1400}
			switch fault {
			case "historical-current":
				result.Interface = "utun991"
			case "foreign-original":
				result.OriginalInterface = "utun999"
			case "missing-original":
				result.OriginalInterface = ""
			case "wrong-policy":
				result.InterfacePolicy = "any-reader"
			case "missing-policy":
				result.InterfacePolicy = ""
			case "wrong-token":
				result.OwnerToken = strings.Repeat("b", 32)
			case "family":
				result.Family = 6
			case "original-mtu":
				result.OriginalMTU = 1320
			case "live-original":
				live.Interface = "utun992"
			case "closed":
				owner.closed = true
			case "native-proof":
				kernel.refuse = true
			}
			err := validateMTUMeasurementAgainstLiveSnapshot(result, live)
			if (err == nil) != (fault == "valid") {
				t.Fatal("measurement lost the original anchor or exact current reader", fault, err)
			}
			if fault == "valid" || fault == "native-proof" {
				if kernel.calls != 1 {
					t.Fatal("measurement skipped its original native proof")
				}
			} else if kernel.calls != 0 {
				t.Fatal("malformed measurement reached native succession proof", fault)
			}
		})
	}
}

func TestMTUInterfaceSuccessionReplyEnvironmentAndJoinedCleanup(t *testing.T) {
	_, sealed := desktopNodeChainLaunchFixture(t, 3, "darwin")
	owner, kernel := mtuSuccessionComparisonModel(sealed.chain.policy)
	owner.current = mtuKernelState{Interface: "utun992", Family: 4, Index: 992, MTU: 1320, Identity: "original-native-reader-2"}
	owner.mu.Lock()
	reply, err := owner.interfaceReplyLocked(owner.current)
	owner.mu.Unlock()
	if err != nil || reply.Interface != "utun992" || reply.OriginalInterface != "utun991" ||
		reply.InterfacePolicy != mtuDarwinOrderedInterfacePolicy || reply.Owner != owner.token {
		t.Fatal("reply replaced its original interface anchor with the successor", reply, err)
	}
	environment := map[string]string{}
	for _, value := range owner.Environment() {
		name, body, _ := strings.Cut(value, "=")
		environment[name] = body
	}
	if environment["HOMEVPN_MTU_ORIGINAL_INTERFACE"] != "utun991" ||
		environment["HOMEVPN_MTU_INTERFACE_POLICY"] != mtuDarwinOrderedInterfacePolicy {
		t.Fatal("optimizer environment lost the original typed scope", environment)
	}
	cleanup := owner.initial
	cleanup.Interface, cleanup.Index, cleanup.Identity = "utun993", 993, "original-native-reader-3"
	kernel.previous, kernel.next, kernel.expectCleanup = owner.current, cleanup, true
	kernel.cleanup, kernel.cleanupPresent, kernel.refuse = cleanup, true, true
	mtuLiveOwners.Store(owner.a, owner)
	t.Cleanup(func() { mtuLiveOwners.Delete(owner.a) })
	before := owner.current
	if err := owner.Close(); err == nil || owner.closed || owner.current != before {
		t.Fatal("failed native cleanup proof discarded the original outer owner", err)
	}
	if retained, ok := mtuLiveOwners.Load(owner.a); !ok || retained != owner {
		t.Fatal("failed native cleanup proof lost its exact retry owner")
	}
	kernel.refuse = false
	if err := owner.Close(); err != nil || !owner.closed || !owner.restored || owner.current != cleanup ||
		kernel.cleanupCalls != 2 {
		t.Fatal("exact joined cleanup successor could not be retained on retry", err, kernel.cleanupCalls)
	}
	if _, ok := mtuLiveOwners.Load(owner.a); ok {
		t.Fatal("confirmed original cleanup retained the outer registry")
	}
}

type mtuFixedRenameKernel struct{ *mtuCapabilityKernel }

func (kernel *mtuFixedRenameKernel) Change(expected mtuKernelState, value int) (mtuKernelState, error) {
	state, err := kernel.mtuCapabilityKernel.Change(expected, value)
	if err != nil {
		return state, err
	}
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	kernel.state.Interface = "utun992"
	return kernel.state, nil
}

func TestMTUInterfaceSuccessionLegacyHTTPKeepsSixFieldsAndRejectsRename(t *testing.T) {
	t.Setenv("HOMEVPN_MTU_ORIGINAL_INTERFACE", "")
	t.Setenv("HOMEVPN_MTU_INTERFACE_POLICY", "")
	owner, kernel := newMTUCapabilityFixture(t)
	code, raw, err := mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"read"}`)
	var reply map[string]any
	if err != nil || code != http.StatusOK || json.Unmarshal(raw, &reply) != nil || len(reply) != 6 {
		t.Fatal("legacy HTTP reply changed its exact six-field contract", code, string(raw), err)
	}
	for _, key := range []string{"owner_token", "interface", "family", "index", "mtu", "identity"} {
		if _, ok := reply[key]; !ok {
			t.Fatal("legacy reply omitted a required field", key)
		}
	}
	env := strings.Join(owner.Environment(), "\n")
	if !strings.Contains(env, "HOMEVPN_MTU_ORIGINAL_INTERFACE=\n") ||
		!strings.HasSuffix(env, "HOMEVPN_MTU_INTERFACE_POLICY=") {
		t.Fatal("legacy environment did not clear inherited succession scope", env)
	}
	before := owner.current
	owner.mu.Lock()
	owner.kernel = &mtuFixedRenameKernel{kernel}
	owner.mu.Unlock()
	code, _, err = mtuCapabilityCall(context.Background(), owner, http.MethodPost, "", "Bearer "+owner.token, `{"action":"set","mtu":1320}`)
	owner.mu.Lock()
	retained := owner.current
	owner.mu.Unlock()
	if err != nil || code != http.StatusConflict || retained != before || owner.Validate() == nil {
		t.Fatal("legacy HTTP mutation accepted a renamed interface without typed proof", code, err)
	}
	// The deliberately inconsistent kernel boundary is restored only after the
	// refusal witness so the existing fixture can join its actual HTTP server.
	owner.mu.Lock()
	owner.kernel = kernel
	owner.mu.Unlock()
	kernel.mu.Lock()
	kernel.state = before
	kernel.mu.Unlock()
}

func TestMTUInterfaceSuccessionUtilityExactHTTPReplyInventory(t *testing.T) {
	token := strings.Repeat("a", 32)
	cases := []string{
		"legacy-read", "legacy-set", "darwin-read", "darwin-set", "legacy-empty-original",
		"legacy-empty-policy", "legacy-empty-both", "legacy-unrequested-scope",
		"darwin-missing-original", "darwin-missing-policy", "darwin-missing-core",
		"darwin-empty-original", "darwin-empty-policy", "darwin-foreign-origin", "darwin-wrong-policy",
		"darwin-fixed-current", "darwin-unicode-current", "darwin-unknown", "darwin-duplicate",
		"darwin-escaped-duplicate", "darwin-null-original", "darwin-legacy-reply",
	}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			scoped := strings.HasPrefix(kind, "darwin-")
			var seen atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/mtu" || r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("utility changed its original HTTP capability")
				}
				body, _ := io.ReadAll(io.LimitReader(r.Body, 512))
				var request map[string]any
				if json.Unmarshal(body, &request) != nil {
					t.Error("utility omitted its actual operation")
				}
				wantAction := "read"
				if strings.HasSuffix(kind, "-set") {
					wantAction = "set"
				}
				if request["action"] != wantAction || wantAction == "set" && request["mtu"] != float64(1320) ||
					wantAction == "read" && len(request) != 1 {
					t.Error("utility changed its exact original read or set request", request)
				}
				reply := map[string]any{"owner_token": token, "interface": "utun992", "family": 4,
					"index": 992, "mtu": 1320, "identity": "original-native-reader-2"}
				if scoped || kind == "legacy-unrequested-scope" {
					reply["original_interface"], reply["interface_policy"] = "utun991", mtuDarwinOrderedInterfacePolicy
				}
				switch kind {
				case "legacy-empty-original", "darwin-empty-original":
					reply["original_interface"] = ""
				case "legacy-empty-policy", "darwin-empty-policy":
					reply["interface_policy"] = ""
				case "legacy-empty-both":
					reply["original_interface"], reply["interface_policy"] = "", ""
				case "darwin-missing-original":
					delete(reply, "original_interface")
				case "darwin-missing-policy":
					delete(reply, "interface_policy")
				case "darwin-missing-core":
					delete(reply, "identity")
				case "darwin-foreign-origin":
					reply["original_interface"] = "utun999"
				case "darwin-wrong-policy":
					reply["interface_policy"] = "any-reader"
				case "darwin-fixed-current":
					reply["interface"] = "router-vpn"
				case "darwin-unicode-current":
					reply["interface"] = "utun９９２"
				case "darwin-unknown":
					reply["unexpected"] = true
				case "darwin-null-original":
					reply["original_interface"] = nil
				case "darwin-legacy-reply":
					delete(reply, "original_interface")
					delete(reply, "interface_policy")
				}
				encoded, _ := json.Marshal(reply)
				if kind == "darwin-duplicate" {
					encoded = append([]byte(`{"original_interface":"utun991",`), encoded[1:]...)
				} else if kind == "darwin-escaped-duplicate" {
					encoded = append([]byte(`{"original_\u0069nterface":"utun991",`), encoded[1:]...)
				}
				_, _ = w.Write(encoded)
			}))
			defer server.Close()
			t.Setenv("HOMEVPN_MTU_OWNER_URL", server.URL+"/mtu")
			t.Setenv("HOMEVPN_MTU_OWNER_TOKEN", token)
			original, policy := "", ""
			if scoped {
				original, policy = "utun991", mtuDarwinOrderedInterfacePolicy
			}
			t.Setenv("HOMEVPN_MTU_ORIGINAL_INTERFACE", original)
			t.Setenv("HOMEVPN_MTU_INTERFACE_POLICY", policy)
			args := []string{"--mtu-owner-read"}
			if strings.HasSuffix(kind, "-set") {
				args = []string{"--mtu-owner-set", "1320"}
			}
			handled, err := mtuOwnerUtility(args)
			valid := kind == "legacy-read" || kind == "legacy-set" || kind == "darwin-read" || kind == "darwin-set"
			if !handled || seen.Load() != 1 || (err == nil) != valid {
				t.Fatal("utility lost exact scope or field inventory", kind, handled, seen.Load(), err)
			}
		})
	}
}

func TestMTUInterfaceSuccessionMalformedScopeNeverCallsHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	t.Setenv("HOMEVPN_MTU_OWNER_URL", server.URL+"/mtu")
	t.Setenv("HOMEVPN_MTU_OWNER_TOKEN", strings.Repeat("a", 32))
	for _, fault := range []struct{ name, original, policy string }{
		{"missing-original", "", mtuDarwinOrderedInterfacePolicy},
		{"missing-policy", "utun991", ""},
		{"wrong-policy", "utun991", "any-reader"},
		{"fixed-original", "router-vpn", mtuDarwinOrderedInterfacePolicy},
		{"empty-number", "utun", mtuDarwinOrderedInterfacePolicy},
		{"upper-case", "UTUN991", mtuDarwinOrderedInterfacePolicy},
		{"unicode", "utun９９１", mtuDarwinOrderedInterfacePolicy},
		{"separator", "utun-991", mtuDarwinOrderedInterfacePolicy},
		{"whitespace", "utun991 ", mtuDarwinOrderedInterfacePolicy},
	} {
		t.Run(fault.name, func(t *testing.T) {
			t.Setenv("HOMEVPN_MTU_ORIGINAL_INTERFACE", fault.original)
			t.Setenv("HOMEVPN_MTU_INTERFACE_POLICY", fault.policy)
			for _, args := range [][]string{{"--mtu-owner-read"}, {"--mtu-owner-set", "1320"}} {
				if handled, err := mtuOwnerUtility(args); !handled || err == nil || calls.Load() != 0 {
					t.Fatal("malformed interface capability reached HTTP", args, handled, err, calls.Load())
				}
			}
		})
	}
}
