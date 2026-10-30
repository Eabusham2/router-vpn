//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type desktopDarwinFixture struct {
	Nonce     string
	Addresses []netip.Addr
	Baselines []string
}

var desktopDarwinTestFixture desktopDarwinFixture

func desktopDarwinTestForeignNamespace() string {
	return "com.apple/zzz.t-" + desktopDarwinTestFixture.Nonce[:12]
}

// Compile the actual shipping Go and Python baselines, including device-wide
// production rules, using pfctl -n only. The native fixture never loads them.
// Traffic tests below load only their fresh loopback-scoped rules.
func TestDesktopDarwinGuardianKernelPFCompiler(t *testing.T) {
	if os.Geteuid() != 0 || len(desktopDarwinTestFixture.Baselines) != 4 {
		t.Fatal("actual captured Darwin dispatcher/parser fixture is required")
	}
	capture := desktopSocketFixtureCapture()
	scope := desktopDarwinPFTestScope
	defer func() { desktopDarwinPFTestScope = scope }()
	parse := func(name, rules string, valid bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		canonical, err := desktopDarwinPFCanonical(ctx, rules)
		if valid && (err != nil || canonical == "") {
			t.Fatal("actual PF parser rejected shipping "+name, err)
		}
		if !valid && (err == nil || !strings.Contains(err.Error(), "syntax error")) {
			t.Fatal("historical misplaced tag negation did not reach the actual PF syntax rejection", name, err)
		}
	}
	for index, lan := range []bool{false, true} {
		options := DesktopDarwinSocketOptions{}
		if lan {
			for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
				options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(raw))
			}
		}
		desktopDarwinPFTestScope = ""
		active := desktopDarwinPFBaseline(capture, options)
		if active != desktopDarwinTestFixture.Baselines[index*2] {
			t.Fatal("shipping Go and Python PF baselines differ for the same capture/LAN policy")
		}
		parse(fmt.Sprintf("active/LAN=%t", lan), active, true)
		parse(fmt.Sprintf("inactive/LAN=%t", lan), desktopDarwinTestFixture.Baselines[index*2+1], true)
		broken := strings.ReplaceAll(active, "! tagged ", "tagged ! ")
		if broken == active {
			t.Fatal("PF compiler negative control lost its tag-negation boundary")
		}
		parse(fmt.Sprintf("misplaced-negation/LAN=%t", lan), broken, false)
		desktopDarwinPFTestScope = scope
		parse(fmt.Sprintf("scoped/LAN=%t", lan), desktopDarwinPFBaseline(capture, options), true)
	}
	policy := &desktopDarwinPF{Capture: capture, UID: 0, permits: make(map[string]desktopDarwinPFPermit)}
	for _, network := range []string{"tcp", "udp"} {
		for _, pair := range [][2]int{{0, 1}, {2, 3}} {
			grant := DesktopSocketGrant{Capture: capture, SocketID: strings.Repeat("4", 32), Network: network,
				Local:   netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[pair[0]], 41111),
				Remote:  netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[pair[1]], 42222),
				Binding: DesktopSocketBinding{InterfaceName: "lo0", InterfaceIndex: 1}, Sequence: 1}
			policy.permits[network+grant.Local.String()] = desktopDarwinPFPermit{Grant: grant}
		}
	}
	parse("complete scoped socket rules", policy.render(), true)
}

func TestDesktopDarwinGuardianKernelPFSystemDispatch(t *testing.T) {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" {
		t.Fatal("actual captured Darwin system-dispatch fixture is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	actual, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "rules")
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFValidateSystemFilters(actual); err != nil {
		t.Fatal("actual system PF normalization/filter dispatch was not proved", err)
	}
	// A failed native read is not evidence that another owner changed a slot.
	// Preserve both the exact captured operation failure and its anchor stage.
	for _, deadline := range []bool{false, true} {
		var cancelled context.Context
		var stop context.CancelFunc
		want := context.Canceled
		if deadline {
			cancelled, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			cancelled, stop = context.WithCancel(context.Background())
			stop()
		}
		readback, err := desktopDarwinPFRead(cancelled, desktopDarwinPFNamespace)
		stop()
		if readback != "" || !errors.Is(err, want) || !strings.Contains(err.Error(), desktopDarwinPFNamespace) {
			t.Fatal("native PF readback lost its actual cancellation/deadline or captured anchor", readback, err)
		}
	}
	anchor := "anchor \"com.apple/*\" all\n"
	scrub := "scrub-anchor \"com.apple/*\" all fragment reassemble\n"
	for _, valid := range []string{anchor, scrub + anchor, scrub + anchor + "block out on utun42 all\n"} {
		if err := desktopDarwinPFValidateSystemFilters([]byte(valid)); err != nil {
			t.Fatal("stock PF normalization changed the required first-filter dispatch", valid, err)
		}
	}
	for _, invalid := range []string{"", scrub, strings.ReplaceAll(anchor, " all", " out"),
		"pass out all no state\n" + anchor,
		strings.ReplaceAll(scrub, "com.apple", "foreign") + anchor,
		strings.ReplaceAll(scrub, "reassemble", "crop") + anchor,
		scrub + scrub + anchor, anchor + scrub, scrub + anchor + "pass out all keep state\n"} {
		if err := desktopDarwinPFValidateSystemFilters([]byte(invalid)); err == nil {
			t.Fatal("Darwin system normalization bypassed the captured first-filter or state boundary", invalid)
		}
	}
}

func TestDesktopDarwinGuardianKernelPFAnchorPaths(t *testing.T) {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" {
		t.Fatal("actual captured Darwin anchor fixture is required")
	}
	capture := desktopSocketFixtureCapture()
	slot, generation := desktopDarwinPFSlot(capture), desktopDarwinPFGeneration(capture)
	if len(slot) > desktopDarwinPFAnchorPathLimit || len(generation) > desktopDarwinPFAnchorPathLimit {
		t.Fatal("captured PF slot/generation exceeded the actual whole-path loader bound", slot, generation)
	}
	for _, changed := range []DesktopSocketCapture{
		{SessionID: strings.Repeat("a", 32), SourceSHA256: capture.SourceSHA256, NetworkID: capture.NetworkID},
		{SessionID: capture.SessionID, SourceSHA256: strings.Repeat("b", 64), NetworkID: capture.NetworkID},
		{SessionID: capture.SessionID, SourceSHA256: capture.SourceSHA256, NetworkID: strings.Repeat("c", 32)},
	} {
		if desktopDarwinPFGeneration(changed) == generation {
			t.Fatal("Darwin sibling PF generation borrowed another complete capture")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	before, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace)
	if err != nil {
		t.Fatal(err)
	}
	legacy := desktopDarwinPFNamespace + "/physical"
	legacyChild := legacy + "/legacy"
	owned := []string{slot, generation, legacyChild, legacy}
	t.Cleanup(func() {
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelCleanup()
		for _, anchor := range owned {
			if _, err := desktopDarwinCommand(cleanup, "/sbin/pfctl", nil, "-a", anchor, "-F", "rules"); err != nil {
				t.Error("native PF anchor fixture did not clear its exact owned rules", anchor, err)
				continue
			}
			if actual, err := desktopDarwinPFRead(cleanup, anchor); err != nil || actual != "" {
				t.Error("native PF anchor fixture lost its exact absent readback", anchor, actual, err)
			}
		}
	})
	// The complete leaf and slot paths go through the actual loader, not only
	// pfctl -n at the shorter parent. These unreferenced fixture rules are
	// limited to newly owned loopback aliases and never affect host egress.
	rules := fmt.Sprintf("block drop out on lo0 inet to %s label \"rvpn-native-anchor-bound\"\n", desktopDarwinTestFixture.Addresses[1])
	expected, err := desktopDarwinPFCanonical(ctx, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFLoad(ctx, generation, rules); err != nil {
		t.Fatal("actual full-generation PF path did not load", err)
	}
	if actual, err := desktopDarwinPFRead(ctx, generation); err != nil || actual != expected {
		t.Fatal("actual full-generation PF path lost its exact readback", actual, err)
	}
	pointer, err := desktopDarwinPFCanonical(ctx, desktopDarwinPFPointer(capture))
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFLoad(ctx, slot, pointer+"\n"); err != nil {
		t.Fatal("actual full-session PF slot did not load its exact sibling pointer", err)
	}
	if actual, err := desktopDarwinPFRead(ctx, slot); err != nil || actual != pointer {
		t.Fatal("actual full-session PF slot lost its exact sibling readback", actual, err)
	}
	if actual, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace); err != nil || actual != before {
		t.Fatal("loading captured PF children rewrote their parent policy", actual, err)
	}
	if err := desktopDarwinPFRejectLegacyLayout(ctx); err != nil {
		t.Fatal("absent legacy PF layout was not proved from its actual parent inventory", err)
	}
	for _, anchor := range []string{legacy, legacyChild} {
		if err := desktopDarwinPFLoad(ctx, anchor, rules); err != nil {
			t.Fatal(err)
		}
		if actual, err := desktopDarwinPFRead(ctx, anchor); err != nil || actual != expected {
			t.Fatal("legacy PF negative did not establish its exact native rule before rejection", anchor, actual, err)
		}
		if err := desktopDarwinPFRejectLegacyLayout(ctx); err == nil || !strings.Contains(err.Error(), "earlier nested physical owner") {
			children, childErr := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", legacy, "-s", "Anchors")
			if len(children) > 2048 {
				children = append(children[:2048:2048], []byte("[truncated]")...)
			}
			t.Fatalf("earlier PF ownership was silently reinterpreted as a sibling generation: anchor=%q children=%q read_error=%v rejection=%v", anchor, children, childErr, err)
		}
		if actual, err := desktopDarwinPFRead(ctx, anchor); err != nil || actual != expected {
			t.Fatal("rejecting an earlier PF owner removed its recovery rules", actual, err)
		}
		if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", anchor, "-F", "rules"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopDarwinGuardianKernelProtectedPathAuthority(t *testing.T) {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" {
		t.Fatal("actual root-owned Darwin path fixture is required")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(filepath.Dir(executable), "path-authority-")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Lstat(directory)
		if err != nil || !os.SameFile(identity, current) {
			t.Error("captured native path fixture was replaced; refusing cleanup", err)
			return
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error("captured native path cleanup failed", err)
		}
	})
	// Exercise actual ownership metadata, including the group inherited from
	// macOS runtime ancestors, without changing a pre-existing system path.
	if err := os.Chown(directory, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinProtectedPath(directory, true); err != nil {
		t.Fatal("root-owned private directory with a read-only group was rejected", err)
	}
	for _, kind := range []string{"public-readonly-group", "private-readonly-group", "foreign-owner", "group-write", "other-write", "private-readable", "symlink", "hardlink", "mutable-parent", "write-acl", "private-read-acl"} {
		t.Run(kind, func(t *testing.T) {
			var err error
			parent := filepath.Join(directory, kind)
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "captured")
			if err := os.WriteFile(path, []byte("owned native path fixture\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 0, 1); err != nil {
				t.Fatal(err)
			}
			private := kind == "private-readonly-group" || kind == "private-readable" || kind == "private-read-acl"
			if private && kind != "private-readable" {
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "foreign-owner":
				err = os.Chown(path, 1, 1)
			case "group-write":
				err = os.Chmod(path, 0664)
			case "other-write":
				err = os.Chmod(path, 0646)
			case "symlink":
				alias := filepath.Join(parent, "alias")
				err = os.Symlink(path, alias)
				path = alias
			case "hardlink":
				err = os.Link(path, filepath.Join(parent, "alias"))
			case "mutable-parent":
				err = os.Chmod(parent, 0775)
			case "write-acl", "private-read-acl":
				right := "write"
				if kind == "private-read-acl" {
					right = "read"
				}
				before, statErr := os.Lstat(path)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if output, aclErr := exec.Command("/bin/chmod", "+a", "everyone allow "+right, path).CombinedOutput(); aclErr != nil {
					t.Fatal("actual native ACL fixture could not be applied", aclErr, string(output))
				}
				t.Cleanup(func() {
					if output, aclErr := exec.Command("/bin/chmod", "-N", path).CombinedOutput(); aclErr != nil {
						t.Error("actual native ACL fixture could not be removed", aclErr, string(output))
					}
				})
				after, statErr := os.Lstat(path)
				if statErr != nil || before.Mode().Perm() != after.Mode().Perm() {
					t.Fatal("ACL authority was not isolated from Unix mode bits", statErr)
				}
			}
			if err != nil {
				t.Fatal("actual native path fixture could not be prepared", err)
			}
			err = desktopDarwinProtectedPath(path, private)
			allowed := kind == "public-readonly-group" || kind == "private-readonly-group"
			if allowed && err != nil {
				t.Fatal("root-owned path with a read-only group was rejected", err)
			}
			if !allowed && err == nil {
				t.Fatal("unowned file, write access or private-data exposure acquired privileged path authority", kind)
			}
		})
	}
}

func init() {
	executable, err := os.Executable()
	if err != nil || filepath.Base(executable) != "darwin-guardian.test" || !strings.HasPrefix(filepath.Dir(executable), "/opt/routervpn-darwin-guardian-") {
		return
	}
	path := filepath.Join(filepath.Dir(executable), "fixture.json")
	if err := desktopDarwinProtectedPath(path, false); err != nil {
		fmt.Fprintln(os.Stderr, "native guardian fixture authority:", err)
		os.Exit(86)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &desktopDarwinTestFixture) != nil || !desktopSocketHex(desktopDarwinTestFixture.Nonce, 32) || len(desktopDarwinTestFixture.Addresses) != 4 || len(desktopDarwinTestFixture.Baselines) != 4 {
		fmt.Fprintln(os.Stderr, "native guardian fixture capture is invalid")
		os.Exit(87)
	}
	addresses := desktopDarwinTestFixture.Addresses
	if !addresses[0].Is4() || !addresses[1].Is4() || !addresses[0].IsLoopback() || !addresses[1].IsLoopback() || !addresses[2].Is6() || !addresses[3].Is6() || !addresses[2].IsPrivate() || !addresses[3].IsPrivate() {
		os.Exit(88)
	}
	desktopDarwinPFNamespace = "com.apple/000.t-" + desktopDarwinTestFixture.Nonce[:12]
	desktopDarwinPFTestScope = fmt.Sprintf("on lo0 to { %s, %s }", addresses[1], addresses[3])
	desktopDarwinPFTestAddresses = append([]netip.Addr(nil), addresses...)
	desktopDarwinIdentities = filepath.Join(filepath.Dir(executable), "identities")
	if len(os.Args) == 2 && os.Args[1] == "routervpn-darwin-fixture-preflight" {
		if os.Geteuid() != 0 {
			os.Exit(89)
		}
		// The runner must prove the actual native mode/ACL ancestry before
		// creating any loopback aliases or acquiring a PF enable reference.
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-owned-socket-helper" {
		if os.Args[2] == "uid-observer" {
			path := filepath.Join(filepath.Dir(executable), "uid-observer-fixture")
			if _, err := os.Lstat(path); err == nil {
				if err := desktopDarwinTestUIDObserver(path); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(91)
				}
				os.Exit(0)
			} else if !errors.Is(err, os.ErrNotExist) {
				os.Exit(92)
			}
		}
		if err := RunDesktopDarwinSocketHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-darwin-crash-source" {
		if err := desktopDarwinTestCrashSource(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(82)
		}
		os.Exit(83)
	}
	if len(os.Args) == 2 && os.Args[1] == "routervpn-darwin-fixture-cleanup" {
		if err := desktopDarwinFixtureCleanup(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(84)
		}
		os.Exit(0)
	}
}

// The root runner invokes this only after its entire native test process group
// has joined. It retires this private anchor/identity directory, never a global
// ruleset, an ambient account, or a helper selected by process name.
func desktopDarwinFixtureCleanup() error {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" {
		return errors.New("fixture cleanup has no explicit native authority")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	foreign := desktopDarwinTestForeignNamespace()
	if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", foreign, "-F", "rules"); err != nil {
		return err
	}
	if actual, err := desktopDarwinPFRead(ctx, foreign); err != nil || actual != "" {
		return errors.Join(err, errors.New("fixture foreign-policy test anchor remained"))
	}
	children, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", desktopDarwinPFNamespace, "-v", "-s", "Anchors")
	if err != nil {
		return err
	}
	var anchors []string
	for _, value := range strings.Fields(string(children)) {
		value = strings.TrimPrefix(value, desktopDarwinPFNamespace+"/")
		if value == "" {
			continue
		}
		if !regexp.MustCompile(`^(?:p[0-9a-f]{32}|g[A-Za-z0-9_-]{32}|physical(?:/[0-9a-f]{32}){0,2}|physical/legacy)$`).MatchString(value) {
			return errors.New("fixture cleanup found an unowned PF descendant")
		}
		anchors = append(anchors, desktopDarwinPFNamespace+"/"+value)
	}
	for index := len(anchors) - 1; index >= 0; index-- {
		if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", anchors[index], "-F", "rules"); err != nil {
			return err
		}
		if actual, err := desktopDarwinPFRead(ctx, anchors[index]); err != nil || actual != "" {
			return errors.Join(err, errors.New("fixture child rules remained"))
		}
	}
	if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", desktopDarwinPFNamespace, "-F", "rules"); err != nil {
		return err
	}
	entries, err := os.ReadDir(desktopDarwinIdentities)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "allocator.lock" {
			continue
		}
		var record desktopDarwinIdentityRecord
		raw, err := os.ReadFile(filepath.Join(desktopDarwinIdentities, entry.Name()))
		if err != nil || json.Unmarshal(raw, &record) != nil || record.Account != entry.Name() {
			return errors.Join(err, errors.New("fixture retained an unverified recovery record"))
		}
		if err := desktopDarwinRetireAccount(record.Account, record.UID); err != nil {
			return err
		}
	}
	return nil
}

func desktopDarwinKernelOptions(t *testing.T, destinations []DesktopDarwinSocketDestination) DesktopDarwinSocketOptions {
	t.Helper()
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" || !desktopDarwinKernelAvailable() {
		t.Fatal("actual root-owned Darwin runner and libproc are required; no native case is skipped")
	}
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	return DesktopDarwinSocketOptions{Interfaces: []DesktopDarwinSocketInterface{
		{Name: lo.Name, Index: uint32(lo.Index), Address: desktopDarwinTestFixture.Addresses[0]},
		{Name: lo.Name, Index: uint32(lo.Index), Address: desktopDarwinTestFixture.Addresses[2]},
	}, PrivateDestinations: destinations}
}

func desktopDarwinKernelPolicy(t *testing.T, destinations []DesktopDarwinSocketDestination) *DesktopDarwinSocketPolicy {
	t.Helper()
	capture := desktopSocketFixtureCapture()
	options := desktopDarwinKernelOptions(t, destinations)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, desktopDarwinPFBaseline(capture, options)); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	policy, err := NewDesktopDarwinSocketPolicy(context.Background(), capture, options)
	if policy != nil {
		t.Cleanup(func() {
			policy.command.Process.Signal(syscall.SIGCONT)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := policy.Close(ctx); err != nil {
				t.Error("actual Darwin guardian close", err)
			}
		})
	}
	if err != nil {
		t.Fatal("actual Darwin guardian preparation", err)
	}
	return policy
}

func desktopDarwinKernelBroker(t *testing.T, policy *DesktopDarwinSocketPolicy) *DesktopSocketBroker {
	t.Helper()
	broker, err := NewDesktopSocketBroker(context.Background(), policy.capture, policy, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		policy.command.Process.Signal(syscall.SIGCONT)
		deadline := time.Now().Add(15 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := broker.Close(ctx)
			cancel()
			if err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Error("Darwin native broker did not drain", err)
				return
			}
		}
	})
	// Register after drain cleanup so failure evidence is read while this
	// exact owner still retains its descriptors and scoped rules.
	t.Cleanup(func() {
		if t.Failed() {
			desktopDarwinKernelTrace(t, policy, broker)
		}
	})
	return broker
}

func desktopDarwinKernelTrace(t *testing.T, policy *DesktopDarwinSocketPolicy, broker *DesktopSocketBroker) {
	t.Helper()
	if policy == nil || policy.pf == nil || !policy.pf.valid() || desktopDarwinTestFixture.Nonce == "" {
		return
	}
	// Diagnostics are read-only and confined to the fixture's captured owner.
	// A failed query remains a failed query; no repair or permit is installed.
	t.Logf("owned PF failure: uid=%d guardian=%d current=%t", policy.uid, policy.owner.ProcessID, policy.Current(policy.capture, policy.owner))
	if broker != nil {
		broker.mu.Lock()
		var sockets []*desktopSocket
		for socket := range broker.sockets {
			sockets = append(sockets, socket)
		}
		broker.mu.Unlock()
		for _, socket := range sockets {
			socket.mu.Lock()
			t.Logf("owned PF tuple: protocol=%s local=%s remote=%s closing=%t last_failure=%v", socket.network, socket.local, socket.remote, socket.closing, socket.lastFailure)
			if socket.sourceFile != nil {
				raw, err := socket.sourceFile.SyscallConn()
				if err == nil {
					err = raw.Control(func(fd uintptr) {
						var stat syscall.Stat_t
						statErr := syscall.Fstat(int(fd), &stat)
						local, localErr := desktopSocketLocal(int(fd))
						family := syscall.AF_INET6
						if socket.binding.LocalAddress.Is4() {
							family = syscall.AF_INET
						}
						bound, boundErr := desktopDarwinBoundInterface(int(fd), family)
						t.Logf("owned PF retained descriptor: uid=%d local=%s interface=%d errors=%v", stat.Uid, local, bound, errors.Join(statErr, localErr, boundErr))
					})
				}
				if err != nil {
					t.Log("owned PF retained descriptor readback:", err)
				}
			}
			socket.mu.Unlock()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, query := range []struct{ anchor, kind string }{
		{desktopDarwinPFNamespace, "labels"}, {policy.pf.Slot, "rules"}, {policy.pf.Anchor, "rules"}, {policy.pf.Anchor, "labels"},
	} {
		started := time.Now()
		raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", query.anchor, "-s", query.kind)
		if len(raw) > 2048 {
			raw = append(raw[:2048:2048], []byte("[truncated]")...)
		}
		t.Logf("owned PF %s %q in %s: %q error=%v", query.kind, query.anchor, time.Since(started).Round(time.Millisecond), raw, err)
	}
}

func TestDesktopDarwinGuardianKernelIdentityRetirement(t *testing.T) {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" || !desktopDarwinKernelAvailable() {
		t.Fatal("actual scoped Darwin identity fixture is required")
	}
	for _, state := range []string{"present", "deleted-before-native-readback", "changed-recovery-owner"} {
		t.Run(state, func(t *testing.T) {
			account, uid, err := desktopDarwinAllocateAccount(desktopSocketFixtureCapture())
			if err != nil {
				t.Fatal("actual disabled identity allocation failed", err)
			}
			path := filepath.Join(desktopDarwinIdentities, account)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Prove the original identity before priming the actual libc cache.
			if err := desktopDarwinVerifyAccount(account, uid); err != nil || !desktopDarwinUIDAccount(uid, account) {
				t.Fatal("captured UID lost its actual native account", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			absent, err := desktopDarwinFreshUIDReadback(ctx, desktopSocketFixtureCapture(), uid)
			cancel()
			if err != nil || absent {
				t.Fatal("fresh observer accepted an actual occupied UID or failed its native lookup", err)
			}
			if state == "changed-recovery-owner" {
				var record desktopDarwinIdentityRecord
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				record.GeneratedUID = "00000000-0000-0000-0000-000000000000"
				changed, err := json.Marshal(record)
				if err != nil || os.WriteFile(path, changed, 0600) != nil {
					t.Fatal("could not install the exact owned recovery negative")
				}
				restore := true
				defer func() {
					if restore {
						os.WriteFile(path, raw, 0600)
					}
				}()
				if err := desktopDarwinRetireAccount(account, uid); err == nil {
					t.Fatal("changed recovery owner deleted a still-present account")
				}
				if _, err := desktopDarwinAccountRecord(account, uid); err != nil {
					t.Fatal("rejected recovery mutated the independently owned account", err)
				}
				if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, changed) {
					t.Fatal("rejected recovery discarded its quarantined record", err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				restore = false
			}
			if state == "deleted-before-native-readback" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, err := desktopDarwinCommand(ctx, "/usr/bin/dscl", nil, "/Local/Default", "-delete", "/Users/"+account)
				cancel()
				if err != nil {
					t.Fatal("actual owned account deletion failed", err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal("interrupted deletion lost its recovery record", err)
				}
			}
			if err := desktopDarwinRetireAccount(account, uid); err != nil {
				t.Fatal("actual identity retirement lost the native absence boundary", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("proved identity retirement retained its recovery owner", err)
			}
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			absent, err = desktopDarwinFreshUIDReadback(ctx, desktopSocketFixtureCapture(), uid)
			cancel()
			if err != nil || !absent {
				t.Fatal("identity retirement completed before actual native absence", err)
			}
			if err := desktopDarwinNoUIDProcesses(uid); err != nil {
				t.Fatal("identity retirement retained an actual UID process", err)
			}
		})
	}
}

// Only this tagged, uniquely installed native test executable reads this
// root-owned fixture file. The shipping helper has no environment, pathname,
// command-line, or observer override. Every negative still crosses the actual
// retained executable, inherited stream, kernel peer check and child join.
func desktopDarwinTestUIDObserver(path string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || desktopDarwinProtectedPath(path, true) != nil {
		return errors.New("UID observer test fixture has no private root owner")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64 {
		return errors.New("UID observer test fixture lost its bounded mode")
	}
	mode := string(raw)
	switch mode {
	case "wrong-uid", "wrong-capture", "wrong-sequence", "unknown-status", "malformed", "descriptor", "failed-join", "cancelled", "unjoined":
	default:
		return errors.New("UID observer test fixture has another mode")
	}
	channel, err := desktopDarwinHelperChannel()
	if err != nil {
		return err
	}
	defer channel.Close()
	channel.SetDeadline(time.Now().Add(3 * time.Second))
	parent := uint32(os.Getppid())
	var request desktopDarwinUIDRequest
	file, err := desktopDarwinReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("UID observer test fixture received a descriptor")
	}
	if err != nil || request.validate() != nil {
		return errors.Join(err, errors.New("UID observer test fixture lost its real parent request"))
	}
	mark := func(stage string) error {
		return os.WriteFile(path+".pid", []byte(strconv.Itoa(os.Getpid())+" "+stage), 0600)
	}
	if err := mark("received"); err != nil {
		return err
	}
	if mode == "cancelled" {
		var unused desktopDarwinUIDRequest
		_, err := desktopDarwinReceive(channel, &unused, parent, 0)
		return errors.Join(err, errors.New("cancelled observer must not issue a receipt"))
	}
	reply := desktopDarwinUIDReply{Sequence: request.Sequence, Capture: request.Capture, UID: request.UID, State: "absent"}
	switch mode {
	case "wrong-uid":
		reply.UID++
	case "wrong-capture":
		reply.Capture.NetworkID = strings.Repeat("e", 32)
	case "wrong-sequence":
		reply.Sequence++
	case "unknown-status":
		reply.State = "unknown"
	}
	if mode == "malformed" {
		err = desktopDarwinSend(channel, map[string]any{"Sequence": reply.Sequence, "Capture": reply.Capture, "UID": reply.UID, "State": reply.State, "Unrequested": true}, nil)
	} else if mode == "descriptor" {
		var unexpected *os.File
		unexpected, err = os.Open(os.DevNull)
		if err == nil {
			err = desktopDarwinSend(channel, reply, unexpected)
			unexpected.Close()
		}
	} else {
		err = desktopDarwinSend(channel, reply, nil)
	}
	if err != nil {
		return err
	}
	var ack desktopDarwinUIDRequest
	file, err = desktopDarwinReceive(channel, &ack, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("UID observer test acknowledgment transferred a descriptor")
	}
	if err != nil || ack != request.acknowledgment() {
		return errors.Join(err, errors.New("UID observer test acknowledgment changed its real parent request"))
	}
	if mode == "unjoined" {
		if err := mark("unjoined"); err != nil {
			return err
		}
		channel.SetDeadline(time.Time{})
		var unused desktopDarwinUIDRequest
		_, err := desktopDarwinReceive(channel, &unused, parent, 0)
		return errors.Join(err, errors.New("unjoined observer has no successful exit"))
	}
	return errors.New("negative observer must not produce a successful child exit")
}

func TestDesktopDarwinGuardianKernelUIDObserver(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" || !desktopDarwinKernelAvailable() {
		t.Fatal("actual scoped Darwin observer fixture is required")
	}
	executable, err := desktopDarwinExecutable()
	if err != nil {
		t.Fatal(err)
	}
	request := desktopDarwinUIDRequest{Operation: "observe-uid", Sequence: 1, Capture: desktopSocketFixtureCapture(), UID: 0x40000001}
	// Exercise the actual production child admission, including a valid
	// native reply followed by an acknowledgment from a different capture.
	for _, mode := range []string{"operation", "sequence", "capture", "uid", "descriptor", "unknown-field", "acknowledgment"} {
		t.Run("request/"+mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			channel, child, err := desktopDarwinSocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			defer child.Close()
			command := exec.CommandContext(ctx, executable, "routervpn-owned-socket-helper", "uid-observer")
			command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
			command.ExtraFiles = []*os.File{child}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			child.Close()
			joined := false
			defer func() {
				if !joined {
					command.Process.Kill()
					command.Wait()
				}
			}()
			deadline, _ := ctx.Deadline()
			channel.SetDeadline(deadline)
			changed := request
			switch mode {
			case "operation":
				changed.Operation = "prepare"
			case "sequence":
				changed.Sequence++
			case "capture":
				changed.Capture.SourceSHA256 = ""
			case "uid":
				changed.UID = 0
			}
			var sent *os.File
			if mode == "descriptor" {
				sent, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer sent.Close()
			}
			if mode == "unknown-field" {
				err = desktopDarwinSend(channel, map[string]any{"Operation": request.Operation, "Sequence": request.Sequence, "Capture": request.Capture, "UID": request.UID, "Path": "/unrequested"}, nil)
			} else {
				err = desktopDarwinSend(channel, changed, sent)
			}
			if err != nil {
				t.Fatal("native request negative could not reach its actual child", err)
			}
			var reply desktopDarwinUIDReply
			file, readErr := desktopDarwinReceive(channel, &reply, uint32(command.Process.Pid), 0)
			if file != nil {
				file.Close()
				t.Fatal("read-only UID helper transferred a descriptor")
			}
			if mode == "acknowledgment" {
				if _, err := reply.absent(request); readErr != nil || err != nil {
					t.Fatal("acknowledgment negative did not first obtain its real native lookup", readErr, err)
				}
				ack := request.acknowledgment()
				ack.UID++
				if err := desktopDarwinSend(channel, ack, nil); err != nil {
					t.Fatal(err)
				}
			} else if readErr == nil {
				t.Fatal("invalid observer request acquired a native receipt")
			}
			joinErr := command.Wait()
			joined = true
			if joinErr == nil || ctx.Err() != nil {
				t.Fatal("invalid observer request was not explicitly rejected by the joined helper", joinErr, ctx.Err())
			}
		})
	}
	fixture := filepath.Join(filepath.Dir(executable), "uid-observer-fixture")
	for _, mode := range []string{"wrong-uid", "wrong-capture", "wrong-sequence", "unknown-status", "malformed", "descriptor", "failed-join", "cancelled", "unjoined"} {
		t.Run("reply/"+mode, func(t *testing.T) {
			file, err := os.OpenFile(fixture, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(fixture)
			defer os.Remove(fixture + ".pid")
			if _, err := file.WriteString(mode); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type observation struct {
				absent bool
				err    error
			}
			done := make(chan observation, 1)
			go func() {
				absent, err := desktopDarwinFreshUIDReadback(ctx, request.Capture, request.UID)
				done <- observation{absent, err}
			}()
			if mode == "cancelled" || mode == "unjoined" {
				stage := "received"
				if mode == "unjoined" {
					stage = "unjoined"
				}
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				deadline := time.NewTimer(2 * time.Second)
				defer deadline.Stop()
			ready:
				for {
					select {
					case result := <-done:
						t.Fatal("UID observation completed without its joined helper", result.absent, result.err)
					case <-deadline.C:
						t.Fatal("UID observer did not reach its real captured cancellation boundary")
					case <-tick.C:
						raw, err := os.ReadFile(fixture + ".pid")
						fields := strings.Fields(string(raw))
						if err == nil && len(fields) == 2 && fields[1] == stage {
							break ready
						}
					}
				}
				select {
				case result := <-done:
					t.Fatal("UID observation completed without its joined helper", result.absent, result.err)
				default:
				}
				cancel()
			}
			result := <-done
			if result.absent || result.err == nil {
				t.Fatal("unowned, unknown, malformed or unjoined UID receipt released an identity", result.absent, result.err)
			}
			if (mode == "cancelled" || mode == "unjoined") && !errors.Is(result.err, context.Canceled) {
				t.Fatal("cancelled native observer lost its actual operation identity", result.err)
			}
			raw, err := os.ReadFile(fixture + ".pid")
			fields := strings.Fields(string(raw))
			if err != nil || len(fields) != 2 {
				t.Fatal("observer negative did not execute its actual retained child", err)
			}
			pid, err := strconv.Atoi(fields[0])
			if err != nil || pid <= 1 || syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("completed UID observer retained an unjoined native process", err)
			}
		})
	}
}

func desktopDarwinKernelPeer(t *testing.T, network string) netip.AddrPort {
	t.Helper()
	address := desktopDarwinTestFixture.Addresses[1]
	if strings.HasSuffix(network, "6") {
		address = desktopDarwinTestFixture.Addresses[3]
	}
	endpoint := netip.AddrPortFrom(address, 0).String()
	var accepted, received, replied atomic.Int64
	trace := func() {
		if t.Failed() {
			t.Logf("owned loopback echo: protocol=%s address=%s accepted=%d received_bytes=%d replied_bytes=%d", network, address, accepted.Load(), received.Load(), replied.Load())
		}
	}
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer connection.Close()
					connection.SetDeadline(time.Now().Add(20 * time.Second))
					buffer := make([]byte, 8192)
					for {
						n, readErr := connection.Read(buffer)
						if n > 0 {
							received.Add(int64(n))
							written, writeErr := connection.Write(buffer[:n])
							replied.Add(int64(written))
							if writeErr != nil || written != n {
								return
							}
						}
						if readErr != nil {
							return
						}
					}
				}()
			}
		}()
		t.Cleanup(func() { trace(); listener.Close(); <-joined; workers.Wait() })
		return netip.MustParseAddrPort(listener.Addr().String())
	}
	packet, err := net.ListenPacket(network, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		buffer := make([]byte, 8192)
		for {
			n, address, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			received.Add(int64(n))
			written, _ := packet.WriteTo(buffer[:n], address)
			replied.Add(int64(written))
		}
	}()
	t.Cleanup(func() { trace(); packet.Close(); <-joined })
	return netip.MustParseAddrPort(packet.LocalAddr().String())
}

func desktopDarwinExchange(t *testing.T, connection net.Conn) {
	t.Helper()
	data := []byte("actual stateless PF owned bytes")
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(data); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(data))
	if n, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != string(data) {
		t.Fatal("real owned physical reply", n, string(buffer[:n]), err)
	}
}

func TestDesktopDarwinGuardianKernelTCPAndUDP(t *testing.T) {
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			remote := desktopDarwinKernelPeer(t, network)
			policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: network[:3], Address: remote}})
			broker := desktopDarwinKernelBroker(t, policy)
			// Exercise a bounded real dial; a dropped SYN must not defer failure
			// to the kernel's unrelated default retransmission timeout.
			dial, stopDial := context.WithTimeout(context.Background(), desktopSocketControlWait)
			defer stopDial()
			connection, err := broker.DialContext(dial, network, remote.String())
			if err != nil {
				t.Fatal(err)
			}
			desktopDarwinExchange(t, connection)
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := broker.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := policy.pf.allAbsent(ctx); err != nil {
				t.Fatal(err)
			}
			if !desktopDarwinUIDAvailable(policy.uid) {
				t.Fatal("normal close did not retire its isolated identity")
			}
		})
	}
}

func TestDesktopDarwinGuardianKernelWrongUIDAndPrivatePeer(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopDarwinKernelBroker(t, policy)
	rootSocket, err := net.ListenPacket("udp4", netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[0], 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rootSocket.Close() })
	raw, _ := rootSocket.(syscall.Conn).SyscallConn()
	binding, _ := policy.Select(context.Background(), policy.capture, "udp", remote)
	if policy.Bind(context.Background(), policy.capture, binding, "udp4", raw) == nil {
		t.Fatal("a root-created descriptor acquired the isolated creator UID")
	}
	if _, err := broker.DialContext(context.Background(), "udp4", netip.AddrPortFrom(remote.Addr(), remote.Port()+1).String()); err == nil {
		t.Fatal("an uncaptured private port acquired physical egress")
	}
	// The first half exercises the actual broker/source admission. Retire that
	// owner completely before the deliberate PF-only negative below: cancelling
	// its policy while borrowing its leaf lets the broker concurrently Close it.
	closeCtx, stopClose := context.WithTimeout(context.Background(), 8*time.Second)
	err = broker.Close(closeCtx)
	stopClose()
	if err != nil {
		t.Fatal("native broker did not join before the independent UID rule test", err)
	}
	select {
	case <-broker.joined:
	default:
		t.Fatal("independent UID rule test borrowed an unjoined native broker")
	}
	capture := policy.capture
	capture.NetworkID = desktopDarwinTestFixture.Nonce
	if capture.NetworkID == policy.capture.NetworkID {
		t.Fatal("independent UID rule fixture did not capture a fresh generation")
	}
	account, uid, err := desktopDarwinAllocateAccount(capture)
	if err != nil {
		t.Fatal(err)
	}
	var isolated *desktopDarwinPF
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
		defer stop()
		if isolated != nil {
			if err := isolated.close(cleanup); err != nil {
				t.Error("independent UID rule fixture retained its exact PF/account recovery owner", err)
				return
			}
		}
		if err := desktopDarwinRetireAccount(account, uid); err != nil {
			t.Error("independent UID rule fixture did not retire its exact disabled identity", err)
		}
	})
	isolated, err = desktopDarwinNewPF(capture, uid, account, policy.options)
	if err != nil {
		t.Fatal("independent UID rule fixture did not establish its exact native ownership", err)
	}
	binding.Owner = desktopDarwinOwner(capture, uid, account, 1)
	grant := DesktopSocketGrant{Capture: capture, Binding: binding, SocketID: strings.Repeat("9", 32), Network: "udp", Local: netip.MustParseAddrPort(rootSocket.LocalAddr().String()), Remote: remote, Sequence: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := isolated.grant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	rootSocket.WriteTo([]byte("wrong exact tuple UID"), net.UDPAddrFromAddrPort(remote))
	rootSocket.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buffer := make([]byte, 64)
	if n, _, err := rootSocket.ReadFrom(buffer); err == nil || n != 0 {
		t.Fatal("the actual PF rule admitted the same tuple from another UID", n, err)
	}
	if err := isolated.revoke(ctx, grant); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopDarwinGuardianKernelSocketRetirementReusesCapacity(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopDarwinKernelBroker(t, policy)
	for index := 0; index < DesktopSocketLimit+2; index++ {
		connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
		if err != nil {
			t.Fatalf("sequential owned socket %d: %v", index, err)
		}
		desktopDarwinExchange(t, connection)
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopDarwinGuardianKernelRetainedTunnel(t *testing.T) {
	policy := desktopDarwinKernelPolicy(t, nil)
	fd, err := syscall.Socket(32 /* AF_SYSTEM */, syscall.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "owned-test-utun")
	defer file.Close()
	var control struct {
		Id   uint32
		Name [96]byte
	}
	copy(control.Name[:], "com.apple.net.utun_control")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0xc0644e03 /* CTLIOCGINFO */, uintptr(unsafe.Pointer(&control))); errno != 0 {
		t.Fatal(errno)
	}
	address := struct {
		Length   uint8
		Family   uint8
		System   uint16
		ID       uint32
		Unit     uint32
		Reserved [5]uint32
	}{Length: 32, Family: 32, System: 2, ID: control.Id}
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(address.Length)); errno != 0 {
		t.Fatal(errno)
	}
	name, err := desktopDarwinReadTunnel(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := desktopDarwinCommand(ctx, "/sbin/ifconfig", nil, name, "up"); err != nil {
		t.Fatal(err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if policy.BindTunnel(context.Background(), policy.capture, name, uint32(iface.Index)) == nil {
		t.Fatal("a reusable interface name replaced the actual owned control descriptor")
	}
	if err := policy.BindTunnelFile(context.Background(), policy.capture, name, uint32(iface.Index), file); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if actual, err := net.InterfaceByIndex(iface.Index); err != nil || actual.Name != name {
		t.Fatal("guardian did not retain the actual utun object after native close", err)
	}
	if err := policy.RetireTunnel(context.Background(), policy.capture, name, uint32(iface.Index)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		actual, err := net.InterfaceByIndex(iface.Index)
		if err != nil || actual.Name != name {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired utun descriptor remained owned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readCancel()
	rules, err := desktopDarwinPFRead(readCtx, policy.pf.Anchor)
	if err != nil || strings.Contains(rules, "on "+name+" ") {
		t.Fatal("reusable utun name retained an active permission", err)
	}
}

type desktopDarwinCrashReceipt struct {
	PF          *desktopDarwinPF
	UID         uint32
	Account     string
	GuardianPID int
	Local       netip.AddrPort
}

func desktopDarwinTestCrashSource(remoteText string) error {
	remote, err := netip.ParseAddrPort(remoteText)
	if err != nil {
		return err
	}
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		return err
	}
	options := DesktopDarwinSocketOptions{Interfaces: []DesktopDarwinSocketInterface{{Name: lo.Name, Index: uint32(lo.Index), Address: desktopDarwinTestFixture.Addresses[0]}}, PrivateDestinations: []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}}}
	policy, err := NewDesktopDarwinSocketPolicy(context.Background(), desktopSocketFixtureCapture(), options)
	if err != nil {
		return err
	}
	broker, err := NewDesktopSocketBroker(context.Background(), policy.capture, policy, func() bool { return true })
	if err != nil {
		return err
	}
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		return err
	}
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("actual parent crash proof")); err != nil {
		return err
	}
	buffer := make([]byte, 128)
	if _, err := connection.Read(buffer); err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(desktopDarwinCrashReceipt{PF: policy.pf, UID: policy.uid, Account: policy.account, GuardianPID: policy.command.Process.Pid, Local: netip.MustParseAddrPort(connection.LocalAddr().String())}); err != nil {
		return err
	}
	var signal [1]byte
	if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
		return err
	}
	os.Exit(83)
	return nil
}

func TestDesktopDarwinGuardianKernelBothOwnersCrashCannotReuseTuple(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprint(both), func(t *testing.T) {
			remote := desktopDarwinKernelPeer(t, "udp4")
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, desktopDarwinPFBaseline(desktopSocketFixtureCapture(), desktopDarwinKernelOptions(t, nil))); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			executable, _ := os.Executable()
			command := exec.Command(executable, "routervpn-darwin-crash-source", remote.String())
			command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
			input, _ := command.StdinPipe()
			output, _ := command.StdoutPipe()
			command.Stderr = os.Stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			joined := false
			defer func() {
				input.Close()
				if !joined {
					command.Process.Kill()
					command.Wait()
				}
			}()
			line, err := bufio.NewReader(output).ReadBytes('\n')
			var receipt desktopDarwinCrashReceipt
			if err != nil || json.Unmarshal(line, &receipt) != nil || receipt.PF == nil || !receipt.PF.valid() || receipt.GuardianPID <= 1 {
				t.Fatal("actual native child did not return retained ownership", err, string(line))
			}
			defer func() {
				syscall.Kill(receipt.GuardianPID, syscall.SIGCONT)
				syscall.Kill(receipt.GuardianPID, syscall.SIGKILL)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				if err := receipt.PF.close(ctx); err != nil {
					t.Error(err)
				}
			}()
			if both {
				if err := syscall.Kill(receipt.GuardianPID, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			}
			input.Write([]byte{1})
			if err := command.Wait(); err == nil {
				t.Fatal("crash child returned through ordinary teardown")
			}
			joined = true
			deadline := time.Now().Add(8 * time.Second)
			var replacement net.PacketConn
			for {
				replacement, err = net.ListenPacket("udp4", receipt.Local.String())
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("dead owners retained an unjoined source port", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			defer replacement.Close()
			replacement.WriteTo([]byte("replacement UID must never inherit state"), net.UDPAddrFromAddrPort(remote))
			replacement.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buffer := make([]byte, 128)
			if n, _, err := replacement.ReadFrom(buffer); err == nil || n != 0 {
				t.Fatal("dead owners left state/permission usable by another UID at the same tuple", n, err)
			}
			if err := desktopDarwinVerifyAccount(receipt.Account, receipt.UID); err != nil {
				t.Fatal("exceptional process loss did not quarantine exact UID", err)
			}
		})
	}
}

func TestDesktopDarwinGuardianCurrentFreshnessAndStateScope(t *testing.T) {
	capture, owner := desktopSocketFixtureCapture(), desktopSocketFixturePolicy().owner
	for _, test := range []struct {
		observed int64
		valid    bool
	}{{time.Now().UnixMilli(), true}, {0, false}, {time.Now().Add(time.Hour).UnixMilli(), false}, {time.Now().Add(-DesktopSocketReadbackAge - time.Second).UnixMilli(), false}} {
		policy := &DesktopDarwinSocketPolicy{capture: capture, owner: owner}
		policy.current.Store(true)
		policy.observed.Store(test.observed)
		if policy.Current(capture, owner) != test.valid {
			t.Fatal("Darwin policy freshness accepted an invalid age")
		}
	}
	scope := []desktopDarwinStateInterface{{Name: "en-test", Index: 3, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::2")}}}
	for _, line := range []string{"all udp 192.0.2.1:1234 -> 198.51.100.1:53 MULTIPLE:MULTIPLE", "all tcp 2001:db8::2[1234] <- 2001:db8:1::1[443] ESTABLISHED:ESTABLISHED"} {
		if desktopDarwinStatesAbsent([]byte(line), scope) == nil {
			t.Fatal("floating physical state was accepted", line)
		}
	}
	if err := desktopDarwinStatesAbsent([]byte("utun99 tcp 10.250.0.1:1234 -> 203.0.113.1:443 ESTABLISHED:ESTABLISHED"), scope); err != nil {
		t.Fatal("unrelated tunnel state was discarded", err)
	}
}

func TestDesktopDarwinGuardianKernelForeignBlockAndLaterPass(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopDarwinKernelBroker(t, policy)
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	desktopDarwinExchange(t, connection)
	foreign := desktopDarwinTestForeignNamespace()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := desktopDarwinPFLoad(ctx, foreign, "\n"); err != nil {
			t.Error(err)
		}
	}()
	load := func(rules string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := desktopDarwinPFLoad(ctx, foreign, rules); err != nil {
			t.Fatal(err)
		}
	}
	// A nonquick foreign block must still win after an owned grant. This fails
	// if any enclosing owned anchor or permit accidentally becomes quick.
	block := fmt.Sprintf("block drop out on lo0 inet proto udp to %s port %d\n", remote.Addr(), remote.Port())
	load(block)
	connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := connection.Write([]byte("foreign policy remains authoritative")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	if n, err := connection.Read(buffer); err == nil || n != 0 {
		t.Fatal("owned permit bypassed a later foreign block", n, err)
	}
	load(fmt.Sprintf("pass out on lo0 inet proto udp to %s port %d no state\n", remote.Addr(), remote.Port()))
	desktopDarwinExchange(t, connection)
	rootSocket, err := net.ListenPacket("udp4", netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[0], 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer rootSocket.Close()
	rootSocket.WriteTo([]byte("later foreign pass must not bypass own deny"), net.UDPAddrFromAddrPort(remote))
	rootSocket.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := rootSocket.ReadFrom(buffer); err == nil || n != 0 {
		t.Fatal("later foreign pass bypassed nested quick deny", n, err)
	}
	load("\n")
}

func TestDesktopDarwinGuardianKernelRejectsForeignStatefulDirections(t *testing.T) {
	for _, direction := range []string{"in", "out"} {
		t.Run(direction, func(t *testing.T) {
			policy := desktopDarwinKernelPolicy(t, nil)
			foreign := desktopDarwinTestForeignNamespace()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := desktopDarwinPFLoad(ctx, foreign, "\n"); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			rules := fmt.Sprintf("pass %s on lo0 inet proto udp to %s keep state\n", direction, desktopDarwinTestFixture.Addresses[1])
			if err := desktopDarwinPFLoad(ctx, foreign, rules); err != nil {
				t.Fatal(err)
			}
			if err := policy.pf.verify(ctx, true); err == nil {
				t.Fatal("stateful foreign filter was reported as owned stateless protection")
			}
			if err := desktopDarwinPFLoad(ctx, foreign, "\n"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopDarwinGuardianKernelBlockedControlRetainsSourcePort(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopDarwinKernelBroker(t, policy)
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	desktopDarwinExchange(t, connection)
	local := connection.LocalAddr().String()
	if err := policy.command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer policy.command.Process.Signal(syscall.SIGCONT)
	controlDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, file, err := policy.call(ctx, desktopDarwinRequest{Operation: "probe", Capture: policy.capture}, nil, true)
		if file != nil {
			file.Close()
		}
		controlDone <- err
	}()
	deadline := time.Now().Add(DesktopSocketReadbackAge + 2*time.Second)
	for policy.Current(policy.capture, policy.owner) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	connection.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("retired owner")); err == nil {
		t.Fatal("blocked guardian control postponed independent native I/O retirement")
	}
	if replacement, err := net.ListenPacket("udp4", local); err == nil {
		replacement.Close()
		t.Fatal("blocked cleanup released a still-permitted source port")
	}
	if err := <-controlDone; err == nil {
		t.Fatal("stopped guardian fabricated a control acknowledgment")
	}
	if err := policy.command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := broker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.pf.allAbsent(ctx); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenPacket("udp4", local)
	if err != nil {
		t.Fatal("joined cleanup retained the source port", err)
	}
	replacement.Close()
}

func TestDesktopDarwinGuardianKernelFinishRequiresDescriptorRetirement(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	binding, err := policy.Select(context.Background(), policy.capture, "udp", remote)
	if err != nil {
		t.Fatal(err)
	}
	creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, SocketID: strings.Repeat("a", 32), Network: "udp"}
	created, err := policy.CreateSocket(context.Background(), creation)
	if err != nil {
		t.Fatal(err)
	}
	defer created.File.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	if policy.Close(ctx) == nil {
		cancel()
		t.Fatal("finish claimed success with an unretired descriptor")
	}
	cancel()
	created.File.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := policy.ReleaseSocket(ctx, creation); err != nil {
		t.Fatal(err)
	}
	if err := policy.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopDarwinGuardianKernelFloatingStateRetirement(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	local := desktopDarwinTestFixture.Addresses[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Establish an actual pre-existing floating state inside the fixture's
	// own aliases, then replace only its filter rules. State lookup precedes
	// subsequent per-packet UID checks, so the initial readback must reject it.
	rules := fmt.Sprintf("pass out quick on lo0 inet proto udp from %s to %s port %d keep state (floating)\n", local, remote.Addr(), remote.Port())
	if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, rules); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), net.UDPAddrFromAddrPort(remote))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	desktopDarwinExchange(t, connection)
	captured, err := desktopDarwinCaptureStateInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "states")
	if err != nil || desktopDarwinStatesAbsent(raw, captured) == nil {
		t.Fatal("actual earlier floating physical state was not observed", string(raw), err)
	}
	if err := desktopDarwinPFLoad(ctx, desktopDarwinPFNamespace, desktopDarwinPFBaseline(desktopSocketFixtureCapture(), desktopDarwinKernelOptions(t, nil))); err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinRetirePhysicalStates(ctx, captured); err != nil {
		t.Fatal("actual captured floating state did not retire", err)
	}
	connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
	connection.Write([]byte("former floating state cannot bypass owned deny"))
	var buffer [128]byte
	if n, err := connection.Read(buffer[:]); err == nil || n != 0 {
		t.Fatal("retired earlier physical state still bypassed the UID boundary", n, err)
	}
}

func TestDesktopDarwinGuardianKernelStaleCaptureAndReplacement(t *testing.T) {
	remote := desktopDarwinKernelPeer(t, "udp4")
	policy := desktopDarwinKernelPolicy(t, []DesktopDarwinSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopDarwinKernelBroker(t, policy)
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	desktopDarwinExchange(t, connection)
	stale := policy.capture
	stale.NetworkID = strings.Repeat("f", 32)
	if _, err := policy.Select(context.Background(), stale, "udp", remote); err == nil {
		t.Fatal("another network generation selected the old socket owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	replacement := desktopDarwinPFPointer(stale)
	replacement, err = desktopDarwinPFCanonical(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopDarwinPFLoad(ctx, policy.pf.Slot, replacement+"\n"); err != nil {
		t.Fatal(err)
	}
	// A replacement dispatch invalidates admission synchronously on readback.
	if err := policy.pf.verify(ctx, true); err == nil {
		t.Fatal("replacement PF generation remained current")
	}
	policy.Cancel()
	policy.command.Process.Kill()
	select {
	case <-policy.joined:
	case <-ctx.Done():
		t.Fatal("actual guardian did not join")
	}
	if err := broker.Close(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := desktopDarwinPFRead(ctx, policy.pf.Slot)
	if err != nil || actual != replacement {
		t.Fatal("old-owner cleanup removed the replacement dispatch", actual, err)
	}
	if err := desktopDarwinPFLoad(ctx, policy.pf.Slot, "\n"); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopDarwinGuardianChannelFragmentsAndDescriptorClosure(t *testing.T) {
	for _, fault := range []string{"valid", "idle-then-valid", "partial-header-timeout", "wrong-pid", "late-rights", "two-rights", "unknown-field"} {
		t.Run(fault, func(t *testing.T) {
			receiver, senderFile, err := desktopDarwinSocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			senderConn, err := net.FileConn(senderFile)
			senderFile.Close()
			if err != nil {
				t.Fatal(err)
			}
			sender := senderConn.(*net.UnixConn)
			defer sender.Close()
			if fault == "idle-then-valid" {
				if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				var idle desktopDarwinRequest
				file, err := desktopDarwinReceive(receiver, &idle, uint32(os.Getpid()), 0)
				if file != nil {
					file.Close()
				}
				if !errors.Is(err, desktopDarwinIdle) || file != nil || idle.Operation != "" {
					t.Fatal("actual empty Darwin control retired its idle owner", err)
				}
			}
			raw := []byte(`{"Operation":"probe"}`)
			if fault == "unknown-field" {
				raw = []byte(`{"Operation":"probe","foreign":true}`)
			}
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, uint32(len(raw)))
			local := netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[0], 0)
			packet, err := net.ListenPacket("udp4", local.String())
			if err != nil {
				t.Fatal(err)
			}
			port := packet.LocalAddr().String()
			duplicate, err := packet.(*net.UDPConn).File()
			if err != nil {
				packet.Close()
				t.Fatal(err)
			}
			packet.Close()
			sent := make(chan error, 1)
			senderJoined := make(chan struct{})
			go func() {
				defer close(senderJoined)
				defer duplicate.Close()
				rights := []byte(nil)
				if fault == "two-rights" {
					rights = syscall.UnixRights(int(duplicate.Fd()), int(duplicate.Fd()))
				}
				if fault == "partial-header-timeout" {
					_, _, err := sender.WriteMsgUnix(header[:2], syscall.UnixRights(int(duplicate.Fd())), nil)
					sent <- err
					return
				}
				if _, _, err := sender.WriteMsgUnix(header, rights, nil); err != nil {
					sent <- err
					return
				}
				// sendmsg on every fragment is observed, including ancillary
				// rights arriving after the initially valid length prefix.
				if fault == "late-rights" {
					rights = syscall.UnixRights(int(duplicate.Fd()))
				} else {
					rights = nil
				}
				_, _, err := sender.WriteMsgUnix(raw, rights, nil)
				sent <- err
			}()
			receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
			peer := uint32(os.Getpid())
			if fault == "wrong-pid" {
				peer++
			}
			var request desktopDarwinRequest
			file, readErr := desktopDarwinReceive(receiver, &request, peer, 0)
			if file != nil {
				file.Close()
			}
			if fault == "valid" || fault == "idle-then-valid" {
				if readErr != nil || request.Operation != "probe" {
					t.Fatal("valid fragmented control lost its peer", readErr)
				}
			} else if readErr == nil {
				t.Fatal("invalid control frame accepted", fault)
			}
			if fault == "partial-header-timeout" && errors.Is(readErr, desktopDarwinIdle) {
				t.Fatal("partially received Darwin frame was mistaken for an idle tick")
			}
			// The receiver may reject the header before the sender writes the
			// body. Closing the stream also retires queued SCM_RIGHTS records.
			receiver.Close()
			sender.Close()
			<-sent
			<-senderJoined
			replacement, err := net.ListenPacket("udp4", port)
			if err != nil {
				t.Fatal("rejected ancillary descriptor leaked its source port", err)
			}
			replacement.Close()
		})
	}
	output := desktopDarwinCommandBuffer{limit: 8}
	if n, err := output.Write([]byte("123456789")); n != 8 || err == nil || output.Len() != 8 {
		t.Fatal("privileged readback exceeded its in-memory bound", n, err, output.Len())
	}
}
