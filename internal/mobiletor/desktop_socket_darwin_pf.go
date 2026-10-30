//go:build darwin

package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// These are private implementation constants. Tagged native tests replace
// their own compiled copies with an owned anchor and a loopback-only scope;
// neither graph JSON, arguments nor the environment can select another PF
// namespace in the shipping command.
var desktopDarwinPFNamespace = "com.apple/000.router-vpn"
var desktopDarwinPFTestScope = ""

// The Darwin/BSD pfctl loader copies its complete -a path into the 64-byte
// pf_anchor.name before loading rules, even though the kernel path is larger.
// Keep both independently mutable anchors as short siblings. The generation
// name binds every original capture field, so reusing a NetworkID in another
// session cannot make an old cleanup target that session's leaf.
const desktopDarwinPFAnchorPathLimit = 63

func desktopDarwinPFSlot(c DesktopSocketCapture) string {
	return desktopDarwinPFNamespace + "/p" + c.SessionID
}

func desktopDarwinPFGeneration(c DesktopSocketCapture) string {
	digest := sha256.Sum256([]byte("router-vpn/darwin/pf-generation/v2\x00" + c.SessionID + "\x00" + c.SourceSHA256 + "\x00" + c.NetworkID))
	return desktopDarwinPFNamespace + "/g" + base64.RawURLEncoding.EncodeToString(digest[:24])
}

func desktopDarwinPFPointer(c DesktopSocketCapture) string {
	return fmt.Sprintf("anchor \"/%s\" out all\n", desktopDarwinPFGeneration(c))
}

func desktopDarwinPFLoadPointer(ctx context.Context, c DesktopSocketCapture) error {
	// pfctl's dry-run printer can shorten an absolute anchor to its leaf name.
	// Its display is not reloadable authority: load the original complete path,
	// then independently read the kernel's dispatch before granting any socket.
	return desktopDarwinPFLoad(ctx, desktopDarwinPFSlot(c), desktopDarwinPFPointer(c))
}

func desktopDarwinPFReadPointer(ctx context.Context, c DesktopSocketCapture) (string, error) {
	actual, err := desktopDarwinPFRead(ctx, desktopDarwinPFSlot(c))
	expected := strings.TrimSpace(desktopDarwinPFPointer(c))
	if err != nil || actual != expected {
		return actual, errors.Join(err, errors.New("Darwin PF slot changed its network owner or complete generation path"))
	}
	return actual, nil
}

type desktopDarwinPFPermit struct {
	Grant   DesktopSocketGrant
	Expires time.Time
}

// Only captured metadata crosses the private child channel. Actual permits,
// retained descriptors and monotonic deadlines remain in the guardian.
type desktopDarwinPF struct {
	Capture  DesktopSocketCapture
	UID      uint32
	Account  string
	Baseline string
	Slot     string
	Anchor   string
	Pointer  string
	Physical []desktopDarwinStateInterface
	permits  map[string]desktopDarwinPFPermit
	tunnel   string
	index    uint32
}

func desktopDarwinPFLabel(value string) string {
	return desktopPFLabel(value)
}

func desktopDarwinPFAllowedTag(c DesktopSocketCapture) string {
	return desktopDarwinPFLabel("allowed\x00" + c.SessionID + "\x00" + c.SourceSHA256)
}

func desktopDarwinPFBaseline(c DesktopSocketCapture, o DesktopDarwinSocketOptions) string {
	return desktopPFOwnedBaseline(c.SessionID, c.SourceSHA256, len(o.LANPrefixes) != 0, desktopDarwinPFTestScope)
}

func desktopDarwinPFCanonical(ctx context.Context, rules string) (string, error) {
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", []byte(rules), "-n", "-v", "-a", desktopDarwinPFNamespace, "-f", "-")
	if err != nil {
		return "", err
	}
	return desktopDarwinPFRulesText(raw), nil
}

func desktopDarwinPFRulesText(raw []byte) string {
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func desktopDarwinPFRead(ctx context.Context, anchor string) (string, error) {
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", anchor, "-s", "rules")
	if err != nil {
		return "", fmt.Errorf("Darwin PF readback for anchor %q: %w", anchor, err)
	}
	return desktopDarwinPFRulesText(raw), nil
}

func desktopDarwinPFLoad(ctx context.Context, anchor string, rules string) error {
	if anchor == "" || len(anchor) > desktopDarwinPFAnchorPathLimit {
		return errors.New("Darwin PF load path exceeds the native loader's captured anchor bound")
	}
	_, err := desktopDarwinCommand(ctx, "/sbin/pfctl", []byte(rules), "-a", anchor, "-f", "-")
	if err != nil {
		return fmt.Errorf("Darwin scoped PF load for anchor %q (%d input bytes): %w", anchor, len(rules), err)
	}
	return nil
}

var desktopDarwinPFAnchorName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func desktopDarwinPFRejectLegacyLayout(ctx context.Context) error {
	return desktopPFRejectLegacyRules(desktopDarwinPFNamespace+"/physical",
		func(anchor string) (string, error) { return desktopDarwinPFRead(ctx, anchor) },
		func(anchor string) ([]byte, error) {
			if anchor == "" {
				return desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "Anchors")
			}
			return desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", anchor, "-s", "Anchors")
		})
}

func desktopDarwinPFStatelessFilters(rules string) error {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "}" || strings.HasPrefix(line, "anchor ") || strings.HasPrefix(line, "block ") {
			continue
		}
		if !strings.HasPrefix(line, "pass ") || !strings.Contains(line, " no state") || strings.Contains(line, " keep state") || strings.Contains(line, " modulate state") || strings.Contains(line, " synproxy state") {
			return errors.New("Darwin protected physical path intersects a foreign stateful or unknown filter")
		}
	}
	return nil
}

func desktopDarwinPFNoTranslation(ctx context.Context, anchor string) error {
	arguments := []string{"-s", "nat"}
	if anchor != "" {
		arguments = append([]string{"-a", anchor}, arguments...)
	}
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, arguments...)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(desktopDarwinPFRulesText(raw), "\n") {
		if line == "" || line == "}" || strings.HasPrefix(line, "nat-anchor ") || strings.HasPrefix(line, "rdr-anchor ") || strings.HasPrefix(line, "binat-anchor ") {
			continue
		}
		// Translation can create a state even when a filter says no state.
		// Preserve the foreign owner and reject this currently unsupported
		// intersection before a physical descriptor receives permission.
		return errors.New("Darwin physical protection intersects an active foreign translation rule")
	}
	return nil
}

func desktopDarwinPFValidateSystemFilters(raw []byte) error {
	readback := desktopDarwinPFRulesText(raw)
	filters := readback
	// Stock macOS prints its normalization anchor before the filter anchor.
	// This exact fragment-reassembly dispatch does not admit a filter flow.
	// Only this single observed system prefix is separated; foreign children
	// still undergo complete filter/translation checks below, and an unknown
	// scrub action, earlier filter, duplicate prefix or changed dispatch fails.
	const scrub = "scrub-anchor \"com.apple/*\" all fragment reassemble\n"
	filters = strings.TrimPrefix(filters, scrub)
	if !strings.HasPrefix(filters+"\n", "anchor \"com.apple/*\" all\n") {
		if len(readback) > 4096 {
			readback = readback[:4096] + "[truncated]"
		}
		return fmt.Errorf("Darwin physical policy requires the captured system PF anchor dispatch; actual rules: %q", readback)
	}
	return desktopDarwinPFStatelessFilters(filters)
}

func desktopDarwinPFGlobal(ctx context.Context) error {
	// These independent inspections only read the kernel. Keep their original
	// shared deadline and every foreign-owner/state/translation check, but do
	// not spend that proof budget serially starting unrelated pfctl processes.
	// The bounded group joins every native command before returning an error.
	inspect := func(stage string, check func(context.Context) error) func(context.Context) error {
		return func(captured context.Context) error {
			if err := check(captured); err != nil {
				return fmt.Errorf("Darwin PF %s inspection: %w", stage, err)
			}
			return nil
		}
	}
	return desktopPFReadback(ctx,
		inspect("enablement", desktopDarwinPFEnabled),
		inspect("system dispatch", desktopDarwinPFSystemFilters),
		inspect("legacy inventory", desktopDarwinPFRejectLegacyLayout),
		inspect("owned translation", desktopDarwinPFOwnedTranslations),
		inspect("foreign roots", desktopDarwinPFForeignRoots),
		inspect("system children", desktopDarwinPFSystemChildren))
}

func desktopDarwinPFEnabled(ctx context.Context) error {
	info, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "info")
	if err != nil || !regexp.MustCompile(`(?m)^Status:\s+Enabled\b`).Match(info) {
		return errors.Join(err, errors.New("Darwin physical policy lost PF enablement"))
	}
	return nil
}

func desktopDarwinPFSystemFilters(ctx context.Context) error {
	global, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "rules")
	if err != nil {
		return errors.Join(err, errors.New("Darwin physical policy could not read the captured system PF anchor dispatch"))
	}
	return desktopDarwinPFValidateSystemFilters(global)
}

func desktopDarwinPFOwnedTranslations(ctx context.Context) error {
	// Translation outside or inside our filter namespace can create a state
	// ahead of the next packet's creator-UID check. Read every relevant root
	// as well as the complete owned subtree; filter ownership is not NAT ownership.
	for _, anchor := range []string{"", desktopDarwinPFNamespace, desktopDarwinPFNamespace + "/*"} {
		if err := desktopDarwinPFNoTranslation(ctx, anchor); err != nil {
			return err
		}
	}
	return nil
}

func desktopDarwinPFForeignRoots(ctx context.Context) error {
	roots, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "Anchors")
	if err != nil {
		return err
	}
	for _, root := range strings.Fields(string(roots)) {
		if root == "com.apple" {
			continue
		}
		if !desktopDarwinPFAnchorName.MatchString(root) {
			return errors.New("Darwin PF has an unknown root anchor identity")
		}
		for _, anchor := range []string{root, root + "/*"} {
			rules, err := desktopDarwinPFRead(ctx, anchor)
			if err != nil {
				return err
			}
			if err := desktopDarwinPFStatelessFilters(rules); err != nil {
				return err
			}
			if err := desktopDarwinPFNoTranslation(ctx, anchor); err != nil {
				return err
			}
		}
	}
	return nil
}

func desktopDarwinPFSystemChildren(ctx context.Context) error {
	anchors, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-a", "com.apple", "-s", "Anchors")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(anchors), "\n") {
		name := strings.TrimPrefix(strings.TrimSpace(line), "com.apple/")
		if name == "" || "com.apple/"+name == desktopDarwinPFNamespace {
			continue
		}
		if !desktopDarwinPFAnchorName.MatchString(name) {
			return errors.New("Darwin PF dispatch has an unknown anchor identity")
		}
		// Quick deny prevents a later foreign pass from admitting an unowned
		// packet; our nonquick permitted/tagged packets still reach foreign
		// blocks. Stateful foreign passes (in either direction) cannot be
		// accepted yet: a state can outlive both socket holders and bypass the
		// per-packet UID check. This is a bounded compatibility requirement,
		// not authority to rewrite or flush another filter owner.
		for _, anchor := range []string{"com.apple/" + name, "com.apple/" + name + "/*"} {
			rules, err := desktopDarwinPFRead(ctx, anchor)
			if err != nil || "com.apple/"+name < desktopDarwinPFNamespace && rules != "" {
				return errors.Join(err, errors.New("Darwin PF dispatch has an unreadable or earlier nonempty filter owner"))
			}
			if err := desktopDarwinPFStatelessFilters(rules); err != nil {
				return err
			}
			if err := desktopDarwinPFNoTranslation(ctx, anchor); err != nil {
				return err
			}
		}
	}
	return nil
}

func desktopDarwinValidatePFBaseline(ctx context.Context, capture DesktopSocketCapture, options DesktopDarwinSocketOptions) error {
	if !capture.valid() {
		return errors.New("Darwin PF baseline has no complete source")
	}
	if len(options.LANPrefixes) != 0 {
		want := map[string]bool{"10.0.0.0/8": true, "172.16.0.0/12": true, "192.168.0.0/16": true, "169.254.0.0/16": true, "fc00::/7": true, "fe80::/10": true}
		if len(options.LANPrefixes) != len(want) {
			return errors.New("Darwin PF baseline has another LAN policy")
		}
		for _, prefix := range options.LANPrefixes {
			if !want[prefix.String()] {
				return errors.New("Darwin PF baseline has another LAN prefix")
			}
			delete(want, prefix.String())
		}
	}
	if err := desktopDarwinPFGlobal(ctx); err != nil {
		return err
	}
	want, err := desktopDarwinPFCanonical(ctx, desktopDarwinPFBaseline(capture, options))
	if err != nil || want == "" {
		return errors.Join(err, errors.New("Darwin PF baseline did not compile"))
	}
	actual, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace)
	if err != nil || actual != want {
		return errors.Join(err, errors.New("Darwin PF baseline is not the exact captured deny policy"))
	}
	return nil
}

func desktopDarwinNewPF(capture DesktopSocketCapture, uid uint32, account string, options DesktopDarwinSocketOptions) (*desktopDarwinPF, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := desktopDarwinValidatePFBaseline(ctx, capture, options); err != nil {
		return nil, err
	}
	baseline, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace)
	if err != nil {
		return nil, err
	}
	p := &desktopDarwinPF{Capture: capture, UID: uid, Account: account, Baseline: baseline,
		Slot:    desktopDarwinPFSlot(capture),
		permits: make(map[string]desktopDarwinPFPermit)}
	p.Anchor = desktopDarwinPFGeneration(capture)
	p.Physical, err = desktopDarwinCaptureStateInterfaces()
	if err != nil {
		return nil, err
	}
	if err := desktopDarwinRetirePhysicalStates(ctx, p.Physical); err != nil {
		return nil, err
	}
	p.Pointer = strings.TrimSpace(desktopDarwinPFPointer(capture))
	existing, err := desktopDarwinPFRead(ctx, p.Slot)
	if err != nil || existing != "" {
		return nil, errors.Join(err, errors.New("Darwin physical slot still belongs to another network generation"))
	}
	existing, err = desktopDarwinPFRead(ctx, p.Anchor)
	if err != nil || existing != "" {
		return nil, errors.Join(err, errors.New("Darwin physical anchor already has an owner"))
	}
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return p, err
	}
	if err := desktopDarwinPFLoadPointer(ctx, capture); err != nil {
		return p, err
	}
	return p, p.verify(ctx, true)
}

func (p *desktopDarwinPF) valid() bool {
	return p != nil && p.Capture.valid() && p.UID >= 0x40000000 && p.UID < 0x80000000 &&
		p.Slot == desktopDarwinPFSlot(p.Capture) && p.Anchor == desktopDarwinPFGeneration(p.Capture) &&
		len(p.Slot) <= desktopDarwinPFAnchorPathLimit && len(p.Anchor) <= desktopDarwinPFAnchorPathLimit &&
		p.Baseline != "" && p.Pointer == strings.TrimSpace(desktopDarwinPFPointer(p.Capture)) &&
		strings.HasPrefix(p.Account, "_rvpnt_") && desktopSocketHex(strings.TrimPrefix(p.Account, "_rvpnt_"), 20)
}

func (p *desktopDarwinPF) verify(ctx context.Context, complete bool) error {
	if !p.valid() {
		return errors.New("Darwin PF readback has another captured owner")
	}
	if err := desktopDarwinPFGlobal(ctx); err != nil {
		return err
	}
	if err := desktopDarwinCheckPhysicalStates(ctx, p.Physical); err != nil {
		return err
	}
	baseline, err := desktopDarwinPFRead(ctx, desktopDarwinPFNamespace)
	if err != nil || baseline != p.Baseline {
		return errors.Join(err, errors.New("Darwin PF baseline changed its captured rules"))
	}
	pointer, err := desktopDarwinPFReadPointer(ctx, p.Capture)
	if err != nil || pointer != p.Pointer {
		return errors.Join(err, errors.New("Darwin PF slot changed its network owner"))
	}
	actual, err := desktopDarwinPFRead(ctx, p.Anchor)
	if err != nil {
		return err
	}
	if complete && p.permits != nil {
		want, err := desktopDarwinPFCanonical(ctx, p.render())
		if err != nil || actual != want {
			return errors.Join(err, errors.New("Darwin physical permits differ from their complete captured tuples"))
		}
	}
	return nil
}

func (p *desktopDarwinPF) permitLabel(g DesktopSocketGrant) string {
	return desktopDarwinPFLabel(fmt.Sprintf("permit\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s\x00%s\x00%d", p.Capture.SessionID, p.Capture.SourceSHA256, p.Capture.NetworkID, p.UID, g.SocketID, g.Network, g.Local.String()+"/"+g.Remote.String(), g.Sequence))
}

func (p *desktopDarwinPF) key(g DesktopSocketGrant) string {
	return g.SocketID + "/" + g.Remote.String()
}

func (p *desktopDarwinPF) render() string {
	var lines []string
	keys := make([]string, 0, len(p.permits))
	for key := range p.permits {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := p.permits[key].Grant
		family, flags := "inet6", ""
		if g.Local.Addr().Is4() {
			family = "inet"
		}
		if g.Network == "tcp" {
			flags = " flags any"
		}
		lines = append(lines, fmt.Sprintf("pass out on %s %s proto %s from %s port %d to %s port %d user %d%s tag \"%s\" no state label \"%s\"",
			g.Binding.InterfaceName, family, g.Network, g.Local.Addr(), g.Local.Port(), g.Remote.Addr(), g.Remote.Port(), p.UID, flags, desktopDarwinPFAllowedTag(p.Capture), p.permitLabel(g)))
	}
	if p.tunnel != "" {
		lines = append(lines, "pass out on "+p.tunnel+" all tag \""+desktopDarwinPFAllowedTag(p.Capture)+"\" no state label \""+desktopDarwinPFLabel("tunnel\x00"+p.Capture.NetworkID+"\x00"+p.tunnel+"\x00"+strconv.FormatUint(uint64(p.index), 10))+"\"")
	}
	if desktopDarwinPFTestScope != "" {
		lines = append(lines, "block drop out quick "+desktopDarwinPFTestScope+" ! tagged \""+desktopDarwinPFAllowedTag(p.Capture)+"\"")
	}
	return strings.Join(lines, "\n") + "\n"
}

func (p *desktopDarwinPF) grant(ctx context.Context, g DesktopSocketGrant) (DesktopSocketReceipt, error) {
	started := time.Now()
	if !p.valid() || p.permits == nil || g.Capture != p.Capture || g.Local.Port() == 0 || g.Remote.Port() == 0 || g.Binding.InterfaceIndex == 0 || !desktopDarwinInterfaceName.MatchString(g.Binding.InterfaceName) {
		return DesktopSocketReceipt{}, errors.New("Darwin PF grant has no independently retained owner")
	}
	if err := p.verify(ctx, true); err != nil {
		return DesktopSocketReceipt{}, err
	}
	p.permits[p.key(g)] = desktopDarwinPFPermit{Grant: g, Expires: started.Add(7 * time.Second)}
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return DesktopSocketReceipt{}, err
	}
	if err := p.verify(ctx, true); err != nil {
		return DesktopSocketReceipt{}, err
	}
	if ctx.Err() != nil || !time.Now().Before(started.Add(5*time.Second)) {
		return DesktopSocketReceipt{}, errors.New("Darwin PF grant readback became stale")
	}
	return DesktopSocketReceipt{Grant: g, ObservedAt: time.Now().UnixMilli(), ExpiresAt: started.Add(7 * time.Second).UnixMilli()}, nil
}

func (p *desktopDarwinPF) expire(ctx context.Context) error {
	if p.permits == nil {
		return nil
	}
	changed := false
	for key, permit := range p.permits {
		if !time.Now().Before(permit.Expires) {
			delete(p.permits, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := p.verify(ctx, false); err != nil {
		return err
	}
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return err
	}
	return p.verify(ctx, true)
}

func (p *desktopDarwinPF) absent(ctx context.Context, g DesktopSocketGrant) error {
	if !p.valid() || g.Capture != p.Capture {
		return errors.New("Darwin PF absent readback changed ownership")
	}
	actual, err := desktopDarwinPFRead(ctx, p.Anchor)
	if err != nil || strings.Contains(actual, `label "`+p.permitLabel(g)+`"`) {
		return errors.Join(err, errors.New("Darwin physical permit is still present"))
	}
	return nil
}

func (p *desktopDarwinPF) revoke(ctx context.Context, g DesktopSocketGrant) error {
	if !p.valid() || g.Capture != p.Capture {
		return errors.New("Darwin physical retirement changed ownership")
	}
	if p.permits == nil {
		// Only the native policy's actual guardian-joined path uses this copy.
		// The entire network generation is retired, never a replacement slot.
		return p.close(ctx)
	}
	if err := p.verify(ctx, true); err != nil {
		return err
	}
	key := p.key(g)
	if permit, found := p.permits[key]; found && permit.Grant != g {
		return errors.New("Darwin PF retirement belongs to another tuple sequence")
	}
	delete(p.permits, key)
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return err
	}
	return p.absent(ctx, g)
}

func (p *desktopDarwinPF) allAbsent(ctx context.Context) error {
	if !p.valid() {
		return errors.New("Darwin PF final absence has no captured owner")
	}
	actual, err := desktopDarwinPFRead(ctx, p.Anchor)
	if err != nil || actual != "" {
		return errors.Join(err, errors.New("Darwin physical generation still has retained filter rules"))
	}
	return nil
}

func (p *desktopDarwinPF) close(ctx context.Context) error {
	if !p.valid() {
		return errors.New("Darwin PF cleanup has no captured source")
	}
	// The leaf binds the full session, source and fresh network nonce. A
	// replacement may change the slot, but cannot acquire this old leaf's identity. Never clear or
	// rewrite that replacement slot or the household/system PF ruleset.
	if err := desktopDarwinPFLoad(ctx, p.Anchor, "\n"); err != nil {
		return err
	}
	if err := p.allAbsent(ctx); err != nil {
		return err
	}
	pointer, err := desktopDarwinPFRead(ctx, p.Slot)
	if err != nil {
		return err
	}
	if pointer == p.Pointer {
		if err := desktopDarwinPFLoad(ctx, p.Slot, "\n"); err != nil {
			return err
		}
		pointer, err = desktopDarwinPFRead(ctx, p.Slot)
		if err != nil || pointer != "" {
			return errors.Join(err, errors.New("Darwin physical slot did not retire"))
		}
	}
	clear(p.permits)
	p.tunnel, p.index = "", 0
	return nil
}

func (p *desktopDarwinPF) bindTunnel(ctx context.Context, name string, index uint32) error {
	if p.tunnel != "" || p.index != 0 || !regexp.MustCompile(`^utun[0-9]+$`).MatchString(name) || index == 0 {
		return errors.New("Darwin physical tunnel has another retained control owner")
	}
	actual, err := net.InterfaceByIndex(int(index))
	if err != nil || actual.Name != name || actual.Flags&net.FlagUp == 0 {
		return errors.New("Darwin physical tunnel changed its kernel interface")
	}
	if err := p.verify(ctx, true); err != nil {
		return err
	}
	p.tunnel, p.index = name, index
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return err
	}
	return p.verify(ctx, true)
}

func (p *desktopDarwinPF) retireTunnel(ctx context.Context, name string, index uint32) error {
	if p.tunnel != name || p.index != index || name == "" || index == 0 {
		return errors.New("Darwin physical tunnel retirement belongs to another reader")
	}
	if err := p.verify(ctx, true); err != nil {
		return err
	}
	p.tunnel, p.index = "", 0
	if err := desktopDarwinPFLoad(ctx, p.Anchor, p.render()); err != nil {
		return err
	}
	return p.verify(ctx, true)
}
