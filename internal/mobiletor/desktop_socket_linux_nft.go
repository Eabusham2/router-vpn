//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type desktopLinuxNFT struct {
	tupleNetlink      *desktopLinuxBaselineNetlink // Held only by the creating guardian; never serialized.
	HostProtectionOff bool                         `json:",omitempty"`
	DenyHandle        uint64                       `json:",omitempty"`
	Capture           DesktopSocketCapture
	TableName         string `json:",omitempty"`
	UID               uint32
	Prefix            string
	TableHandle       uint64
	ChainHandle       uint64
	Rules             map[string]uint64
	Sets              map[string]uint64
	Baseline          map[uint64]any
}

func desktopLinuxSetNormalized(value any) any {
	switch value := value.(type) {
	case []any:
		result := make([]any, len(value))
		for i, item := range value {
			result[i] = desktopLinuxSetNormalized(item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			result[key] = desktopLinuxSetNormalized(item)
		}
		if set, ok := result["set"].([]any); ok {
			sort.Slice(set, func(i, j int) bool {
				a, _ := json.Marshal(set[i])
				b, _ := json.Marshal(set[j])
				return string(a) < string(b)
			})
		}
		return result
	default:
		return value
	}
}

func desktopLinuxBaselineExpressions(options DesktopLinuxSocketOptions) []any {
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	meta := func(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	accept := map[string]any{"accept": nil}
	expected := []any{
		[]any{match(meta("oifname"), "lo"), accept},
		[]any{match(meta("oifname"), map[string]any{"set": []any{"wg", "awg", "router-vpn"}}), accept},
		[]any{match(payload("ip", "protocol"), float64(17)), match(payload("udp", "sport"), float64(68)), match(payload("udp", "dport"), float64(67)), accept},
		[]any{match(payload("ip6", "nexthdr"), float64(58)), match(payload("icmpv6", "type"), map[string]any{"set": []any{float64(133), float64(134), float64(135), float64(136)}}), accept},
	}
	for _, ipv4 := range []bool{true, false} {
		var values []any
		family := "ip6"
		if ipv4 {
			family = "ip"
		}
		for _, prefix := range options.LANPrefixes {
			if prefix.Addr().Is4() == ipv4 {
				values = append(values, map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": float64(prefix.Bits())}})
			}
		}
		if len(values) > 0 {
			expected = append(expected, []any{match(payload(family, "daddr"), map[string]any{"set": values}), accept})
		}
	}
	return expected
}

func (n *desktopLinuxNFT) captureBaseline(rows []map[string]any, options DesktopLinuxSocketOptions) error {
	expected := desktopLinuxBaselineExpressions(options)
	found := make(map[int]bool)
	for _, row := range rows {
		rule, ok := row["rule"].(map[string]any)
		if !ok {
			continue
		}
		handle := desktopLinuxNumber(rule["handle"])
		if handle == 0 || rule["family"] != "inet" || rule["table"] != n.table() || rule["chain"] != "output" {
			return errors.New("Linux physical baseline has an unrelated rule")
		}
		matched := -1
		for index, expressions := range expected {
			if reflect.DeepEqual(desktopLinuxSetNormalized(rule["expr"]), desktopLinuxSetNormalized(expressions)) {
				matched = index
				break
			}
		}
		if matched < 0 || found[matched] {
			return errors.New("Linux physical baseline contains an unselected output exemption")
		}
		found[matched] = true
		n.Baseline[handle] = rule["expr"]
	}
	if len(found) != len(expected) {
		return errors.New("Linux physical baseline lacks its complete captured policy")
	}
	return nil
}

func desktopLinuxNFTCommand(ctx context.Context, args []string, input string) ([]byte, error) {
	return desktopLinuxNFTCommandFiles(ctx, args, input, nil)
}

func desktopLinuxNFTCommandFiles(ctx context.Context, args []string, input string, files []*os.File) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, netClosedError()
	}
	info, err := os.Stat("/usr/sbin/nft")
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("nftables executable is not root owned")
	}
	command := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input)
	command.ExtraFiles = files
	var output, diagnostic bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	err = command.Run()
	if output.Len() > 2<<20 || diagnostic.Len() > 64<<10 {
		return nil, errors.New("nftables readback exceeded its bound")
	}
	if err != nil {
		return nil, fmt.Errorf("owned physical nftables operation failed: %w", err)
	}
	return output.Bytes(), nil
}

func netClosedError() error { return errors.New("Linux physical control deadline expired") }

func desktopLinuxNFTRows(raw []byte) ([]map[string]any, error) {
	var value struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value.NFTables == nil {
		return nil, errors.New("missing nftables readback")
	}
	return value.NFTables, nil
}

func desktopLinuxNFTReadTable(ctx context.Context, tableName string) ([]map[string]any, error) {
	if tableName != desktopLinuxNFTTable && !desktopLinuxOwnedTableName(tableName) {
		return nil, errors.New("Linux physical readback rejected an unowned table name")
	}
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "table", "inet", tableName}, "")
	if err == nil {
		rows, readErr := desktopLinuxNFTRows(raw)
		if readErr != nil || len(rows) == 0 {
			return nil, errors.Join(readErr, errors.New("Linux physical table listing has no kernel objects"))
		}
		return rows, nil
	}
	// A command error alone is never proof of absence. Independently enumerate
	// tables, and only accept an actual list that does not contain this table.
	raw, listErr := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
	if listErr != nil {
		return nil, errors.Join(err, listErr)
	}
	rows, listErr := desktopLinuxNFTRows(raw)
	if listErr != nil {
		return nil, listErr
	}
	if err := desktopLinuxTableListAbsent(rows, func(name string) bool { return name == tableName }); err != nil {
		return nil, err
	}
	return nil, nil
}

func (n *desktopLinuxNFT) table() string {
	if n.TableName == "" {
		return desktopLinuxNFTTable
	}
	return n.TableName
}

func desktopLinuxNFTForCapture(c DesktopSocketCapture, node bool) *desktopLinuxNFT {
	n := &desktopLinuxNFT{Capture: c, Baseline: make(map[uint64]any)}
	if node {
		n.TableName = desktopLinuxNodeTable(c)
	}
	return n
}

func desktopLinuxNumber(v any) uint64 {
	n, ok := v.(float64)
	if !ok || n <= 0 || n != float64(uint64(n)) {
		return 0
	}
	return uint64(n)
}

func desktopLinuxNFTTableActive(table map[string]any) bool {
	flags, present := table["flags"]
	if !present {
		return true
	}
	values, ok := flags.([]any)
	return ok && len(values) == 0
}

func (n *desktopLinuxNFT) captureChain(ctx context.Context, options DesktopLinuxSocketOptions) error {
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return err
	}
	for _, row := range rows {
		if table, ok := row["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == n.table() {
			if !desktopLinuxNFTTableActive(table) {
				return errors.New("Linux physical baseline table is inactive or has unselected flags")
			}
			n.TableHandle = desktopLinuxNumber(table["handle"])
		}
		if chain, ok := row["chain"].(map[string]any); ok && chain["family"] == "inet" && chain["table"] == n.table() && chain["name"] == "output" && chain["type"] == "filter" && chain["hook"] == "output" && chain["policy"] == n.chainPolicy() && chain["prio"] == float64(-310) && chain["comment"] == "routervpn-owned-baseline:"+n.Capture.SessionID+":"+n.Capture.SourceSHA256 {
			n.ChainHandle = desktopLinuxNumber(chain["handle"])
		}
	}
	if n.TableHandle == 0 || n.ChainHandle == 0 {
		return errors.New("Linux owned physical policy requires its already installed fail-closed output chain")
	}
	return n.captureBaseline(rows, options)
}

func desktopLinuxValidateNFTBaseline(ctx context.Context, c DesktopSocketCapture, options DesktopLinuxSocketOptions, node bool) error {
	n := desktopLinuxNFTForCapture(c, node)
	n.HostProtectionOff = options.HostProtectionOff
	if n.HostProtectionOff && !node {
		return errors.New("nonblocking baseline requires a Node owner")
	}
	return n.captureChain(ctx, options)
}

func desktopLinuxNewNFT(c DesktopSocketCapture, uid uint32, options DesktopLinuxSocketOptions, node bool) (*desktopLinuxNFT, error) {
	var nonce [10]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	n := desktopLinuxNFTForCapture(c, node)
	n.HostProtectionOff = options.HostProtectionOff
	if n.HostProtectionOff && !node {
		return nil, errors.New("nonblocking baseline requires a Node owner")
	}
	n.UID, n.Prefix, n.Rules, n.Sets = uid, "rvpn_"+hex.EncodeToString(nonce[:]), make(map[string]uint64), make(map[string]uint64)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var err error
	n.tupleNetlink, err = desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return n, err
	}
	before, err := n.tupleNetlink.generation(ctx)
	if err != nil {
		return n, err
	}
	if err := n.captureChain(ctx, options); err != nil {
		return n, err
	}
	var script strings.Builder
	// Insert the exact isolated UID deny first, then insert its expiring
	// tuple permits ahead of it in the same atomic transaction. Ordinary
	// host traffic keeps the selected accept policy; this UID never does.
	if n.HostProtectionOff {
		fmt.Fprintf(&script, "insert rule inet %s output meta skuid %d drop comment %s\n", n.table(), uid, strconv.Quote(n.comment("deny")))
	}
	for _, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		network, family := kind[:3], "ip"
		if kind[3] == '6' {
			family = "ip6"
		}
		name := n.Prefix + "_" + kind
		fmt.Fprintf(&script, "create set inet %s %s { typeof meta oif . %s saddr . %s sport . %s daddr . %s dport; flags timeout; timeout 9s; size 4096; }\n", n.table(), name, family, network, family, network)
		fmt.Fprintf(&script, "insert rule inet %s output meta skuid %d meta l4proto %s meta oif . %s saddr . %s sport . %s daddr . %s dport @%s accept comment %s\n", n.table(), uid, network, family, network, family, network, name, strconv.Quote(n.comment(kind)))
	}
	if _, err := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, script.String()); err != nil {
		return n, err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return n, err
	}
	// Accept the handles only from our one exclusive batch. An intervening
	// generation (including a same-name replacement) leaves no child authority.
	after, err := n.tupleNetlink.generation(ctx)
	if err != nil || after != desktopLinuxNextGeneration(before) {
		return n, errors.Join(err, errors.New("Linux physical creation changed before original child handles were captured"))
	}
	for _, row := range rows {
		if set, ok := row["set"].(map[string]any); ok {
			for _, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
				if set["name"] == n.Prefix+"_"+kind {
					n.Sets[kind] = desktopLinuxNumber(set["handle"])
				}
			}
		}
		if rule, ok := row["rule"].(map[string]any); ok {
			if n.HostProtectionOff && rule["comment"] == n.comment("deny") {
				if n.DenyHandle != 0 {
					return n, errors.New("duplicate original UID deny")
				}
				n.DenyHandle = desktopLinuxNumber(rule["handle"])
			}
			for _, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
				if rule["comment"] == n.comment(kind) {
					n.Rules[kind] = desktopLinuxNumber(rule["handle"])
				}
			}
		}
	}
	if err = n.verifyRows(rows, true); err != nil {
		return n, err
	}
	return n, nil
}

func (n *desktopLinuxNFT) comment(kind string) string {
	return "routervpn-owned:" + n.Capture.SessionID + ":" + n.Prefix + ":" + kind
}

func (n *desktopLinuxNFT) ruleExpressions(kind string) any {
	network, family := kind[:3], "ip"
	if kind[3] == '6' {
		family = "ip6"
	}
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	return []any{match(map[string]any{"meta": map[string]any{"key": "skuid"}}, float64(n.UID)), match(map[string]any{"concat": []any{map[string]any{"meta": map[string]any{"key": "oif"}}, payload(family, "saddr"), payload(network, "sport"), payload(family, "daddr"), payload(network, "dport")}}, "@"+n.Prefix+"_"+kind), map[string]any{"accept": nil}}
}

func (n *desktopLinuxNFT) verifyRows(rows []map[string]any, required bool) error {
	if n == nil || !desktopLinuxTableValid(n.Capture, n.TableName) || n.UID == 0 || len(n.Prefix) != 25 || !strings.HasPrefix(n.Prefix, "rvpn_") {
		return errors.New("Linux physical nft identity is malformed")
	}
	if err := n.verifyOffDeny(rows, required); err != nil {
		return err
	}
	tableOK, chainOK := false, false
	foundRules, foundSets := make(map[string]bool), make(map[string]bool)
	baselineFound := make(map[uint64]bool)
	for _, row := range rows {
		if table, ok := row["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == n.table() {
			tableOK = desktopLinuxNumber(table["handle"]) == n.TableHandle && desktopLinuxNFTTableActive(table)
		}
		if chain, ok := row["chain"].(map[string]any); ok && chain["name"] == "output" {
			chainOK = chain["family"] == "inet" && chain["table"] == n.table() && desktopLinuxNumber(chain["handle"]) == n.ChainHandle && chain["policy"] == n.chainPolicy() && chain["type"] == "filter" && chain["hook"] == "output" && chain["prio"] == float64(-310) && chain["comment"] == "routervpn-owned-baseline:"+n.Capture.SessionID+":"+n.Capture.SourceSHA256
		}
		if rule, ok := row["rule"].(map[string]any); ok && required {
			comment, _ := rule["comment"].(string)
			owned := n.HostProtectionOff && comment == n.comment("deny")
			for _, transport := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
				owned = owned || comment == n.comment(transport)
			}
			if !owned {
				handle := desktopLinuxNumber(rule["handle"])
				expected, found := n.Baseline[handle]
				if !found || baselineFound[handle] || rule["family"] != "inet" || rule["table"] != n.table() || rule["chain"] != "output" || !reflect.DeepEqual(rule["expr"], expected) {
					return errors.New("Linux fail-closed baseline gained or changed an output exemption")
				}
				baselineFound[handle] = true
			}
		}
		for _, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			if rule, ok := row["rule"].(map[string]any); ok && rule["comment"] == n.comment(kind) {
				if foundRules[kind] || rule["family"] != "inet" || rule["table"] != n.table() || rule["chain"] != "output" || n.Rules[kind] == 0 || desktopLinuxNumber(rule["handle"]) != n.Rules[kind] || !reflect.DeepEqual(rule["expr"], n.ruleExpressions(kind)) {
					return errors.New("Linux physical rule lost exact UID/interface/tuple ownership")
				}
				foundRules[kind] = true
			}
			if set, ok := row["set"].(map[string]any); ok && set["name"] == n.Prefix+"_"+kind {
				addressType := "ipv4_addr"
				if kind[3] == '6' {
					addressType = "ipv6_addr"
				}
				if foundSets[kind] || set["family"] != "inet" || set["table"] != n.table() || n.Sets[kind] == 0 || desktopLinuxNumber(set["handle"]) != n.Sets[kind] || !reflect.DeepEqual(set["type"], []any{"iface_index", addressType, "inet_service", addressType, "inet_service"}) || !reflect.DeepEqual(set["flags"], []any{"timeout"}) || set["timeout"] != float64(9) || set["size"] != float64(4096) {
					return errors.New("Linux physical tuple set lost its exact timed bound")
				}
				foundSets[kind] = true
			}
		}
	}
	if required && (!tableOK || !chainOK || len(foundRules) != 4 || len(foundSets) != 4 || len(baselineFound) != len(n.Baseline)) {
		return errors.New("Linux physical fail-closed policy disappeared or was replaced")
	}
	return nil
}

func (n *desktopLinuxNFT) verify(ctx context.Context, required bool) error {
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return err
	}
	return n.verifyRows(rows, required)
}

func (n *desktopLinuxNFT) kind(g DesktopSocketGrant) string {
	family := "6"
	if g.Local.Addr().Is4() {
		family = "4"
	}
	return g.Network + family
}

func (n *desktopLinuxNFT) findElement(rows []map[string]any, g DesktopSocketGrant) (map[string]any, bool, error) {
	if g.Capture != n.Capture || g.Network != "tcp" && g.Network != "udp" || !g.Local.IsValid() || !g.Remote.IsValid() || g.Local.Port() == 0 || g.Remote.Port() == 0 || g.Local.Addr().Is4() != g.Remote.Addr().Is4() {
		return nil, false, errors.New("Linux nft tuple is invalid")
	}
	if err := n.verifyRows(rows, false); err != nil {
		return nil, false, err
	}
	want := []any{g.Binding.InterfaceName, g.Local.Addr().String(), float64(g.Local.Port()), g.Remote.Addr().String(), float64(g.Remote.Port())}
	for _, row := range rows {
		set, _ := row["set"].(map[string]any)
		if set["name"] != n.Prefix+"_"+n.kind(g) {
			continue
		}
		elements, _ := set["elem"].([]any)
		for _, raw := range elements {
			outer, _ := raw.(map[string]any)
			element, _ := outer["elem"].(map[string]any)
			value, _ := element["val"].(map[string]any)
			if reflect.DeepEqual(value["concat"], want) {
				return element, true, nil
			}
		}
	}
	return nil, false, nil
}

// Each guardian serializes mutations for its original socket. An empty tuple
// is created exclusively. Renewal replaces only the previous observed socket
// and sequence in one atomic transaction; expiration between read and delete
// rejects that transaction without installing a fresh permit.
func (n *desktopLinuxNFT) installElement(ctx context.Context, grant, previous DesktopSocketGrant, seconds int64, comment string, control *DesktopSocketGrant) error {
	started := time.Now()
	rows, generation, err := n.tupleRows(ctx)
	if err != nil {
		return err
	}
	parent := ""
	if control != nil {
		parent = control.SocketID
		controlUntil, err := n.socksControlExpiry(rows, *control, started)
		deadline, bounded := ctx.Deadline()
		if err != nil || !bounded || deadline.Add(time.Duration(seconds)*time.Second).After(controlUntil) {
			return errors.Join(err, errors.New("Linux UDP permit lost its original TCP control before mutation"))
		}
	}
	element, found, err := n.findElement(rows, grant)
	if err != nil {
		return err
	}
	if found {
		old := grant
		old.Sequence = previous.Sequence
		if previous != old || previous.Sequence == 0 || previous.Sequence >= grant.Sequence || !desktopLinuxElementOwned(element, previous, parent, true) {
			return errors.New("Linux physical tuple renewal lost its original socket and sequence")
		}
	}
	return n.mutateElement(ctx, grant, generation, found, seconds, comment)
}

func desktopLinuxElementOwned(element map[string]any, grant DesktopSocketGrant, parent string, renewal bool) bool {
	comment, ok := element["comment"].(string)
	parts := strings.Split(comment, ":")
	if !ok || len(parts) != 2 && len(parts) != 5 || parts[0] != grant.SocketID {
		return false
	}
	seq, ok := desktopLinuxRunningSequence(parts[1])
	if !ok || seq > grant.Sequence || renewal && seq != grant.Sequence {
		return false
	}
	if len(parts) == 2 {
		return !renewal || parent == ""
	}
	_, ok = desktopLinuxRunningSequence(parts[4])
	return ok && parts[2] == "socks" && desktopSocketHex(parts[3], 32) && (!renewal || parent == parts[3])
}

func (n *desktopLinuxNFT) grant(ctx context.Context, g, previous DesktopSocketGrant) (DesktopSocketReceipt, error) {
	started := time.Now()
	comment := g.SocketID + ":" + strconv.FormatUint(g.Sequence, 10)
	if err := n.installElement(ctx, g, previous, 9, comment, nil); err != nil {
		return DesktopSocketReceipt{}, err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	if err = n.verifyRows(rows, true); err != nil {
		return DesktopSocketReceipt{}, err
	}
	element, found, err := n.findElement(rows, g)
	if err != nil || !found || element["comment"] != comment || (element["timeout"] != nil && element["timeout"] != float64(9)) || desktopLinuxNumber(element["expires"]) < 7 || time.Since(started) >= 2*time.Second {
		return DesktopSocketReceipt{}, errors.Join(err, fmt.Errorf("Linux exact kernel permit did not read back with bounded expiry (found=%t element=%v elapsed=%s)", found, element, time.Since(started)))
	}
	return DesktopSocketReceipt{Grant: g, ObservedAt: time.Now().UnixMilli(), ExpiresAt: started.Add(7 * time.Second).UnixMilli()}, nil
}

func (n *desktopLinuxNFT) absent(ctx context.Context, g DesktopSocketGrant) error {
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return err
	}
	_, found, err := n.findElement(rows, g)
	if err != nil {
		return err
	}
	if found {
		return errors.New("Linux physical permit remains in the kernel")
	}
	return nil
}

func (n *desktopLinuxNFT) revoke(ctx context.Context, g DesktopSocketGrant) error {
	element, found, generation, err := n.observeElement(ctx, g)
	if err != nil || !found {
		return err
	}

	// The immediately preceding sequence can remain when an atomic renewal
	// was refused. Only a tuple stamped by the same still-owned socket may be
	// revoked. A concurrent natural expiry is accepted by independent absence.
	if !desktopLinuxElementOwned(element, g, "", false) {
		return errors.New("Linux physical revocation found a different tuple owner")
	}
	removal := n.mutateElement(ctx, g, generation, true, 0, "")
	_, remains, _, observed := n.observeElement(ctx, g)
	if observed != nil || remains {
		return errors.Join(removal, observed, errors.New("Linux original physical permit was not proved absent"))
	}
	return nil
}

func (n *desktopLinuxNFT) allAbsent(ctx context.Context) error {
	return n.allAbsentKeepingOffDeny(ctx, false)
}

func (n *desktopLinuxNFT) allAbsentKeepingOffDeny(ctx context.Context, keep bool) error {
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return err
	}
	return n.childrenAbsent(rows, keep)
}

func (n *desktopLinuxNFT) childrenAbsent(rows []map[string]any, keep bool) error {
	children, err := n.retiringChildren(rows, keep)
	if err != nil {
		return err
	}
	if len(children) != 0 {
		return errors.New("Linux original socket policy still has unretired rules or sets")
	}
	return nil
}

type desktopLinuxNFTChild struct {
	kind   uint16
	name   string
	handle uint64
}

func (n *desktopLinuxNFT) retiringChildren(rows []map[string]any, keep bool) ([]desktopLinuxNFTChild, error) {
	if keep && !n.HostProtectionOff {
		return nil, errors.New("unselected Linux UID deny retention")
	}
	// A missing table is established by an independent table enumeration.
	if len(rows) == 0 && !keep {
		return nil, nil
	}
	if n.TableHandle == 0 || n.ChainHandle == 0 {
		return nil, errors.New("Linux socket cleanup has no original table and output chain")
	}
	if err := n.verifyRows(rows, false); err != nil {
		return nil, err
	}
	// Missing original children are permitted. Replacements, unrecognized
	// objects and nonempty sets (including foreign tuples) block the batch.
	if err := desktopLinuxInspectProtectionInventory(n, rows, true, true); err != nil {
		return nil, err
	}
	if keep {
		if err := n.verifyOffDeny(rows, true); err != nil {
			return nil, err
		}
	}
	var rules, sets []desktopLinuxNFTChild
	for _, row := range rows {
		if rule, ok := row["rule"].(map[string]any); ok {
			handle := desktopLinuxNumber(rule["handle"])
			if _, baseline := n.Baseline[handle]; !baseline && !(keep && handle == n.DenyHandle) {
				rules = append(rules, desktopLinuxNFTChild{desktopLinuxNFTDeleteRule, "output", handle})
			}
		}
		if set, ok := row["set"].(map[string]any); ok {
			sets = append(sets, desktopLinuxNFTChild{desktopLinuxNFTDeleteSet, set["name"].(string), desktopLinuxNumber(set["handle"])})
		}
	}
	// Detach every original reference before retiring its empty set.
	return append(rules, sets...), nil
}

func (n *desktopLinuxNFT) close(ctx context.Context) error {
	return n.closeKeepingOffDeny(ctx, false)
}

func (n *desktopLinuxNFT) closeKeepingOffDeny(ctx context.Context, keep bool) error {
	if n.tupleNetlink == nil {
		// The parent receives comparison data over the original guardian
		// channel. Once joined, it can witness absence but cannot send.
		return n.allAbsentKeepingOffDeny(ctx, keep)
	}
	rows, generation, err := n.observedRows(ctx)
	if err != nil {
		return err
	}
	children, err := n.retiringChildren(rows, keep)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		if err = n.retireChildren(ctx, generation, children); err != nil {
			return err
		}
		// Re-read the exact terminal inventory even after kernel commit.
		rows, _, err = n.observedRows(ctx)
		if err != nil {
			return err
		}
	}
	if err = n.childrenAbsent(rows, keep); err != nil {
		return err
	}
	return n.tupleNetlink.close()
}
