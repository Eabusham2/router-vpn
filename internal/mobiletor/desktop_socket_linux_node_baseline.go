//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"time"
)

// DesktopLinuxNodeBaseline retains the original creator of one per-session
// deny table. It cannot be reconstructed from a protection/journal record.
// Its kernel operations do not establish child-process or journal authority:
// the authenticated parent must join the original engine before retirement,
// and durably record an intent before calling Release or Supersede.
// Close joins descriptors only, retaining any remaining fail-closed policy.
type DesktopLinuxNodeBaseline struct {
	gate                      chan struct{}
	nft                       *desktopLinuxNFT
	netlink                   *desktopLinuxBaselineNetlink
	namespace                 *os.File
	namespaceInfo             os.FileInfo
	prepared                  *desktopLinuxNFT
	preparedRecord            DesktopLinuxProtectionRecord
	successor                 *DesktopLinuxNodeBaseline
	homeLAN                   bool
	complete, removed, closed bool
	uncertain, closeErr       error
}

// NewDesktopLinuxNodeBaseline creates, never replaces, the strictly derived
// session table in one exclusive native transaction. Exact kernel handles
// from the original create receipt must match an independent generation-
// bracketed readback. A partial return remains owned and closeable; neither
// its label nor a later matching readback can recover an unknown creation.
func NewDesktopLinuxNodeBaseline(ctx context.Context, capture DesktopSocketCapture, homeLAN bool) (*DesktopLinuxNodeBaseline, error) {
	if ctx == nil || ctx.Err() != nil || !capture.valid() || os.Geteuid() != 0 {
		return nil, errors.New("Linux Node baseline requires its live captured privileged creator")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), nft: desktopLinuxNFTForCapture(capture, true), homeLAN: homeLAN}
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var err error
	b.namespace, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return b, err
	}
	b.namespaceInfo, err = b.namespace.Stat()
	if err != nil {
		return b, err
	}
	b.netlink, err = desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return b, err
	}
	options := DesktopLinuxSocketOptions{}
	if homeLAN {
		for _, prefix := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(prefix))
		}
	}
	request := desktopLinuxNodeBaselineRequest(capture, options)
	body, err := json.Marshal(map[string]any{"nftables": request})
	if err != nil || b.currentNamespace(ctx) != nil {
		return b, errors.Join(err, errors.New("Linux Node baseline lost its original namespace before creation"))
	}
	// JSON output requires JSON input. The exclusive create is part of the
	// same batch as every drop-chain exemption; no empty table is admitted.
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-a", "-e", "-j", "-f", "-"}, string(body))
	if err != nil {
		b.uncertain = errors.Join(err, errors.New("Linux Node baseline retained an unacknowledged creation"))
		return b, b.uncertain
	}
	created, err := desktopLinuxNodeBaselineReceipt(raw, capture, options)
	if err != nil {
		b.uncertain = err
		return b, err
	}
	b.nft = created
	if _, err := b.observe(ctx, false); err != nil {
		b.uncertain = err
		return b, err
	}
	b.complete = true
	return b, nil
}

func desktopLinuxNodeBaselineRequest(c DesktopSocketCapture, options DesktopLinuxSocketOptions) []map[string]any {
	table := desktopLinuxNodeTable(c)
	request := []map[string]any{
		{"create": map[string]any{"table": map[string]any{"family": "inet", "name": table}}},
		{"add": map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": "output", "type": "filter", "hook": "output", "prio": float64(-310), "policy": "drop", "comment": "routervpn-owned-baseline:" + c.SessionID + ":" + c.SourceSHA256}}},
	}
	for _, expressions := range desktopLinuxBaselineExpressions(options) {
		request = append(request, map[string]any{"add": map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": "output", "expr": expressions}}})
	}
	return request
}

func desktopLinuxNodeBaselineReceipt(raw []byte, c DesktopSocketCapture, options DesktopLinuxSocketOptions) (*desktopLinuxNFT, error) {
	request := desktopLinuxNodeBaselineRequest(c, options)
	if len(raw) == 0 || len(raw) > 64<<10 || !c.valid() {
		return nil, errors.New("Linux Node creation has no bounded original receipt")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	value, err := profileValue(decoder, 0) // Reject duplicate fields and excess nesting.
	root, ok := value.(map[string]any)
	if err != nil || !ok || len(root) != 1 {
		return nil, errors.Join(err, errors.New("Linux Node creation receipt has an ambiguous root"))
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("Linux Node creation receipt contains trailing data")
	}
	rows, ok := root["nftables"].([]any)
	if !ok || len(rows) != len(request) || len(request) < 6 || len(request) > 8 {
		return nil, errors.New("Linux Node creation receipt omitted or added native operations")
	}
	n := desktopLinuxNFTForCapture(c, true)
	for index, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok || len(row) != 1 {
			return nil, errors.New("Linux Node creation receipt contains an ambiguous operation")
		}
		verb, kind := "add", "rule"
		if index == 0 {
			verb, kind = "create", "table"
		} else if index == 1 {
			kind = "chain"
		}
		operation, ok := row[verb].(map[string]any)
		object, objectOK := operation[kind].(map[string]any)
		if !ok || !objectOK {
			return nil, errors.New("Linux Node creation receipt changed its ordered native operation")
		}
		// nft's create-table echo places handle beside table; other native
		// objects put it inside the object. Accept either sole location, but
		// never two competing identities or an unrequested operation field.
		handleValue, inObject := object["handle"]
		outer, outside := operation["handle"]
		if inObject == outside {
			return nil, errors.New("Linux Node creation receipt has no unique native handle")
		}
		if outside {
			handleValue = outer
			delete(operation, "handle")
		} else {
			delete(object, "handle")
		}
		handle := desktopLinuxNumber(handleValue)
		if handle == 0 || handle > 1<<53-1 || !reflect.DeepEqual(row, request[index]) {
			return nil, errors.New("Linux Node creation receipt substituted an original native operation")
		}
		switch kind {
		case "table":
			n.TableHandle = handle
		case "chain":
			n.ChainHandle = handle
		case "rule":
			if n.Baseline[handle] != nil || handle == n.ChainHandle {
				return nil, errors.New("Linux Node creation reused a native chain/rule handle")
			}
			n.Baseline[handle] = object["expr"]
		}
	}
	return n, nil
}

func (b *DesktopLinuxNodeBaseline) enter(ctx context.Context) error {
	if b == nil || b.gate == nil || ctx == nil || ctx.Err() != nil {
		return net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
		return nil
	}
}

func (b *DesktopLinuxNodeBaseline) currentNamespace(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || b.closed || b.nft == nil || b.netlink == nil || b.namespace == nil || b.namespaceInfo == nil || b.uncertain != nil {
		return errors.Join(b.uncertain, net.ErrClosed)
	}
	retained, err := b.namespace.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if err != nil || currentErr != nil || !os.SameFile(retained, b.namespaceInfo) || !os.SameFile(current, b.namespaceInfo) {
		return errors.Join(err, currentErr, errors.New("Linux Node baseline left its original retained network namespace"))
	}
	return ctx.Err()
}

func (b *DesktopLinuxNodeBaseline) read(ctx context.Context, prepared bool) error {
	if b.removed || b.nft.TableName != desktopLinuxNodeTable(b.nft.Capture) || b.nft.TableHandle == 0 || b.nft.ChainHandle == 0 {
		return errors.New("Linux Node baseline lost its original creation receipt")
	}
	rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if err != nil {
		return err
	}
	if prepared {
		if b.prepared == nil {
			return errors.New("Linux Node successor has no original prepared source")
		}
		return desktopLinuxProtectionRows(b.prepared, rows, true)
	}
	// nft may reorder an anonymous set between its original command echo and
	// kernel listing. Only that unordered set representation is normalized;
	// every original handle, expression, flag and namespace remains exact.
	closed := *b.nft
	closed.Baseline = make(map[uint64]any, len(b.nft.Baseline))
	for handle, expressions := range b.nft.Baseline {
		closed.Baseline[handle] = desktopLinuxSetNormalized(expressions)
	}
	normalized := make([]map[string]any, len(rows))
	for index, row := range rows {
		normalized[index] = desktopLinuxSetNormalized(row).(map[string]any)
	}
	if err := desktopLinuxProtectionInventoryRows(&closed, normalized, false); err != nil {
		return err
	}
	if !b.complete {
		// Preserve the actual kernel representation for comparison with the
		// independently created guardian's digest. This happens only during
		// the original generation-bracketed constructor, never on adoption.
		for _, row := range rows {
			if rule, ok := row["rule"].(map[string]any); ok {
				b.nft.Baseline[desktopLinuxNumber(rule["handle"])] = rule["expr"]
			}
		}
	}
	return nil
}

func (b *DesktopLinuxNodeBaseline) observe(ctx context.Context, prepared bool) (uint32, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := b.currentNamespace(ctx); err != nil {
		return 0, err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return 0, err
	}
	if err := b.read(ctx, prepared); err != nil {
		return 0, err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return 0, errors.Join(err, errors.New("Linux Node baseline changed during its native snapshot"))
	}
	return after, nil
}

// BindPrepared compares the exact native engine observation to this original
// created table. The caller must receive it on the authenticated engine
// channel; this record never creates table ownership or process authority.
// A second source or a nonempty/changed permit inventory cannot bind it again.
func (b *DesktopLinuxNodeBaseline) BindPrepared(ctx context.Context, record DesktopLinuxProtectionRecord) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete || b.removed || b.prepared != nil || record.Validate() != nil || record.Capture != b.nft.Capture ||
		record.TableName != b.nft.TableName || record.TableHandle != b.nft.TableHandle || record.ChainHandle != b.nft.ChainHandle {
		return errors.New("Linux Node preparation belongs to another original baseline or source")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if err != nil {
		return err
	}
	n := *b.nft
	n.UID, n.Prefix = record.UID, record.PermitPrefix
	n.Rules, n.Sets = make(map[string]uint64), make(map[string]uint64)
	for _, row := range rows {
		for _, transport := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			if rule, ok := row["rule"].(map[string]any); ok && rule["comment"] == n.comment(transport) {
				if n.Rules[transport] != 0 {
					return errors.New("Linux Node preparation duplicated a native permit rule")
				}
				n.Rules[transport] = desktopLinuxNumber(rule["handle"])
			}
			if set, ok := row["set"].(map[string]any); ok && set["name"] == n.Prefix+"_"+transport {
				if n.Sets[transport] != 0 {
					return errors.New("Linux Node preparation duplicated a native permit set")
				}
				n.Sets[transport] = desktopLinuxNumber(set["handle"])
			}
		}
	}
	if err := desktopLinuxProtectionRows(&n, rows, true); err != nil {
		return err
	}
	encoded, err := json.Marshal(n.Baseline)
	if err != nil || record.BaselineSHA256 != desktopLinuxBaselineDigest(encoded) {
		return errors.New("Linux Node preparation substituted its original baseline digest")
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return errors.Join(err, errors.New("Linux Node preparation changed during its native snapshot"))
	}
	b.prepared, b.preparedRecord = &n, record
	return nil
}

func (b *DesktopLinuxNodeBaseline) ObserveClosed(ctx context.Context) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete {
		return errors.New("Linux Node baseline creation is incomplete")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, err := b.observe(ctx, false)
	return err
}

func (b *DesktopLinuxNodeBaseline) absence(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if !b.removed || b.currentNamespace(ctx) != nil {
		return errors.New("Linux Node absence has no acknowledged original removal")
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if err != nil || len(rows) != 0 {
		return errors.Join(err, errors.New("Linux Node original table is not absent"))
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return errors.Join(err, errors.New("Linux Node absence changed during its native snapshot"))
	}
	return nil
}

func (b *DesktopLinuxNodeBaseline) remove(ctx context.Context, generation uint32) error {
	acknowledged, sent, err := b.netlink.delete(ctx, generation, b.nft.TableHandle)
	if acknowledged {
		b.removed = true
	}
	var rejection syscall.Errno
	if sent && !acknowledged && !errors.As(err, &rejection) {
		b.uncertain = errors.Join(err, errors.New("Linux Node baseline retained an unknown native removal"))
	}
	if err != nil {
		return err
	}
	if !acknowledged {
		return errors.New("Linux Node baseline removal has no committed native receipt")
	}
	return nil
}

// Release removes only the original closed table. A parent must prove child
// retirement and its selected disconnect/explicit Off semantics separately.
func (b *DesktopLinuxNodeBaseline) Release(ctx context.Context) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete || b.successor != nil {
		return errors.New("Linux Node release cannot replace an incomplete or pending succession")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !b.removed {
		generation, err := b.observe(ctx, false)
		if err != nil {
			return err
		}
		if err := b.remove(ctx, generation); err != nil {
			return err
		}
	}
	return b.absence(ctx)
}

// Supersede keeps the newly prepared deny table installed throughout the
// predecessor's conditional deletion. One global generation brackets both
// exact tables, so a changed/deleted successor makes the kernel reject the old
// deletion. An acknowledged retry only proves absence and never deletes again.
func (b *DesktopLinuxNodeBaseline) Supersede(ctx context.Context, successor *DesktopLinuxNodeBaseline) error {
	if b == nil || successor == nil || b == successor || b.nft == nil || successor.nft == nil || b.nft.Capture.SessionID == successor.nft.Capture.SessionID {
		return errors.New("Linux Node succession requires two distinct original creators")
	}
	first, second := b, successor
	if first.nft.Capture.SessionID > second.nft.Capture.SessionID {
		first, second = second, first
	}
	if err := first.enter(ctx); err != nil {
		return err
	}
	defer func() { first.gate <- struct{}{} }()
	if err := second.enter(ctx); err != nil {
		return err
	}
	defer func() { second.gate <- struct{}{} }()
	if !b.complete || !successor.complete || b.prepared == nil || successor.prepared == nil || b.successor != nil && b.successor != successor ||
		successor.removed || successor.successor != nil || !os.SameFile(b.namespaceInfo, successor.namespaceInfo) {
		return errors.New("Linux Node succession lost its exact prepared owners or pending candidate")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	if err := successor.currentNamespace(ctx); err != nil {
		return err
	}
	if !b.removed {
		before, err := b.netlink.generation(ctx)
		if err != nil {
			return err
		}
		if err := b.read(ctx, false); err != nil {
			return err
		}
		if err := successor.read(ctx, true); err != nil {
			return err
		}
		after, err := b.netlink.generation(ctx)
		if err != nil || before != after || b.currentNamespace(ctx) != nil || successor.currentNamespace(ctx) != nil {
			return errors.Join(err, errors.New("Linux Node succession changed during its shared generation snapshot"))
		}
		b.successor = successor
		if err := b.remove(ctx, after); err != nil {
			// A definitive rejection or unsent request leaves the original
			// baseline intact. Its parent may roll back that intent and try
			// another candidate. Unknown/acknowledged outcomes keep the
			// exact original candidate and can never redirect a retry.
			if !b.removed && b.uncertain == nil {
				b.successor = nil
			}
			return err
		}
	}
	if b.successor != successor {
		return errors.New("Linux Node committed succession belongs to another original candidate")
	}
	if err := b.absence(ctx); err != nil {
		return err
	}
	_, err := successor.observe(ctx, true)
	return err
}

func (b *DesktopLinuxNodeBaseline) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.closed {
		return b.closeErr
	}
	if err := b.netlink.close(); err != nil {
		b.closeErr = errors.Join(b.closeErr, err)
	}
	if b.namespace != nil {
		if err := b.namespace.Close(); err != nil {
			b.closeErr = errors.Join(b.closeErr, err)
		} else {
			b.namespace = nil
		}
	}
	if b.closeErr == nil {
		b.closed = true
	}
	return b.closeErr
}

func desktopLinuxBaselineDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
