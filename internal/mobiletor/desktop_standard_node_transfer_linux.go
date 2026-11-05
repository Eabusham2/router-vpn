//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
)

// DesktopLinuxNodeTransferSnapshot is comparison data from a pinned original
// creator. Only its authenticated live controller may submit it while retaining
// the corresponding pin. Decoding it never constructs a native creator.
type DesktopLinuxNodeTransferSnapshot struct {
	Record    DesktopLinuxProtectionRecord `json:"record"`
	HomeLAN   bool                         `json:"home_lan"`
	Inventory json.RawMessage              `json:"inventory"`
}

type DesktopLinuxNodeTransferPin struct {
	baseline *DesktopLinuxNodeBaseline
	id       string
	snapshot DesktopLinuxNodeTransferSnapshot
	released bool
}

func (b *DesktopLinuxNodeBaseline) PinStandardTransfer(ctx context.Context, id string) (*DesktopLinuxNodeTransferPin, error) {
	if err := b.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if !desktopSocketHex(id, 32) || b.standard || b.prepared == nil || !b.complete || b.removed || b.crossTransfer != "" {
		return nil, errors.New("Node transfer requires its unused original prepared creator")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, true); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b.prepared)
	if err != nil {
		return nil, err
	}
	p := &DesktopLinuxNodeTransferPin{baseline: b, id: id, snapshot: DesktopLinuxNodeTransferSnapshot{Record: b.preparedRecord, HomeLAN: b.homeLAN, Inventory: raw}}
	if _, err = p.snapshot.inventory(); err != nil {
		return nil, err
	}
	b.crossTransfer = id
	return p, nil
}

// WithSnapshot keeps the actual creator gate held throughout the authenticated
// service call. A failed/lost call retains the pin until that original service
// positively resolves whether its source removal committed.
func (p *DesktopLinuxNodeTransferPin) WithSnapshot(ctx context.Context, call func(DesktopLinuxNodeTransferSnapshot) error) error {
	if p == nil || p.baseline == nil || call == nil {
		return errors.New("Node transfer lost its original pin")
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if p.released || b.crossTransfer != p.id || b.removed || b.preparedRecord != p.snapshot.Record {
		return errors.New("Node transfer pin was replaced")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, true); err != nil {
		return err
	}
	snapshot := p.snapshot
	snapshot.Inventory = append([]byte(nil), snapshot.Inventory...)
	return call(snapshot)
}

// Resolve is called only after an authenticated original service result. It
// unpins this creator; it never removes either table or claims service absence.
func (p *DesktopLinuxNodeTransferPin) Resolve(ctx context.Context) error {
	if p == nil || p.baseline == nil {
		return errors.New("Node transfer omitted its retained pin")
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if p.released {
		return nil
	}
	if b.crossTransfer != p.id {
		return errors.New("Node transfer resolve changed its original pin")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := b.observe(ctx, true); err != nil {
		if _, closedErr := b.observe(ctx, false); closedErr != nil {
			return errors.Join(err, closedErr)
		}
	}
	b.crossTransfer = ""
	p.released = true
	return nil
}

func (s DesktopLinuxNodeTransferSnapshot) inventory() (*desktopLinuxNFT, error) {
	if s.Record.Validate() != nil || s.Record.TableName == "" || len(s.Inventory) == 0 || len(s.Inventory) > 24<<10 {
		return nil, errors.New("Node transfer has no bounded prepared inventory")
	}
	var n desktopLinuxNFT
	dec := json.NewDecoder(bytes.NewReader(s.Inventory))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&n); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(n)
	if err != nil || !bytes.Equal(canonical, s.Inventory) {
		return nil, errors.New("Node transfer inventory is not canonical")
	}
	r := s.Record
	if n.Capture != r.Capture || n.TableName != r.TableName || n.TableHandle != r.TableHandle || n.ChainHandle != r.ChainHandle || n.UID != r.UID || n.Prefix != r.PermitPrefix || len(n.Rules) != 4 || len(n.Sets) != 4 {
		return nil, errors.New("Node transfer changed its prepared identity")
	}
	raw, err := json.Marshal(n.Baseline)
	if err != nil || desktopLinuxBaselineDigest(raw) != r.BaselineSHA256 {
		return nil, errors.New("Node transfer changed its baseline digest")
	}
	options := DesktopLinuxSocketOptions{}
	if s.HomeLAN {
		for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(p))
		}
	}
	expected := desktopLinuxBaselineExpressions(options)
	if len(n.Baseline) != len(expected) {
		return nil, errors.New("Node transfer changed its closed baseline")
	}
	for _, actual := range n.Baseline {
		found := -1
		for i, want := range expected {
			if reflect.DeepEqual(desktopLinuxSetNormalized(actual), desktopLinuxSetNormalized(want)) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, errors.New("Node transfer widened its closed baseline")
		}
		expected = append(expected[:found], expected[found+1:]...)
	}
	return &n, nil
}

// DesktopLinuxStandardNodeTransfer retains the service's original creator.
// The service must bind this object to one live authenticated controller and
// persist its intent before Commit. Snapshot values alone cannot obtain it.
type DesktopLinuxStandardNodeTransfer struct {
	source      *DesktopLinuxStandardProtection
	id          string
	destination *DesktopLinuxNodeTransferSnapshot
	finished    bool
}

func (p *DesktopLinuxStandardProtection) ReserveNodeTransfer(ctx context.Context, id string, lease *os.File) (*DesktopLinuxStandardNodeTransfer, error) {
	if !desktopSocketHex(id, 32) || p == nil {
		return nil, errors.New("standard transfer requires its original reservation")
	}
	if err := p.Current(ctx, lease); err != nil {
		return nil, err
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.crossTransfer != "" || b.removed || b.successor != nil {
		return nil, errors.New("standard creator already has a successor")
	}
	b.crossTransfer = id
	return &DesktopLinuxStandardNodeTransfer{source: p, id: id}, nil
}
func (t *DesktopLinuxStandardNodeTransfer) Result(ctx context.Context) (bool, error) {
	if t == nil || t.source == nil {
		return false, errors.New("standard transfer lost its creator")
	}
	b := t.source.baseline
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.crossTransfer != t.id && !t.finished {
		return false, errors.New("standard transfer reservation changed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return false, err
	}
	if b.removed {
		if t.destination == nil {
			return false, errors.New("committed transfer lost its original destination")
		}
		n, err := t.destination.inventory()
		if err != nil {
			return false, err
		}
		before, err := b.netlink.generation(ctx)
		if err != nil {
			return false, err
		}
		if err = b.absence(ctx); err != nil {
			return false, err
		}
		rows, err := desktopLinuxNFTReadTable(ctx, n.table())
		if err != nil {
			return false, err
		}
		preparedErr := desktopLinuxProtectionRows(n, rows, true)
		if preparedErr != nil {
			if err = desktopLinuxProtectionInventoryRows(n, rows, false); err != nil {
				return false, errors.Join(preparedErr, err)
			}
		}
		after, err := b.netlink.generation(ctx)
		if err != nil || before != after {
			return false, errors.Join(err, errors.New("transfer result lost stable destination protection"))
		}
		return true, nil
	}
	_, err := b.observe(ctx, false)
	return false, err
}
func (t *DesktopLinuxStandardNodeTransfer) Commit(ctx context.Context, snapshot DesktopLinuxNodeTransferSnapshot, lease *os.File) error {
	if t == nil || t.source == nil {
		return errors.New("standard transfer lost its original creator")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	n, err := snapshot.inventory()
	if err != nil {
		return err
	}
	b := t.source.baseline
	if err = b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if t.finished || b.crossTransfer != t.id || !b.standard || !b.complete || b.successor != nil {
		return errors.New("standard transfer cannot replace its original reservation")
	}
	if t.destination != nil && !reflect.DeepEqual(*t.destination, snapshot) {
		return errors.New("standard transfer cannot redirect an entered removal")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = b.currentNamespace(ctx); err != nil {
		return err
	}
	if !b.removed {
		before, err := b.netlink.generation(ctx)
		if err != nil {
			return err
		}
		if err = b.read(ctx, false); err != nil {
			return err
		}
		rows, err := desktopLinuxNFTReadTable(ctx, n.table())
		if err != nil {
			return err
		}
		if err = desktopLinuxProtectionRows(n, rows, true); err != nil {
			return err
		}
		after, err := b.netlink.generation(ctx)
		if err != nil || before != after {
			return errors.Join(err, errors.New("standard transfer inventories changed generation"))
		}
		copy := snapshot
		copy.Inventory = append([]byte(nil), snapshot.Inventory...)
		t.destination = &copy
		if err = b.remove(ctx, after); err != nil {
			return err
		}
	}
	return b.absence(ctx)
}

// Finish follows a positive committed/aborted result while the actual creator
// remains retained. Unknown native removal outcomes cannot clear this pin.
func (t *DesktopLinuxStandardNodeTransfer) Finish(ctx context.Context) (bool, error) {
	committed, err := t.Result(ctx)
	if err != nil {
		return false, err
	}
	b := t.source.baseline
	if err = b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if t.finished {
		return committed, nil
	}
	if b.crossTransfer != t.id {
		return false, errors.New("standard transfer finish replaced its reservation")
	}
	b.crossTransfer = ""
	t.finished = true
	return committed, nil
}

// Exclusive observes the original reserved source beside absence of every
// other Router VPN protection table. It is the narrow journal-create exception;
// neither its receipt nor an arbitrary table name can call this method.
func (t *DesktopLinuxStandardNodeTransfer) Exclusive(ctx context.Context) error {
	if t == nil || t.source == nil {
		return errors.New("transfer absence exception has no original source")
	}
	b := t.source.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if b.removed || b.crossTransfer != t.id && !t.finished {
		return errors.New("transfer no longer retains source protection")
	}
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	if err = b.read(ctx, false); err != nil {
		return err
	}
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTRows(raw)
	if err != nil {
		return err
	}
	if err = desktopLinuxTableListAbsent(rows, func(name string) bool {
		return name != b.nft.TableName && (name == desktopLinuxNFTTable || strings.HasPrefix(name, desktopLinuxStandardTablePrefix) || strings.HasPrefix(name, desktopLinuxNodeTablePrefix))
	}); err != nil {
		return err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after {
		return errors.Join(err, errors.New("transfer exclusive source changed generation"))
	}
	return b.currentNamespace(ctx)
}
