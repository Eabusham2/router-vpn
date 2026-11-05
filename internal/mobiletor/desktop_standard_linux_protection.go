//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const desktopLinuxStandardTablePrefix = "router_vpn_standard_"

// DesktopLinuxStandardProtection retains the creator of a standard-exit deny
// table. It is not a socket guardian and grants no engine/process authority.
// Callers must join the original engine, prove TUN absence, and compare their
// persisted owner under their retained mutation lease before Release.
// Close joins descriptors only and deliberately leaves kernel protection.
type DesktopLinuxStandardProtection struct {
	baseline     *DesktopLinuxNodeBaseline
	generation   uint32
	acknowledged bool
	bootstrap    *desktopLinuxStandardBootstrap
}

// DesktopLinuxStandardProtectionReceipt describes the original acknowledged
// creation. A receipt is observation, never authority to recover this object.
type DesktopLinuxStandardProtectionReceipt struct {
	NamespaceDevice    uint64          `json:"namespace_device"`
	NamespaceInode     uint64          `json:"namespace_inode"`
	Baseline           json.RawMessage `json:"baseline"`
	CreationGeneration uint32          `json:"creation_generation"`
	Session            string          `json:"session"`
	ConfigSHA256       string          `json:"config_sha256"`
	Table              string          `json:"table"`
	TableHandle        uint64          `json:"table_handle"`
	ChainHandle        uint64          `json:"chain_handle"`
	BaselineSHA256     string          `json:"baseline_sha256"`
}

func desktopLinuxStandardTable(c DesktopSocketCapture) string {
	return desktopLinuxStandardTablePrefix + c.SessionID
}
func desktopLinuxOwnedTableName(name string) bool {
	for _, prefix := range []string{desktopLinuxNodeTablePrefix, desktopLinuxStandardTablePrefix} {
		if strings.HasPrefix(name, prefix) && desktopSocketHex(strings.TrimPrefix(name, prefix), 32) {
			return true
		}
	}
	return false
}

func desktopLinuxStandardRequest(c DesktopSocketCapture, endpoints []netip.Addr, homeLAN bool) ([]map[string]any, error) {
	if !c.valid() || len(endpoints) == 0 || len(endpoints) > 16 {
		return nil, errors.New("standard protection requires bounded captured literal endpoints")
	}
	options := DesktopLinuxSocketOptions{}
	if homeLAN {
		for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(p))
		}
	}
	request := desktopLinuxNodeBaselineRequest(c, options)
	table := desktopLinuxStandardTable(c)
	request[0]["create"].(map[string]any)["table"].(map[string]any)["name"] = table
	for _, row := range request[1:] {
		for _, obj := range row["add"].(map[string]any) {
			obj.(map[string]any)["table"] = table
		}
	}
	seen := map[netip.Addr]bool{}
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() || endpoint.Zone() != "" || endpoint.Is4In6() || endpoint.IsUnspecified() || endpoint.IsMulticast() || seen[endpoint] {
			return nil, errors.New("standard protection has an invalid or duplicate physical endpoint")
		}
		seen[endpoint] = true
		family := "ip6"
		if endpoint.Is4() {
			family = "ip"
		}
		expressions := []any{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": family, "field": "daddr"}}, "right": endpoint.String()}}, map[string]any{"accept": nil}}
		request = append(request, map[string]any{"add": map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": "output", "expr": expressions}}})
	}
	return request, nil
}

func desktopLinuxStandardLease(lease *os.File) error {
	if lease == nil || os.Geteuid() != 0 {
		return errors.New("standard protection requires its retained privileged mutation lease")
	}
	info, err := lease.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("standard protection mutation lease lost its private inode")
	}
	// flock on this same open description preserves an already held lock. A
	// different live helper lease is rejected; the caller retains/joins this fd.
	return syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// NewDesktopLinuxStandardProtection atomically creates an exclusive session
// table. It records original echoed handles then verifies their exact namespace
// and complete inventory between native generation reads. Never replace an
// existing table. A partial owner is retained on uncertain creation.
func NewDesktopLinuxStandardProtection(ctx context.Context, session, configSHA256 string, endpoints []netip.Addr, homeLAN bool, lease *os.File) (*DesktopLinuxStandardProtection, error) {
	capture := DesktopSocketCapture{SessionID: session, SourceSHA256: configSHA256, NetworkID: session}
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("standard protection creation was cancelled")
	}
	request, err := desktopLinuxStandardRequest(capture, endpoints, homeLAN)
	if err != nil {
		return nil, err
	}
	if err = desktopLinuxStandardLease(lease); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), nft: desktopLinuxNFTForCapture(capture, true), standard: true, homeLAN: homeLAN}
	b.nft.TableName = desktopLinuxStandardTable(capture)
	owner := &DesktopLinuxStandardProtection{baseline: b}
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b.namespace, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return owner, err
	}
	b.namespaceInfo, err = b.namespace.Stat()
	if err != nil {
		return owner, err
	}
	b.netlink, err = desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return owner, err
	}
	body, err := json.Marshal(map[string]any{"nftables": request})
	if err != nil {
		return owner, err
	}
	if err = b.currentNamespace(ctx); err != nil {
		return owner, err
	}
	raw, err := desktopLinuxNFTCommandFiles(ctx, []string{"-a", "-e", "-j", "-f", "-"}, string(body), []*os.File{lease})
	if err != nil {
		b.uncertain = errors.Join(err, errors.New("standard protection retained an unacknowledged creation"))
		return owner, b.uncertain
	}
	b.nft, err = desktopLinuxBaselineReceipt(raw, capture, request, b.nft)
	if err != nil {
		b.uncertain = err
		return owner, err
	}
	owner.acknowledged = true
	if owner.generation, err = b.observe(ctx, false); err != nil {
		return owner, err
	}
	b.complete = true
	return owner, nil
}

// An acknowledged creator may finish its interrupted read-only validation.
// An unknown command outcome or malformed original receipt can never resume.
func (p *DesktopLinuxStandardProtection) complete(ctx context.Context) error {
	if p == nil || p.baseline == nil || !p.acknowledged {
		return errors.New("standard protection lacks its original acknowledged creation")
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if b.uncertain != nil {
		return b.uncertain
	}
	if p.bootstrap != nil {
		return errors.New("standard protection retains original bootstrap cleanup")
	}
	if b.complete {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	generation, err := b.observe(ctx, false)
	if err != nil {
		return err
	}
	p.generation = generation
	b.complete = true
	return nil
}

func (p *DesktopLinuxStandardProtection) Receipt(ctx context.Context) (DesktopLinuxStandardProtectionReceipt, error) {
	if err := p.complete(ctx); err != nil {
		return DesktopLinuxStandardProtectionReceipt{}, err
	}
	if p == nil || p.baseline == nil {
		return DesktopLinuxStandardProtectionReceipt{}, errors.New("standard protection has no original creator")
	}
	b := p.baseline
	if err := b.enter(ctx); err != nil {
		return DesktopLinuxStandardProtectionReceipt{}, err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete || b.closed || b.uncertain != nil || p.bootstrap != nil {
		return DesktopLinuxStandardProtectionReceipt{}, errors.New("standard protection creation is incomplete")
	}
	encoded, err := json.Marshal(b.nft.Baseline)
	if err != nil {
		return DesktopLinuxStandardProtectionReceipt{}, err
	}
	n := b.nft
	namespace, ok := b.namespaceInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return DesktopLinuxStandardProtectionReceipt{}, errors.New("standard creation lost native namespace identity")
	}
	return DesktopLinuxStandardProtectionReceipt{NamespaceDevice: uint64(namespace.Dev), NamespaceInode: namespace.Ino, Baseline: encoded, CreationGeneration: p.generation, Session: n.Capture.SessionID, ConfigSHA256: n.Capture.SourceSHA256, Table: n.TableName, TableHandle: n.TableHandle, ChainHandle: n.ChainHandle, BaselineSHA256: desktopLinuxBaselineDigest(encoded)}, nil
}
func (p *DesktopLinuxStandardProtection) Current(ctx context.Context, lease *os.File) error {
	if p == nil || p.baseline == nil {
		return errors.New("standard protection has no original creator")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	if err := p.complete(ctx); err != nil {
		return err
	}
	return p.baseline.ObserveClosed(ctx)
}
func (p *DesktopLinuxStandardProtection) Release(ctx context.Context, lease *os.File) error {
	if p == nil || p.baseline == nil {
		return errors.New("standard protection has no original creator")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	if err := p.complete(ctx); err != nil {
		return err
	}
	return p.baseline.Release(ctx)
}

// Supersede keeps successor installed while a shared native generation binds
// both exact inventories to deletion of the predecessor's original handle.
func (p *DesktopLinuxStandardProtection) Supersede(ctx context.Context, next *DesktopLinuxStandardProtection, lease *os.File) error {
	if p == nil || next == nil || p.baseline == nil || next.baseline == nil {
		return errors.New("standard succession requires two original creators")
	}
	if err := desktopLinuxStandardLease(lease); err != nil {
		return err
	}
	if err := p.complete(ctx); err != nil {
		return err
	}
	if err := next.complete(ctx); err != nil {
		return err
	}
	return p.baseline.supersede(ctx, next.baseline, false)
}
func (p *DesktopLinuxStandardProtection) Close(ctx context.Context) error {
	if p == nil || p.baseline == nil {
		return nil
	}
	return p.baseline.Close(ctx)
}
