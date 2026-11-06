//go:build windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// BindTunnel consumes the native Box's actual owned-TUN readback after startup
// (or a serialized MTU replacement). The shipping adapter never supplies an
// interface from JSON, an alias search, or a guessed wildcard. The policy also
// rejects every captured physical interface, independently of that readback.
func (p *DesktopWindowsSocketPolicy) BindTunnel(ctx context.Context, capture DesktopSocketCapture, name string, index uint32) error {
	owner, err := p.Owner()
	if err != nil || capture != p.capture || !p.Current(capture, owner) || name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") || index == 0 {
		return errors.Join(err, errors.New("Windows tunnel grant has no captured native owner"))
	}
	_, err = desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) {
		if p.terminalCleanup != nil {
			return struct{}{},errors.New("Windows tunnel owner entered terminal cleanup")
		}
		if len(p.tunnel) != 0 || p.tunnelName != "" {
			return struct{}{}, errors.New("Windows tunnel grant must retire its previous reader first")
		}
		luid, err := p.checkTunnel(name, index)
		if err != nil {
			return struct{}{}, err
		}
		if err := p.assertBaseline(); err != nil {
			return struct{}{}, err
		}
		p.tunnelName, p.tunnelIndex, p.tunnelLUID = name, index, luid
		for _, family := range []int{4, 6} {
			if family == 6 && !p.options.IPv6Enabled {
				continue
			}
			p.tunnel = append(p.tunnel, p.pair("owned-tunnel", family, 55, true, false,
				desktopWFPNumber(desktopWFPInterface, 4, luid))...)
		}
		if err := p.leaseEngine.Begin(); err != nil {
			return struct{}{}, err
		}
		for index := range p.tunnel {
			if err = p.leaseEngine.Add(&p.tunnel[index]); err != nil {
				break
			}
		}
		if err == nil {
			err = p.leaseEngine.Commit()
		}
		if err != nil {
			return struct{}{}, errors.Join(err, p.leaseEngine.Abort())
		}
		if err := p.assertTunnel(); err != nil {
			return struct{}{}, err
		}
		if err := p.assertBaseline(); err != nil {
			return struct{}{}, err
		}
		if ctx.Err() != nil || !p.Current(capture, owner) {
			return struct{}{}, net.ErrClosed
		}
		p.observed.Store(time.Now().UnixMilli())
		return struct{}{}, nil
	})
	return err
}

func (p *DesktopWindowsSocketPolicy) checkTunnel(name string, index uint32) (uint64, error) {
	actual, err := net.InterfaceByIndex(int(index))
	if err != nil || actual.Name != name || actual.Flags&net.FlagUp == 0 || actual.Flags&net.FlagLoopback != 0 {
		return 0, errors.Join(err, errors.New("Windows owned tunnel interface changed"))
	}
	luid, err := desktopWindowsInterfaceLUID(index)
	if err != nil {
		return 0, err
	}
	for _, physical := range p.interfaces {
		if physical.Index == index || physical.LUID == luid {
			return 0, errors.New("Windows tunnel grant cannot authorize a physical interface")
		}
	}
	return luid, nil
}
func (p *DesktopWindowsSocketPolicy) assertTunnel() error {
	if len(p.tunnel) == 0 {
		if p.tunnelName != "" || p.tunnelIndex != 0 || p.tunnelLUID != 0 {
			return errors.New("Windows tunnel grant lost its complete identity")
		}
		return nil
	}
	luid, err := p.checkTunnel(p.tunnelName, p.tunnelIndex)
	if err != nil || luid != p.tunnelLUID {
		return errors.Join(err, errors.New("Windows owned tunnel LUID changed"))
	}
	return nil
}

// RetireTunnel is acknowledged before the native TUN is replaced. An expired
// callback cannot remove a newer interface's grant. A rollback must present its
// own newly returned native readback to BindTunnel; the former LUID is not
// silently reused after an interface index changes.
func (p *DesktopWindowsSocketPolicy) RetireTunnel(ctx context.Context, capture DesktopSocketCapture, name string, index uint32) error {
	if p == nil || capture != p.capture || ctx == nil || ctx.Err() != nil {
		return net.ErrClosed
	}
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		if name == "" || index == 0 || p.tunnelName != name || p.tunnelIndex != index || len(p.tunnel) == 0 {
			return struct{}{}, errors.New("Windows tunnel retirement belongs to another native reader")
		}
		return struct{}{}, p.retireTunnel()
	})
	return err
}
func (p *DesktopWindowsSocketPolicy) retireTunnel() error {
	if len(p.tunnel) == 0 {
		return nil
	}
	if p.leaseEngine == nil || p.baselineEngine == nil {
		return errors.New("Windows tunnel retirement lost its native WFP sessions")
	}
	if err := p.leaseEngine.Abort(); err != nil {
		return err
	}
	if err := p.leaseEngine.Begin(); err != nil {
		return err
	}
	var err error
	for _, rule := range p.tunnel {
		if err = p.leaseEngine.Delete(rule.Key); err != nil {
			break
		}
	}
	if err == nil {
		err = p.leaseEngine.Commit()
	}
	if err != nil {
		return errors.Join(err, p.leaseEngine.Abort())
	}
	for _, rule := range p.tunnel {
		if err := p.baselineEngine.Absent(rule.Key); err != nil {
			return err
		}
	}
	p.tunnel = nil
	p.tunnelName, p.tunnelIndex, p.tunnelLUID = "", 0, 0
	return nil
}

type desktopWindowsLeaseCleanup struct {
	policy *DesktopWindowsSocketPolicy
	capture DesktopSocketCapture
	owner DesktopSocketKernelOwner
	discarded atomic.Bool
	// Remaining fields are protected by the original policy's gate.
	name string
	index uint32
	luid uint64
	keys []syscall.GUID
	joined bool
}
func (t *desktopWindowsLeaseCleanup) Discard() {
	if t != nil { t.discarded.Store(true) }
}
func (t *desktopWindowsLeaseCleanup) ownerCurrent() bool {
	return t != nil && t.policy != nil && !t.discarded.Load() && t.policy.Current(t.capture,t.owner)
}
func (p *DesktopWindowsSocketPolicy) SealLeaseCleanup(ctx context.Context,capture DesktopSocketCapture) (DesktopSocketLeaseCleanup,error) {
	owner,err := p.Owner()
	if err != nil || capture != p.capture { return nil,net.ErrClosed }
	return desktopWindowsPolicyCall[DesktopSocketLeaseCleanup](p,ctx,false,func()(DesktopSocketLeaseCleanup,error){
		if p.terminalCleanup != nil || !p.Current(capture,owner) { return nil,net.ErrClosed }
		if err := p.assertBaseline(); err != nil { return nil,err }
		if err := p.assertTunnel(); err != nil { return nil,err }
		if len(p.tunnel) == 0 { return nil,errors.New("Windows lease cleanup requires an owned tunnel") }
		return &desktopWindowsLeaseCleanup{policy:p,capture:capture,owner:owner},nil
	})
}
func (t *desktopWindowsLeaseCleanup) Quiesce(ctx context.Context,name string,index uint32) error {
	if !t.ownerCurrent() { return net.ErrClosed }
	p := t.policy
	_,err := desktopWindowsPolicyCall(p,ctx,true,func()(struct{},error){
		if !t.ownerCurrent() { return struct{}{},net.ErrClosed }
		if p.terminalCleanup == nil {
			if name == "" || index == 0 || p.tunnelName != name || p.tunnelIndex != index || len(p.tunnel) == 0 {
				return struct{}{},errors.New("Windows terminal cleanup belongs to another tunnel")
			}
			if err := p.assertTunnel(); err != nil { return struct{}{},err }
			if err := p.assertBaseline(); err != nil { return struct{}{},err }
			t.name,t.index,t.luid = name,index,p.tunnelLUID
			for _,rule := range p.tunnel { t.keys = append(t.keys,rule.Key) }
			p.terminalCleanup = t
		} else if p.terminalCleanup != t || name != t.name || index != t.index {
			return struct{}{},errors.New("Windows terminal cleanup token changed")
		}
		// The policy gate is retained until an entered native call really joins.
		// A later caller observes that original result, never a replacement TUN.
		if len(p.tunnel) != 0 {
			if p.tunnelName != t.name || p.tunnelIndex != t.index || p.tunnelLUID != t.luid || len(p.tunnel) != len(t.keys) {
				return struct{}{},errors.New("Windows terminal tunnel identity changed")
			}
			for i,rule := range p.tunnel {
				if rule.Key != t.keys[i] { return struct{}{},errors.New("Windows terminal tunnel rule changed") }
			}
		}
		if err := p.retireTunnel(); err != nil { return struct{}{},err }
		if err := t.absent(); err != nil { return struct{}{},err }
		if !t.ownerCurrent() { return struct{}{},net.ErrClosed }
		t.joined = true
		return struct{}{},nil
	})
	return err
}
func (t *desktopWindowsLeaseCleanup) absent() error {
	p := t.policy
	if len(t.keys) == 0 || p.baselineEngine == nil || len(p.tunnel) != 0 ||
		p.tunnelName != "" || p.tunnelIndex != 0 || p.tunnelLUID != 0 {
		return errors.New("Windows terminal tunnel removal is not complete")
	}
	for _,key := range t.keys {
		if err := p.baselineEngine.Absent(key); err != nil { return err }
	}
	return p.assertBaseline()
}
func (t *desktopWindowsLeaseCleanup) Current(ctx context.Context) error {
	if !t.ownerCurrent() { return net.ErrClosed }
	_,err := desktopWindowsPolicyCall(t.policy,ctx,true,func()(struct{},error){
		if !t.ownerCurrent() || t.policy.terminalCleanup != t || !t.joined { return struct{}{},net.ErrClosed }
		if err := t.absent(); err != nil { return struct{}{},err }
		if !t.ownerCurrent() { return struct{}{},net.ErrClosed }
		return struct{}{},nil
	})
	return err
}
