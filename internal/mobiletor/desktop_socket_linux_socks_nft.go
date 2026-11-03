//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

func desktopLinuxSOCKSExpiry(element map[string]any, timeout float64) (time.Duration, error) {
	expires, ok := element["expires"].(float64)
	if !ok || math.IsNaN(expires) || math.IsInf(expires, 0) || expires <= 0 || expires > timeout ||
		element["timeout"] != nil && element["timeout"] != timeout {
		return 0, errors.New("Linux SOCKS permit has no bounded native expiry")
	}
	return time.Duration(expires * float64(time.Second)), nil
}

func (n *desktopLinuxNFT) socksControlExpiry(rows []map[string]any, control DesktopSocketGrant, started time.Time) (time.Time, error) {
	if control.Network != "tcp" || control.Sequence == 0 || started.IsZero() || n.verifyRows(rows, true) != nil {
		return time.Time{}, errors.New("Linux SOCKS control lost its captured native firewall")
	}
	element, found, err := n.findElement(rows, control)
	if err != nil || !found || element["comment"] != control.SocketID+":"+strconv.FormatUint(control.Sequence, 10) {
		return time.Time{}, errors.Join(err, errors.New("Linux SOCKS control permit is absent or has another operation"))
	}
	remaining, err := desktopLinuxSOCKSExpiry(element, 9)
	until := started.Add(remaining)
	if err != nil || !time.Now().Before(until) {
		return time.Time{}, errors.Join(err, errors.New("Linux SOCKS control permit expired during native readback"))
	}
	return until, nil
}

// Installation is bounded by the original guardian operation deadline. The
// derived kernel timeout ends before the independently observed control expiry
// even when installation consumes that whole remaining operation budget.
func desktopLinuxSOCKSTimeout(now, deadline, controlUntil time.Time) (int64, error) {
	if !now.Before(deadline) || deadline.Sub(now) > 2*time.Second || !deadline.Before(controlUntil) {
		return 0, errors.New("Linux SOCKS grant has no original bounded installation deadline")
	}
	seconds := int64(controlUntil.Sub(deadline) / time.Second)
	if seconds < 1 || seconds > 9 {
		return 0, errors.New("Linux SOCKS control lacks a usable remaining kernel lease")
	}
	return seconds, nil
}

func (n *desktopLinuxNFT) grantSOCKS(ctx context.Context, grant, control DesktopSocketGrant, controlUntil time.Time) (DesktopSocketReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return DesktopSocketReceipt{}, errors.New("Linux SOCKS grant has no current original operation")
	}
	started := time.Now()
	deadline, bounded := ctx.Deadline()
	seconds, err := desktopLinuxSOCKSTimeout(started, deadline, controlUntil)
	if !bounded || err != nil || grant.Network != "udp" || control.Network != "tcp" || grant.Capture != control.Capture || grant.Binding.Owner != control.Binding.Owner ||
		grant.Sequence == 0 || control.Sequence == 0 || grant.SocketID == control.SocketID {
		return DesktopSocketReceipt{}, errors.Join(err, errors.New("Linux SOCKS grant substituted its original association"))
	}
	set := n.Prefix + "_" + n.kind(grant)
	comment := grant.SocketID + ":" + strconv.FormatUint(grant.Sequence, 10) + ":socks:" + control.SocketID + ":" + strconv.FormatUint(control.Sequence, 10)
	script := fmt.Sprintf("destroy element inet %s %s { %s }\nadd element inet %s %s { %s timeout %ds comment %s }\n", n.table(), set, n.key(grant), n.table(), set, n.key(grant), seconds, strconv.Quote(comment))
	if _, err := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, script); err != nil {
		return DesktopSocketReceipt{}, err
	}
	readStarted := time.Now()
	rows, err := desktopLinuxNFTReadTable(ctx, n.table())
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	controlExpires, err := n.socksControlExpiry(rows, control, readStarted)
	if err != nil {
		return DesktopSocketReceipt{}, err
	}
	element, found, err := n.findElement(rows, grant)
	if err != nil || !found || element["comment"] != comment {
		return DesktopSocketReceipt{}, errors.Join(err, errors.New("Linux SOCKS derived permit did not retain its original control annotation"))
	}
	remaining, err := desktopLinuxSOCKSExpiry(element, float64(seconds))
	if err != nil || readStarted.Add(remaining).After(controlExpires) || time.Since(started) >= 2*time.Second {
		return DesktopSocketReceipt{}, errors.Join(err, errors.New("Linux SOCKS derived permit outlived its selected control or readback budget"))
	}
	// The command's earlier start is conservative: the kernel cannot have
	// installed this new timeout before the original operation began.
	until := started.Add(time.Duration(seconds) * time.Second)
	if !time.Now().Before(until) {
		return DesktopSocketReceipt{}, errors.New("Linux SOCKS derived permit expired before acknowledgment")
	}
	return DesktopSocketReceipt{Grant: grant, ObservedAt: time.Now().UnixMilli(), ExpiresAt: until.UnixMilli()}, nil
}
