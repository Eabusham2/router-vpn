package routervpnpq

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// This test-only observer uses the actual deliberately uncaptured connection.
// Its probe is the retained reference process's private request/reply channel;
// the caller serializes that channel and verifies native policy before/after.
// Successful UDP writes alone say nothing about delivery. An absent receipt
// is meaningful only between fresh independent positive exchanges at the same
// listener, with the exact attempted nonce still absent after the second one.
func nodeMAXWFPObserveOrdinaryUDP(ctx context.Context, connection net.Conn, local netip.Addr, remote netip.AddrPort, probe func(context.Context, string, string) (int64, error)) (result error) {
	if ctx == nil || ctx.Err() != nil || connection == nil || probe == nil || !local.IsValid() || !remote.IsValid() || remote.Port() == 0 {
		return errors.New("ordinary UDP observation lost its captured input")
	}
	localAddress, remoteAddress := connection.LocalAddr(), connection.RemoteAddr()
	if localAddress == nil || remoteAddress == nil || localAddress.Network() != "udp" || remoteAddress.Network() != "udp" {
		return errors.New("ordinary UDP observation replaced its actual socket transport")
	}
	actualLocal, localErr := netip.ParseAddrPort(localAddress.String())
	actualRemote, remoteErr := netip.ParseAddrPort(remoteAddress.String())
	if localErr != nil || remoteErr != nil || actualLocal.Addr().Unmap() != local.Unmap() || actualLocal.Port() == 0 || actualRemote != remote {
		return errors.New("ordinary UDP observation replaced its actual socket tuple")
	}
	nonce := func() (string, error) {
		var value [16]byte
		if _, err := rand.Read(value[:]); err != nil {
			return "", err
		}
		return hex.EncodeToString(value[:]), nil
	}
	positive := func() error {
		value, err := nonce()
		if err != nil {
			return err
		}
		count, err := probe(ctx, "positive", value)
		if err != nil || count != 1 {
			return errors.Join(err, errors.New("ordinary UDP observation lost its independent positive receipt"))
		}
		return nil
	}
	if err := positive(); err != nil {
		return err
	}
	value, err := nonce()
	if err != nil {
		return err
	}
	if count, err := probe(ctx, "arm", value); err != nil || count != 0 {
		return errors.Join(err, errors.New("ordinary UDP observation reused its attempted nonce"))
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	if parent, bounded := ctx.Deadline(); bounded && parent.Before(deadline) {
		deadline = parent
	}
	// Clear even a partially installed deadline, and reject a failed reset.
	// The original connection is returned to Hysteria by the caller unchanged.
	defer func() {
		result = errors.Join(result, connection.SetDeadline(time.Time{}))
	}()
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.Join(err, errors.New("ordinary UDP observation could not bound its original socket"))
	}
	marker := []byte("routervpn-complete-max-owned-marker/" + value)
	n, writeErr := connection.Write(marker)
	if writeErr == nil && n != len(marker) {
		return io.ErrShortWrite
	}
	if writeErr != nil && (!errors.Is(writeErr, syscall.Errno(10013)) || n != 0) {
		return errors.Join(writeErr, errors.New("ordinary UDP observation has no native write denial"))
	}
	if writeErr == nil {
		answer := make([]byte, len(marker)+1)
		n, readErr := connection.Read(answer)
		var timeout net.Error
		if n != 0 || !errors.Is(readErr, syscall.Errno(10013)) && !(errors.As(readErr, &timeout) && timeout.Timeout()) {
			return errors.Join(readErr, errors.New("ordinary UDP observation received traffic or lacked a bounded denial"))
		}
	}
	if count, err := probe(ctx, "observe", value); err != nil || count != 0 {
		return errors.Join(err, errors.New("ordinary UDP reached its independent reference"))
	}
	if err := positive(); err != nil {
		return err
	}
	if count, err := probe(ctx, "observe", value); err != nil || count != 0 {
		return errors.Join(err, errors.New("ordinary UDP reached its reference after the repeated positive"))
	}
	return ctx.Err()
}
